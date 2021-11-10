from json.decoder import JSONDecodeError
import os
import sys
import json
import time
import argparse
import logging
import pandas as pd
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, BulkWriteError
from datetime import datetime
from getpass import getpass
from splunklib.binding import AuthenticationError
import splunklib.results as results
import splunklib.client as client
import tqdm

from utils.database import SetupDatabase, ALERTS_NAME
from utils.queries import VALID_ALERTS
from utils.pipelines import VALID_ALERTS_REGEX
from unittests.validate import log_validation_stats

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ splunk alert fetch")


search = 'search `ALERTS` "blacklisted hostname" OR "threatlist hostname" OR "known C2 hostname/domain" OR "known Malware hostname/domain" OR "Typosquat domain" OR  "malicious executable download (Domain reputation)" OR  "outbound requests (vendor malicious category, sparse single host)" customer=* | \
    dedup sha |\
    regex name="(?<alert_name>{}) |\
    |  fields + sha, dst_ip, dest_host_uniq, dst, timestamp, name, customer, filter, filter_id, filter_description \    "\
    '.format(VALID_ALERTS_REGEX)


def progress_bar(progress):
    return "[{}✨{}]".format("." * (round(progress * 20)), " " * (round((1-progress) * 20)))


def get_status(job):
    msg = "{progressbar} mb: {diskUsage}, eventCount: {eventCount}, scanCount: {scanCount}".format(
        progressbar=progress_bar(float(job["doneProgress"])),
        diskUsage=int(job["diskUsage"]) / (10**6), 
        eventCount=int(job["eventCount"]),
        scanCount=int(job["scanCount"]))
    return msg

def wait_to_finish(job):
    while not job.is_done(): 
        msg = get_status(job)
        msg = "{} INFO    :l++ splunk alert fetch:   {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
        sys.stdout.write(msg)
        sys.stdout.flush()
        sys.stdout.write("\b" * (len(msg)+1)) # return to start of line
        time.sleep(2)
    print()

def main(args):    
        
    if args.password:
        password = args.password
    else:
        password = getpass()
    try:
        splunk_service = client.connect(
            host='global-sh01.gss01.nttsecurity.net', 
            port=8089,
            username=args.user, 
            password=password)
    except AuthenticationError:
        logger.error("Authentication error. exiting..")
        return
    
    months = pd.date_range(args.startdate, args.enddate, freq='M')
    prev_month = months[0]
    for month in months[1:]:
        kwargs = {
            "earliest_time": prev_month.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3], 
            "latest_time": month.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3],
            "exec_mode": "normal"
        }
        logger.info("Starting Splunk export for range: {} - {}".format(kwargs["earliest_time"], kwargs["latest_time"]))
        job = splunk_service.jobs.create(search, **kwargs)
        while not job.is_ready():
            pass
        job.set_ttl(60 * 60 * 24 * 7)
        wait_to_finish(job)
        setup = SetupDatabase()
        logger.info("Query {} done! Saving Splunk export to collection `{}` @ {}".format(job.name, args.collection, setup.redacted_uri))
        prev_month = month

        def try_insert(tmp, doc, key):
            try:
                tmp[key] = doc[key]
            except KeyError:
                return tmp
            return tmp

        for result in tqdm.tqdm(results.ResultsReader(job.results(count=0)), total=int(job["eventCount"])):
            tmp = {}
            if isinstance(result, dict):
                try:
                    doc = json.loads(result["_raw"])
                except JSONDecodeError as e:
                    logger.warn("Couldnt decode json blob: {}. Skipping.".format(result["_raw"]))
            else:    
                logger.warning("Message: {msg}".format(msg=result))
                continue
            try:
                doc["date"] = datetime.fromtimestamp(float(doc["timestamp"]))
            except KeyError:
                doc["error"] = {"type": "splunk", "message": "timestamp not found"}
                logger.warn("timestamp not found in alert with sha {}".format(doc["sha"]))

            for key in ["date", "sha", "dst_ip", "dest_host_uniq", "dst", "timestamp", "name", "customer", "filter", "filter_id", "filter_description"]:
                tmp = try_insert(tmp, doc, key)
            try:                    
                setup.db[args.collection].insert_one(tmp)
            except DuplicateKeyError:
                logger.debug("Already inserted `{}`".format(result["sha"]))
            except Exception as e:
                logger.error("unknown error during handling of `{}`".format(doc["sha"]))
                raise e
        job.cancel()
    
    logger.info("Job Complete.")    
    setup = SetupDatabase()
    logger.info("Adding hosts_array field to {}".format(args.collection))
    setup.create_hosts_array()
    log_validation_stats(args.collection, VALID_ALERTS, setup)
    logger.info("Done. Exiting")
