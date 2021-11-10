import asyncio
import json
import logging
import sys
import os
import argparse

setup_dir = os.path.abspath(__name__ + "/../setup")
sys.path.append(setup_dir)

from tqdm import tqdm
from aiohttp import ClientSession
from aiohttp.client_exceptions import ContentTypeError
from datetime import datetime

from pymongo.errors import WriteError, InvalidDocument

from database import SetupDatabase, DOMAINS_NAME, TqdmToLogger
from apis import VtApi, IsIpException, InvalidDomainException, QuotaExceededException, OtherVtException, clean_keys
from queries import NO_ERROR_AND_NO_VT_OR_QUOTA_ERROR

def parse_args():
    parser = argparse.ArgumentParser(description='vt api script')
    parser.add_argument("-c", "--collection", required=False)
    return parser.parse_args()

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ VirusTotal api fetch")


def format_error_entry(data, api_name):
    return {
        "error": {
            "type": api_name,
            "message": data
        }
    }

async def main(vt_api, setup, collection):
        async with ClientSession(trust_env=True) as session:
            nr_domains = setup.db[collection].count_documents(NO_ERROR_AND_NO_VT_OR_QUOTA_ERROR)
            logger.info("Calling VT endpoints for {} domains".format(nr_domains))
            tqdm_out = TqdmToLogger(logger,level=logging.INFO)
            for doc in tqdm(setup.db[collection].find(NO_ERROR_AND_NO_VT_OR_QUOTA_ERROR), file=tqdm_out, mininterval=30, total=nr_domains):
                try: # fetch the data
                    data = await vt_api.fetch_vt(doc["name"], session)
                except IsIpException as e:
                    logger.debug("this is an ip {}".format(doc["name"]))
                    setup.db[collection].remove({"name": doc["name"]})
                    continue
                except InvalidDomainException as e:
                    setup.db[collection].update_one({"name": doc["name"]}, {"$set": format_error_entry("invalid domain name", "badf00d")})
                    logger.debug("invalid domain name found `{}`.".format(doc["name"]))
                except ContentTypeError:
                    logger.warn("ContentTypeError occurred while fetching data for `{}`".format(doc["name"]))
                    setup.db[collection].update_one({"name": doc["name"]}, {"$set": format_error_entry("ContentTypeError", "badf00d")})
                except OtherVtException as e:
                    setup.db[collection].update_one({"name": doc["name"]}, {"$set": format_error_entry(e.message, "vt")})
                    logger.error(f"Other VT error occurred {e.message}")
                except QuotaExceededException:
                    logger.error("Quota reached when looking up `{}`. Exiting.".format(doc["name"]))
                
                data = clean_keys(data)
                try:
                    setup.db[collection].update_one({"name": doc["name"]}, {"$set": {"vt": data}})
                except (UnicodeEncodeError, WriteError, InvalidDocument, OverflowError) as e:
                    setup.db[collection].update_one({"name": doc["name"]},
                                                    {"$set": format_error_entry(str(e), "vt")})
                    logger.error("Database Exception when inserting domain `{}`. saving stacktrace to error...".format(
                        doc["name"]))
                    logger.debug(str(e))


def main_wrapper():
    args = parse_args()
    setup = SetupDatabase()
    
    collection = args.collection
    if not collection:
        collection = DOMAINS_NAME
    
    logger.info("Making api calls to VirusTotal for domains in `{}`".format(collection))
    vt_api = VtApi()
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(main(vt_api, setup, collection))
    loop.run_until_complete(future)

if __name__ == "__main__":
    main_wrapper()
        