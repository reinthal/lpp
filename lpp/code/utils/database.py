import os, tldextract, sys, json, logging, io

from datetime import datetime
from tqdm import tqdm
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

from utils.queries import HAS_NO_ALERT_ENRICHMENT, has_domain_enrichment, date_fields_exists_and_is_date

TICKETS_NAME = os.getenv("MONGO_TICKETS_NAME")
ALERTS_NAME = os.getenv("MONGO_ALERTS_NAME")
DOMAINS_NAME = os.getenv("MONGO_DOMAINS_NAME")
INCIDENTS_NAME = os.getenv("MONGO_INCIDENTS_NAME")
DOMAINS_REAL_TIME_NAME = os.getenv("MONGO_DOMAINS_REAL_TIME_NAME")

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ database")

def flatten_array_data(input_data, column):
    data = input_data["vt"][column]["data"]
    if data:
        i = 0
        for val in data:
            new_key = "data{}{}".format(".", i)
            input_data["vt"][column][new_key] = val
            i += 1
    del input_data["vt"][column]["data"]

class TqdmToLogger(io.StringIO):
    """
        Output stream for TQDM which will output to logger module instead of
        the StdOut.
    """
    logger = None
    level = None
    buf = ''
    def __init__(self,logger,level=None):
        super(TqdmToLogger, self).__init__()
        self.logger = logger
        self.level = level or logging.INFO
    def write(self,buf):
        self.buf = buf.strip('\r\n\t ')
    def flush(self):
        self.logger.log(self.level, self.buf)

class SetupDatabase(object):

    def __init__(self):
        usr = os.getenv("MONGO_INITDB_ROOT_USERNAME")
        pw = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
        host = os.getenv("MONGO_HOST")
        port = int(os.getenv("MONGO_PORT"))
        db = os.getenv("MONGO_DBNAME")
        uri = f"mongodb://{usr}:{pw}@{host}:{port}/default_db?authsource=admin"
        
        
        self.client = MongoClient(uri)
        redacted_uri = f"mongodb://{usr}:*@{host}:{port}/default_db?authsource=admin"
        logger.info(f"Testing connection to {redacted_uri}")
        self.redacted_uri = redacted_uri
        try:
            self.client.server_info()
            logger.info(f"Connection successful towards {redacted_uri}")
        except ServerSelectionTimeoutError as e:
            logger.error(f"Connection failure when connecting to {redacted_uri}.")
            raise e
        db = os.getenv("MONGO_DBNAME")
        self.db = self.client[db]
    
    def __del__(self):
        logger.debug("closing mongodb connection")
        try:
            self.client.close()
        except TypeError:
            pass
    
    def create_hosts_array(self, collection=ALERTS_NAME):
        for doc in tqdm(self.db[collection].find(HAS_NO_ALERT_ENRICHMENT)):
            try:
                hosts_string = doc["dest_host_uniq"]
                if hosts_string != "N/A":
                    hosts = list(filter(lambda a: a != '', doc["dest_host_uniq"].split(',')))
                    self.db[collection].update_one({"sha": doc["sha"]}, {"$set": {"hosts_array": hosts}})
                else:
                    hosts = [doc["dst"]]
                    self.db[collection].update_one({"sha": doc["sha"]}, {"$set": {"hosts_array": hosts}})
            except KeyError:
                hosts = [doc["dst"]]
                self.db[collection].update_one({"sha": doc["sha"]}, {"$set": {"hosts_array": hosts}})

    def add_domain_and_tld(self, collection):
        """ parses domains and extracts subdomain domain and tld """
        query = has_domain_enrichment(switch=False)
        for doc in tqdm(self.db[collection].find(query)):
            extractor = tldextract.extract(doc["name"])
            data = {
                "domain": "{dom}.{tld}".format(dom=extractor.domain, tld=extractor.suffix),
                "subdomain": extractor.subdomain,
                "tld": extractor.suffix

            }
            self.db[collection].update_one({"name": doc["name"]}, {"$set": data})

    def add_date_obj_sys_created_on_incidents(self, collection="incidents"):
        query = self.db[collection].find({"sys_created_on": {"$type": "string"}})
        nr = query.count()
        logger.info("Updating `{}` sys_created_on. Docs to Update {}".format(collection, nr))
        for doc in tqdm(query, total=nr):
            created_on_date = datetime.strptime(doc["sys_created_on"], "%Y-%m-%d %H:%M:%S")
            self.db[collection].update_one({"_id": doc["_id"]}, {"$set": {"sys_created_on": created_on_date}})
        logger.info("Updating `{}` sys_created_on done!".format(collection))


    def add_object_u_json_on_incidents(self, collection="incidents"):
        query = self.db[collection].find({ "u_json": { "$type": "string" } })
        nr = query.count()
        logger.info("Updating `{}` u_json values. Docs to update: {}".format(collection, nr))
        for doc in tqdm(query, total=nr):
            alert_data = json.loads(doc["u_json"])
            self.db[collection].update_one({"_id": doc["_id"]}, {"$set": {"u_json": alert_data}})
        query = self.db[collection].find({ "u_json": { "$type": "string" } })
        nr = query.count()
        logger.info("Updating `{}` u_json done!".format(collection))

    def update_timestamps_alerts(self, collection="alerts"):
        query = date_fields_exists_and_is_date(switch=False)
        cursor = self.db[collection].find(query)
        nr_updates = cursor.count()
        for doc in tqdm(cursor, total=nr_updates):
            date = datetime.fromtimestamp(float(doc["timestamp"]))
            self.db[collection].update_one({"sha": doc["sha"]}, {"$set": {"date": date}})    

    
