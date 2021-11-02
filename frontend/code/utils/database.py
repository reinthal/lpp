import os, sys, logging
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

TICKETS_NAME = os.getenv("MONGO_TICKETS_NAME")
ALERTS_NAME = os.getenv("MONGO_ALERTS_NAME")
DOMAINS_NAME = os.getenv("MONGO_DOMAINS_NAME")
INCIDENTS_NAME = os.getenv("MONGO_INCIDENTS_NAME")
DOMAINS_REAL_TIME_NAME = os.getenv("MONGO_DOMAINS_REAL_TIME_NAME")

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ frontend db con")

class ConnectDatabase(object):

    def __init__(self):
        usr = os.getenv("MONGO_INITDB_ROOT_USERNAME")
        pw = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
        host = os.getenv("MONGO_HOST")
        port = int(os.getenv("MONGO_PORT"))
        db = os.getenv("MONGO_DBNAME")
        uri = f"mongodb://{usr}:{pw}@{host}:{port}/default_db?authsource=admin"
        
        self.client = MongoClient(uri)
        logger.info(f"Testing connection to {usr}@{host}:{port}")
        try:
            self.client.server_info()
            logger.info(f"Connection successful towards {usr}@{host}:{port}")
        except ServerSelectionTimeoutError as e:
            logger.error(f"Connection failure when connecting to {usr}@{host}:{port}.")
            raise e
        db = os.getenv("MONGO_DBNAME")
        self.db = self.client[db]
    
    def __del__(self):
        logger.debug("closing mongodb connection")
        try:
            self.client.close()
        except TypeError:
            pass
    


    
