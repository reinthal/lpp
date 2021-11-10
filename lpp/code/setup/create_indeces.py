# Requires pymongo 3.6.0+
from utils.database import SetupDatabase, TICKETS_NAME, ALERTS_NAME, DOMAINS_NAME, INCIDENTS_NAME, DOMAINS_REAL_TIME_NAME

from pymongo.errors import ServerSelectionTimeoutError, OperationFailure
import logging
import sys

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ creating indeces")

    
def create_index(setup, collection, *args, **kwargs):
    try:
        setup.db[collection].create_index(*args, **kwargs)
    except OperationFailure as e:
        if "already exists" in str(e):
            logger.warn(f"Index already exists for collection {collection}: " + str(*args))
            pass
        else:
            raise e
            
def main():
    try:
        setup = SetupDatabase()
    except ServerSelectionTimeoutError:
        logger.error(f"Could not connect database. Exiting.")
        return
    logger.info("creating indeces.")
    create_index(setup, DOMAINS_NAME, "name", unique=True)
    create_index(setup, DOMAINS_NAME,"name", unique=True)
    create_index(setup, DOMAINS_REAL_TIME_NAME, "name", unique=True, expireAfterSeconds=15770000)
    create_index(setup, DOMAINS_REAL_TIME_NAME, "alerts.sha", unique=True,  partialFilterExpression = {"alerts.sha": {"$exists": True}})
    create_index(setup, TICKETS_NAME, "id", unique=True)
    create_index(setup, TICKETS_NAME, "date")
    create_index(setup, ALERTS_NAME, "sha", unique=True)
    create_index(setup, ALERTS_NAME, "dest")
    create_index(setup, ALERTS_NAME, "date")
    create_index(setup, ALERTS_NAME, "dst")
    create_index(setup, ALERTS_NAME, "hosts_array")
    create_index(setup, INCIDENTS_NAME, "number", unique=True)
    setup.client.close()
    logger.info("Done.")


if __name__ == "__main__":
    main()