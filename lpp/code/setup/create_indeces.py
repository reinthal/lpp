# Requires pymongo 3.6.0+
from utils.database import SetupDatabase, TICKETS_NAME, ALERTS_NAME, DOMAINS_NAME, INCIDENTS_NAME, DOMAINS_REAL_TIME_NAME

from pymongo.errors import ServerSelectionTimeoutError
import logging
import sys

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ creating indeces")

def main():
    try:
        setup = SetupDatabase()
    except ServerSelectionTimeoutError:
        logger.error(f"Could not connect database. Exiting.")
        return
    logger.info("creating indeces.")
    setup.db[DOMAINS_NAME].create_index("name", unique=True)
    setup.db[DOMAINS_REAL_TIME_NAME].create_index("name", unique=True)
    setup.db[DOMAINS_REAL_TIME_NAME].create_index("alerts.sha", unique=True,  partialFilterExpression = {"alerts.sha": {"$exists": True}})
    setup.db[TICKETS_NAME].create_index("id", unique=True)
    setup.db[TICKETS_NAME].create_index("date")
    setup.db[ALERTS_NAME].create_index("sha", unique=True)
    setup.db[ALERTS_NAME].create_index("dest")
    setup.db[ALERTS_NAME].create_index("date")
    setup.db[ALERTS_NAME].create_index("dst")
    setup.db[ALERTS_NAME].create_index("hosts_array")
    setup.db[INCIDENTS_NAME].create_index("number", unique=True)
    setup.client.close()
    logger.info("Done.")


if __name__ == "__main__":
    main()