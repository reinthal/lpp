import logging, sys, argparse

from utils.queries import VALID_TICKETS
from utils.pipelines import incidents_to_tickets_pipeline
from utils.apis import SnowApi
from utils.database import SetupDatabase, INCIDENTS_NAME, TICKETS_NAME
from unittests.validate import log_validation_stats

from datetime import datetime
from pymongo.errors import BulkWriteError

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ snow incidents fetch")

def main():
    parser = argparse.ArgumentParser(description='Export incident data from SNOW')
    parser.add_argument("-u", "--update", action='store_true')
    args = parser.parse_args()
    logger.info("Starting.")
    
    setup = SetupDatabase()
    if args.update:
        # get the date of the last incident
        doc = setup.db[INCIDENTS_NAME].find({}).sort([("sys_created_on", -1)]).limit(1).next()
        latest_incident_date = datetime.strftime(doc["sys_created_on"],"%Y-%m-%d %H:%M:%S") 
        snow_api = SnowApi(date=latest_incident_date)
        logger.info("Updating incidents from {} and onwards".format(latest_incident_date))
    else:
        snow_api = SnowApi()
        setup.db[INCIDENTS_NAME].create_index("number", unique=True)

    count_before = setup.db[INCIDENTS_NAME].count_documents({})
    offset = 0
    while True:
        data, response = snow_api.get_incident_chunk(offset)
        logger.info("{} {} offset: {}".format(response.status_code, response.reason, offset))
        if data and data["result"]:
            offset = offset + snow_api.params_get_incidents_tde["sysparm_limit"]
            try:
                setup.db[INCIDENTS_NAME].insert_many(data["result"])
            except BulkWriteError as e:
                
                logger.warn("Some of these incidents have possibly been inserted. Offset: {}".format(offset))
                errors = e.details["writeErrors"]
                
                for err in errors:
                    if err["code"] != 11000: # not duplicate keyerror
                        logger.error("Found unhandled BulkWriteError. check if this is OK. `{}`".format(err["errmsg"]))
                        
            except Exception as e:
                logger.error("Unknown Exception. Exiting")
                raise e
        else:
            logger.info("Done. {} {} current offset: {}".format(response.status_code, response.reason,  offset))
            break
            
    count_after = setup.db[INCIDENTS_NAME].count_documents({})
    delta = count_after - count_before
    logger.info("Nr. of new incidents : {}".format(delta))
    logger.info("Updating new data")
    setup.add_object_u_json_on_incidents()
    setup.add_date_obj_sys_created_on_incidents()
    logger.info("Merging New Incidents to tickets")
    before = setup.db[TICKETS_NAME].find({}).count()
    setup.db[INCIDENTS_NAME].aggregate(incidents_to_tickets_pipeline(TICKETS_NAME), allowDiskUse=True)
    after = setup.db[TICKETS_NAME].find({}).count()
    logger.info("Merged new incidents to tickets. {} new tickets!".format(after-before))
    log_validation_stats(TICKETS_NAME, VALID_TICKETS, setup)
    logger.info("Done")


if __name__ == "__main__":
    main()