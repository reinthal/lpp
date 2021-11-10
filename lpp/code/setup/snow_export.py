import logging, sys

from utils.queries import VALID_TICKETS
from utils.pipelines import incidents_to_tickets_pipeline, project_relevant_data_incidents
from utils.apis import SnowApi, UninitializedAPIException
from utils.database import SetupDatabase, INCIDENTS_NAME, TICKETS_NAME
from unittests.validate import log_validation_stats

from datetime import datetime, timedelta
from pymongo.errors import BulkWriteError, ServerSelectionTimeoutError

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ snow incidents fetch")

def main(update=True):
    logger.info("Starting snow export.")
    try:
        setup = SetupDatabase()
    except ServerSelectionTimeoutError:
        logger.error(f"Could not connect database. Exiting.")
        return
    if update:
        
        # get the date of the latest incident
        try:
            doc = setup.db[INCIDENTS_NAME].find({}).sort([("sys_created_on", -1)]).limit(1).next()
            latest_incident_date = datetime.strftime(doc["sys_created_on"],"%Y-%m-%d %H:%M:%S")
        except (StopIteration, TypeError):
            days = 180
            logger.info(f"Not incidents present in db. Updating incidents over past {days} days")
            latest_incident_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        try:
            snow_api = SnowApi(date=latest_incident_date)
        except UninitializedAPIException:
            logger.error("API was not properly initialized. Check SNOW_* environment variables")
            return
        logger.info("Updating incidents from {} and onwards".format(latest_incident_date))
    else:
        try:
            snow_api = SnowApi()
        except UninitializedAPIException:
            logger.error("API was not properly initialized. Check SNOW_* environment variables")
            return
        setup.db[INCIDENTS_NAME].create_index("number", unique=True)

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

    logger.info("Updating new data")
    setup.add_object_u_json_on_incidents()
    setup.add_date_obj_sys_created_on_incidents()
    logger.info("Dropping irrelevant incident data.")
    setup.db[INCIDENTS_NAME].aggregate(project_relevant_data_incidents(INCIDENTS_NAME))
    logger.info("Merging New Incidents to tickets")
    before = setup.db[TICKETS_NAME].find({}).count()
    setup.db[INCIDENTS_NAME].aggregate(incidents_to_tickets_pipeline(TICKETS_NAME), allowDiskUse=True)
    after = setup.db[TICKETS_NAME].find({}).count()
    logger.info("Merged new incidents to tickets. {} new tickets!".format(after-before))
    log_validation_stats(TICKETS_NAME, VALID_TICKETS, setup)
    logger.info("Done")


if __name__ == "__main__":
    main()