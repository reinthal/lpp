import sys, logging, pymongo

from datetime import datetime
from utils.database import SetupDatabase, TICKETS_NAME, ALERTS_NAME, DOMAINS_NAME, INCIDENTS_NAME
from utils.queries import VALID_TICKETS, VALID_ALERTS, has_domain_errors

datetime_format = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt=datetime_format)
logger = logging.getLogger("l++ validate")

def strfdelta(tdelta, fmt):
    d = {"days": tdelta.days}
    d["hours"], rem = divmod(tdelta.seconds, 3600)
    d["minutes"], d["seconds"] = divmod(rem, 60)
    return fmt.format(**d)

def valid_percentage(valid_docs, all_docs):
    return round(100 * valid_docs.count()/all_docs.count(), 2),valid_docs.count()

def log_validation(msg, percentage):
    logger = logging.getLogger("l++ validate")
    if percentage > 95:
        logger.info(msg)
    elif percentage > 50:
        logger.warn(msg)
    else:
        logger.critical(msg)

def log_validation_stats(collection, validation_query, setup):
    valid_docs = setup.db[collection].find(validation_query)
    all_docs = setup.db[collection].find()
    valid_perc, valid_count = valid_percentage(valid_docs, all_docs)
    msg = "Valid {collection} docs: {count} ({perc}%)".format(
                                collection=collection, 
                                count=valid_count, 
                                perc=valid_perc
        )
    log_validation(msg, valid_perc)

def main():
    setup = SetupDatabase()
    
    # Validation stats
    log_validation_stats(DOMAINS_NAME, has_domain_errors(), setup)
    log_validation_stats(ALERTS_NAME, VALID_ALERTS, setup)
    log_validation_stats(TICKETS_NAME, VALID_TICKETS, setup)

    # Time since last update
    query_alerts = setup.db[ALERTS_NAME].find({}).sort("date", pymongo.DESCENDING)
    query_tickets = setup.db[TICKETS_NAME].find({}).sort("date", pymongo.DESCENDING)
    last_alert = query_alerts.next()
    last_ticket = query_tickets.next()
    today = datetime.now()
    logger.info("Last update on {alerts}: {delta} ({date})".format(
        alerts=ALERTS_NAME,
        date=datetime.strftime(last_alert["date"], datetime_format),
        delta=strfdelta(today - last_alert["date"], "{days} days, {hours} hours")
    ))
    logger.info("Last update on {tickets}: {delta} ({date})".format(
        tickets=TICKETS_NAME,
        date=datetime.strftime(last_ticket["date"], datetime_format),
        delta=strfdelta(today - last_ticket["date"], "{days} days, {hours} hours")
    ))
    

if __name__ == "__main__":
    main()