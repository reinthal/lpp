"""Sets up indexes and aggregations for the database. Run after new data imports using the apis."""
import sys

from setup.queries import VALID_ALERTS, VALID_TICKETS, TICKETS_ARRAY_DOESNT_EXIST, HAS_TICKET
from setup.pipelines import pipeline_alerts, pipeline_tickets, pipeline_join_tickets_aggregation_on_domains
from setup.database import  SetupDatabase, ALERTS_NAME, TICKETS_NAME, DOMAINS_NAME

import logging
import sys

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ creating and/or updating")

def main():
    setup = SetupDatabase()
    domains_output_collection = DOMAINS_NAME
    
    # Adding alerts to domains and creating new domains
    logger.info("Adding alerts to {} collection".format(domains_output_collection))
    nr_domains_before_alert_export = setup.db[domains_output_collection].find().count()
    setup.db[ALERTS_NAME].aggregate(pipeline_alerts(matching_stage=VALID_ALERTS, output_collection=domains_output_collection), allowDiskUse=True)
    nr_domains_after_alert_export = setup.db[domains_output_collection].find().count()
    logger.info("New nr. domains are : {}".format(nr_domains_after_alert_export - nr_domains_before_alert_export))
    
    # Adding tickets to domains
    logger.info("Adding tickets to collection {}".format(domains_output_collection))
    nr_tickets_before = setup.db[domains_output_collection].find(HAS_TICKET).count()
    group_on_domains = pipeline_tickets(matching_stage=VALID_TICKETS)
    setup.db[TICKETS_NAME].aggregate(group_on_domains, allowDiskUse=True)
    
    join_on_domains_name = pipeline_join_tickets_aggregation_on_domains(output_collection=domains_output_collection)
    setup.db[domains_output_collection].aggregate(join_on_domains_name, allowDiskUse=True)
        
    nr_tickets_after = setup.db[domains_output_collection].find(HAS_TICKET).count()
    logger.info("Added {} new tickets.".format(nr_tickets_after - nr_tickets_before))
    logger.info("Adding empty array for domains with no incidents")
    setup.db[domains_output_collection].update_many(TICKETS_ARRAY_DOESNT_EXIST, {"$set": {"tickets": []}})
    after_tickets = setup.db[domains_output_collection].find().count()
    assert after_tickets - nr_domains_after_alert_export == 0, "Something went wrong when joining tickets on domains using pipeline_tickets"
    
    # Extracting tld and domain for analysis    
    logger.info("Adding tld and domain to domains")
    setup.add_domain_and_tld(domains_output_collection)
    setup.client.close()
    logger.info("Done.")

if __name__ == "__main__":
    main()
