"""Sets up indexes and aggregations for the database. Run after new data imports using the apis."""
import sys

from utils.queries import VALID_ALERTS, VALID_TICKETS, TICKETS_ARRAY_DOESNT_EXIST, HAS_TICKET
from utils.pipelines import pipeline_alerts, pipeline_tickets, pipeline_join_tickets_aggregation_on_domains
from utils.database import  SetupDatabase, ALERTS_NAME, TICKETS_NAME, DOMAINS_NAME

import logging
import sys

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ creating and/or updating")

class UpdateDomains(object):

    def __init__(self, domains_collection=DOMAINS_NAME, alerts_collection=ALERTS_NAME) -> None:
        self.setup = SetupDatabase()
        self.alerts_collection = alerts_collection
        self.collection = domains_collection
        super().__init__()

    def update_alerts(self):
        """Adding alerts to domains and creating new domains (parametrized)"""
        logger.info("Adding alerts to {} collection".format(self.collection))
        nr_domains_before_alert_export = self.setup.db[self.collection].find().count()
        self.setup.db[self.alerts_collection].aggregate(pipeline_alerts(matching_stage=VALID_ALERTS, output_collection=self.collection), allowDiskUse=True)
        nr_domains_after_alert_export = self.setup.db[self.collection].find().count()
        logger.info("New nr. domains are : {}".format(nr_domains_after_alert_export - nr_domains_before_alert_export))
    
    def update_tickets(self):
        """Add tickets to domains"""
        logger.info("Adding tickets to collection {}".format(self.collection))
        nr_tickets_before = self.setup.db[self.collection].find(HAS_TICKET).count()
        group_on_domains = pipeline_tickets(matching_stage=VALID_TICKETS)
        self.setup.db[TICKETS_NAME].aggregate(group_on_domains, allowDiskUse=True)

        join_on_domains_name = pipeline_join_tickets_aggregation_on_domains(output_collection=self.collection)
        self.setup.db[self.collection].aggregate(join_on_domains_name, allowDiskUse=True)
        
        nr_tickets_after = self.setup.db[self.collection].find(HAS_TICKET).count()
        
        logger.info("Added {} new tickets.".format(nr_tickets_after - nr_tickets_before))
        logger.info("Adding empty array for domains with no incidents")
        
        self.setup.db[self.collection].update_many(TICKETS_ARRAY_DOESNT_EXIST, {"$set": {"tickets": []}})
    
    def add_tld(self):
        """Extracting tld and domain for analysis """
        logger.info("Adding tld and domain to domains")
        self.setup.add_domain_and_tld(self.collection)


def main(domains_collection=DOMAINS_NAME, alerts_collection=ALERTS_NAME):
    update = UpdateDomains(domains_collection=domains_collection, alerts_collection=alerts_collection)
    update.update_alerts()
    update.update_tickets()
    update.add_tld()
    logger.info("Done.")
    
if __name__ == "__main__":
    main()
