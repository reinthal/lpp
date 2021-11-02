import logging
import sys
import argparse

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ update dataframe collection")

from tqdm import tqdm
from datetime import datetime

from utils.database import DOMAINS_NAME
from utils.queries import API_ENDPOINTS, has_domain_errors
from utils.database import SetupDatabase, TqdmToLogger
from utils.pipelines import pipeline_domains_dataframe

def extract_last_mod_date(attributes, endpoint):
    if endpoint in  ["subdomains", "siblings", "referrer_files", "downloaded_files", "communicating_files", "urls"]:
        return attributes["last_modification_date"]
    elif endpoint in ["resolutions"]:
        return attributes["date"]
    elif endpoint in ["historical_whois"]:
        return attributes["last_updated"]

class DomainsDataFrame(object):

    def __init__(self):
        self.setup = SetupDatabase()


    def remove_future_data(self, collection):
        """removes data from the future relative to first alert"""
        no_errors_query = has_domain_errors(switch=False)

        cursor = self.setup.db[collection].find(no_errors_query)
        tqdm_out = TqdmToLogger(logger,level=logging.INFO)
        
        for doc in tqdm(cursor, total=cursor.count(), file=tqdm_out, mininterval=30):
            logger.debug("Removing future data for {}".format(doc["name"]))
            first_alert_date = min(doc["alerts"], key=lambda x: x["date"])["date"]
            for endpoint in API_ENDPOINTS:
                try:
                    endpoint_datapoints = doc["vt"][endpoint]["data"]
                except KeyError:
                    continue
                redacted_datapoints = []
                for datapoint in endpoint_datapoints:
                    try:
                        last_mod_date = datetime.fromtimestamp(extract_last_mod_date(datapoint["attributes"], endpoint))
                        if last_mod_date < first_alert_date:
                            redacted_datapoints.append(datapoint)
                    except KeyError:
                        redacted_datapoints = endpoint_datapoints
                        break
                self.setup.db[collection].update_one({"name": doc["name"]}, {"$set": {"vt.{}.data".format(endpoint): redacted_datapoints}})
                



    def flatten_column(self, column, collection_dataframe, sep="."):
        """flatten column using array index

        Flatten column by including array index saves it back to the original collection.

        input  {"abc": [1,2,3]}
        output {"abc.1": 1, "abc.2": 2, "abc.3": 3}

        """

        cursor = self.setup.db[collection_dataframe].find()

        for doc in cursor:
            try:
                data = doc["vt"][column]["data"]
            except KeyError:    # already flattened this data
                continue
            if data:
                i = 0
                for val in data:
                    new_key = "data{}{}".format(sep, i)
                    doc["vt"][column][new_key] = val
                    i += 1
            del doc["vt"][column]["data"]
            self.setup.db[collection_dataframe].update_one({"_id": doc["_id"]}, {"$set": doc})

    def create_domains_dataframe_collection(self, collection):
        output_collection = collection + "_dataframe"
        matching_stage_no_errors = has_domain_errors(switch=False)
        pipeline = pipeline_domains_dataframe(matching_stage_no_errors, output_collection=output_collection)
        self.setup.db[collection].aggregate(
            pipeline,
            allowDiskUse=True
        )
        return output_collection


def main():
    parser = argparse.ArgumentParser(description='Create dataframe collection')
    parser.add_argument("-c", "--collection", required=False)
    args = parser.parse_args()
    dataframe_creator = DomainsDataFrame()
    logger.info("creating data collection")
    if args.collection:
        collection = args.collection
    else:
        collection = DOMAINS_NAME


    logger.info("Projecting data data from `{}`".format(collection))
    output_collection = dataframe_creator.create_domains_dataframe_collection(collection)

    logger.info("Redacting future data data from `{}`".format(output_collection))
    dataframe_creator.remove_future_data(output_collection)
    
    count = dataframe_creator.setup.db[output_collection].find().count()
    logger.info("Created {output_collection}, nr docs: {nr_docs}".format(output_collection=output_collection, nr_docs=count))
    
    for col in API_ENDPOINTS:
        logger.info("flattening `{}`".format(col))
        dataframe_creator.flatten_column(col, output_collection)
    
    logger.info("Done.")


if __name__ == "__main__":
    main()
