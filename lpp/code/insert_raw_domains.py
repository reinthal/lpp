import json, logging, sys, argparse

from datetime import datetime
from utils.database import SetupDatabase
from pymongo.errors import DuplicateKeyError

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ raw domains")

def parse_args():
    parser = argparse.ArgumentParser(description='Ingest Adrenaline data')
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-c", "--collection", required=True)
    return parser.parse_args()

def main():
    args = parse_args()
    docs = []
    logger.info("Loading adrenaline blacklist entries from `{}`".format(args.file))
    setup = SetupDatabase()
    setup.db[args.collection].create_index("name", unique=True)
    with open(args.file, 'r') as fp:
        for line in fp.readlines():
            doc = json.loads(line)
            if doc["identifier_type"] == "DOMAINNAME":
                entries = doc["description"].split("<br>")
                new_entries = {}
                for item in entries:
                    new_entries[item.split(":")[0]] = item.split(":")[-1].strip()
                doc["date"] = datetime.strptime(new_entries["Event Published"], '%Y-%m-%d')
                doc["name"] = doc["identifier"]
                doc["tickets"] = []
                doc["alerts"] = [
                    {
                        "date":doc["date"],
                        "sha": "badf00d",
                        "name": "PROXY/D CUstom stuff",
                        "customer": "1337"
                 }
                ]
                try:
                    setup.db[args.collection].insert_one(doc)
                except DuplicateKeyError:
                    logger.warn("The domain {} has already been inserted".format(doc["name"]))
                    setup.db[args.collection].update_one({"name": doc["name"]}, {"$set": {"ioc_first_date": doc["date"]}})

    # Extracting tld and domain for analysis    
    logger.info("Adding tld and domain to domains")
    setup.add_domain_and_tld(args.collection)
    logger.info("Done")

if __name__ == "__main__":
    main()