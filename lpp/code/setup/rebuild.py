import requests, os, logging, sys
from utils.database import SetupDatabase, DOMAINS_REAL_TIME_NAME

from workers.domain_predicter import DomainPredicter
from tqdm import tqdm
from time import sleep
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++")

api_url = os.getenv("API_URL")

def rebuild(collection=DOMAINS_REAL_TIME_NAME):
    setup = SetupDatabase()
    predicter = DomainPredicter()
    query = {"x_domain": {"$exists": True}, "shap_values": {"$exists": False}}
    docs = setup.db[DOMAINS_REAL_TIME_NAME].find(query)
    nr_docs = setup.db[DOMAINS_REAL_TIME_NAME].count_documents(query)
    for doc in tqdm(docs, total=nr_docs):
        data = doc["x_domain"]
        name = doc["name"]
        result = predicter.get_prediction(data)
        setup.db[DOMAINS_REAL_TIME_NAME].update_one({"name": name}, {"$set": {
            "shap_values": result["shap_values"], 
            'x_domain': result["x_domain"],
            'log_odds': result["log_odds"],
            'verdict': result["verdict"]
            }
        }
        )
    return