import importlib
import logging
from os import terminal_size
from celery import Task
import pandas as pd
from utils.database import SetupDatabase, DOMAINS_REAL_TIME_NAME
from workers.domain_predicter import DomainPredicter
from workers.worker import app
from setup.create_dataframe import CreateDataframe
from setup.snow_export import main as snow_export_main
from setup.update_domains import UpdateDomains

def create_tickets_data(df):
    """
    Creates ticket data for frontend presentation on domains_real_time.

    duplicate code from create_dataframe. 
    """
    tickets = df["tickets"]
    labels = {
        "ticket_label": [],
        "ticket_first_id": [],
        "ticket_first_date": [],
        "ticket_first_severity": []
    }

    for row in tickets:
        if not row:
            labels["ticket_label"].append(0)
            labels["ticket_first_id"].append(None)
            labels["ticket_first_date"].append(None)
            labels["ticket_first_severity"].append(None)
        else:
            ticket = min(row[0]["tickets"], key=lambda x: x["date"])
            labels["ticket_label"].append(1)
            labels["ticket_first_id"].append(ticket["id"])
            labels["ticket_first_date"].append(ticket["date"])
            labels["ticket_first_severity"].append(ticket["severity"])
    for key in labels.keys():
        assert len(df) == len(labels[key]), "Something went wrong when creating ticket data."
    for key in labels.keys():
        df.insert(2, key, labels[key])

class PredictTask(Task):
    """
    Abstraction of Celery's Task class to support loading ML model.

    """
    abstract = True

    def __init__(self):
        super().__init__()
        self.model = None

    def __call__(self, *args, **kwargs):
        """
        Load model on first call (i.e. first task processed)
        Avoids the need to load model on each task request
        """
        if not self.model:
            logging.info('Loading Model...')
            module_import = importlib.import_module(self.path[0])
            model_obj = getattr(module_import, self.path[1])
            self.model = model_obj()
            logging.info('Model loaded')
        return self.run(*args, **kwargs)

@app.task(ignore_result=False,
          bind=True,
          base=PredictTask,
          path=('workers.domain_predicter', 'DomainPredicter'),
          name='{}.{}'.format(__name__, 'Domain'))
def predict(self, data):
    """
    creates a prediction for data and crunches it if this is not a cached result
    """
    return self.model.get_prediction(data)

@app.task
def fetch_snow_data():
    snow_export_main(update=True)
    update = UpdateDomains(domains_collection=DOMAINS_REAL_TIME_NAME)
    logging.info(f"joining tickets on {DOMAINS_REAL_TIME_NAME}")
    update.update_tickets()

@app.task
def assemble_data():
    setup = SetupDatabase()
    cursor = setup.db[DOMAINS_REAL_TIME_NAME].find({"log_odds": {"$exists": True}}, 
        {"log_odds": 1, "name": 1, "verdict": 1, "tickets.tickets":1, "last_analysis":1, "alerts": 1, "_id": 0}
        )
    creator = CreateDataframe(cursor, DOMAINS_REAL_TIME_NAME)
    creator.create_prediction_summary_dataframe()
    return creator.df.to_dict()    