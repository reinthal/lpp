import os
from celery import Celery
from setup.snow_export import main as snow_export_main

BROKER_URI = os.environ['BROKER_URI']
BACKEND_URI = os.environ['BACKEND_URI']
SNOW_FETCH_UPDATE_PERIOD = os.environ["SNOW_FETCH_UDPATE_PERIOD"]

app = Celery(broker=BROKER_URI, backend=BACKEND_URI)

app.conf.beat_schedule = {
    "fetch-snow-incident-data": {
        "task": "workers.tasks.fetch_snow_data",
        "schedule": float(SNOW_FETCH_UPDATE_PERIOD)
    }
}