# project/app/main.py
import pickle, json

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from bson.binary import Binary
from datetime import datetime, timedelta

from pymongo.collection import ReturnDocument
from pymongo.errors import DuplicateKeyError

from datetime import datetime, timedelta
from fastapi import HTTPException
from celery.result import AsyncResult

from aiohttp import ClientSession


from utils.database import SetupDatabase, DOMAINS_REAL_TIME_NAME
from utils.pipelines import pipeline_domains_dataframe
from utils.static_functions import format_data, create_mock_alert
from utils.apis import VtApi, clean_keys, DomainNotFoundException, InvalidDomainException, \
                        IsIpException, OtherVtException, QuotaExceededException

from utils.static_functions import format_data, create_mock_alert
from api.queries import tickets_aggregation_projection
from api.config import Alert, Acknowledgement, Task, Prediction

from predict.tasks import predict

pipeline = pipeline_domains_dataframe({}, DOMAINS_REAL_TIME_NAME)
relevant_data = pipeline[1]["$project"]
setup = SetupDatabase

vt_api = VtApi()
setup = SetupDatabase()
api = FastAPI()

async def fetch_domain_data(domain):
    """ fetches vt api data for domain.
    
        Throws HTTPException
    """
    try:
        async with ClientSession(trust_env=True) as session:
            data = await vt_api.fetch_vt(domain, session)
            return data
    except (OtherVtException, QuotaExceededException, DomainNotFoundException, IsIpException, InvalidDomainException) as e:
        raise HTTPException(status_code=404, detail=e.message)


async def get_prediction_data(domain: str):
    domain_has_been_analyzed_past_day = {
        "name": domain,
        "x_domain": {"$exists": True},
        "last_analysis" : {"$gt": datetime.now() - timedelta(hours=24)}
    }
    fresh_analysis = setup.db[DOMAINS_REAL_TIME_NAME].find_one(domain_has_been_analyzed_past_day, projection={"x_domain": 1})

    try:
        if fresh_analysis: # If yes load old prediction
            return fresh_analysis["x_domain"]
        else: 
            # fetch the data
            data = await fetch_domain_data(domain)
            
            # make some formating
            data = format_data(data, domain)
            
            # clean keys from bad chars
            data = clean_keys(data)
            
            # insert and project
            doc = setup.db[DOMAINS_REAL_TIME_NAME].find_one_and_update(
                {"name": domain}, 
                {"$set": data},
                projection=relevant_data,
                return_document=ReturnDocument.AFTER,
                upsert=True
            )
            
            # if alerts not present document then make a mock alert
            # happens when a user requests an analysis of an arbitrary domain that never triggered alert
            if "alerts" not in doc.keys():
                doc["alerts"] = create_mock_alert()

            return doc
    except UnicodeEncodeError as e:
        raise HTTPException(status_code=422, detail=str(e))


@api.get("/predict/result/{task_id}", response_model=Prediction, status_code=200,
         responses={202: {'model': Task, 'description': 'Accepted: Not Ready'}})
async def predict_result(task_id: str):
    task = AsyncResult(task_id)
    
    if not task.ready():
        return JSONResponse(status_code=202, content={'task_id': str(task_id), 'status': 'Processing'})
    else:
        
        result = task.get()
        
        # cache prediction in mongodb
        setup.db[DOMAINS_REAL_TIME_NAME].update_one({"name": result["name"]}, {"$set": {"last_analysis": datetime.now(), 'x_domain': result["x_domain"]}})
        
        result["task_id"] = task_id
        result["status"] = "Success"
        return result

@api.get("/predict/{name}",  response_model=Task, status_code=202)
async def get_prediction(name: str):
    data = await get_prediction_data(name) # io bound
    task_id = predict.delay(data) #cpu bound
    return {'task_id': str(task_id), 'status': 'Processing'}


@api.post("/predict/",  response_model=Task, status_code=202)
async def post_prediction(alert: Alert):
    domain = alert.dst
    if alert.timestamp:
        try:
            alert.date = datetime.fromtimestamp(float(alert.timestamp))
        except TypeError:
            raise HTTPException(422, f"could not convert {alert.timestamp} to a date.")
    
    # Push new alert to domains collection
    tmp = alert.dict(by_alias=True)
    tmp["dst_ip"] = str(tmp["dst_ip"])
    try:
        setup.db[DOMAINS_REAL_TIME_NAME].find_one_and_update(
            {"name": domain}, 
            {"$push": {"alerts": tmp}},
            projection={"alerts": 1},
            return_document=ReturnDocument.BEFORE,
            upsert=True
        )
    except DuplicateKeyError:
        raise HTTPException(422, "{} has already been analyzed".format(tmp["sha"]))
    data = await get_prediction_data(domain) # io bound
    task_id = predict.delay(data) #cpu bound
    return {'task_id': str(task_id), 'status': 'Processing'}


@api.get("/tickets/")
async def get_tickets():
    tickets = setup.db["incidents"].aggregate([{"$project": tickets_aggregation_projection}])
    return list(tickets)

@api.get("/socs/")
async def get_socs():
    socs = setup.db["socs"].find({}, {"soc":1, "customers":1, "_id":0})
    return list(socs)


@api.put("/domains/")
async def ack_alert(ack: Acknowledgement):
    try:
        ack.data.date = datetime.fromtimestamp(ack.data.ts)
    except OSError:
        raise HTTPException(422, "invalid timestamp received")
    result = setup.db[DOMAINS_REAL_TIME_NAME].update_one({"alerts.sha": ack.sha}, {"$push": {"acks": ack.dict(by_alias=True)}})
    if result.modified_count == 1:
        return ack
    else:
        raise HTTPException(422, "did not find matching alert for sha {}".format(ack.sha))

@api.get("/ping")
async def pong():
    return {
        "ping": "pong!",
    }
