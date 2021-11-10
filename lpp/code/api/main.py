# project/app/main.py
import os, re
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

import pandas as pd
from datetime import datetime, timedelta

from pymongo.collection import ReturnDocument
from pymongo.errors import DuplicateKeyError

from datetime import datetime, timedelta
from fastapi import HTTPException

from celery.result import AsyncResult

from aiohttp import ClientSession
from typing import Optional

from utils.database import SetupDatabase, DOMAINS_REAL_TIME_NAME, ALERTS_NAME
from utils.pipelines import pipeline_domains_dataframe
from utils.static_functions import format_data, create_mock_alert
from utils.apis import VtApi, clean_keys, DomainNotFoundException, InvalidDomainException, \
                        IsIpException, OtherVtException, QuotaExceededException

from utils.static_functions import format_data, create_mock_alert
from api.config import Alert, Acknowledgement, EndpointName, Task, Prediction
from api.static import format_endpoint, blacklist_sigs_regex, blacklist_signatures

from workers.tasks import predict, assemble_data

pipeline = pipeline_domains_dataframe({}, DOMAINS_REAL_TIME_NAME)
relevant_data = pipeline[1]["$project"]

MAX_ROWS_ALERTS = 1000
vt_api = VtApi()
setup = SetupDatabase()
api = FastAPI()
api_url = os.getenv("API_URL")
karte_url = os.getenv("KARTE_URL")

async def fetch_domain_data(domain: str):
    """ fetches vt api data for domain.
    
        Throws HTTPException
    """
    try:
        async with ClientSession(trust_env=True) as session:
            data = await vt_api.fetch_vt(domain, session)
            return data
    except (OtherVtException, QuotaExceededException, DomainNotFoundException, IsIpException, InvalidDomainException) as e:
        raise HTTPException(status_code=404, detail=e.message)


async def get_prediction_data(domain: str, bypass_cache: bool = False):
    domain_has_been_analyzed_past_day = {
        "name": domain,
        "x_domain": {"$exists": True},
        "last_analysis" : {"$gt": datetime.now() - timedelta(hours=24)}
    }
    fresh_analysis = setup.db[DOMAINS_REAL_TIME_NAME].find_one(domain_has_been_analyzed_past_day, projection={"x_domain": 1})

    try:
        if fresh_analysis and not bypass_cache: # If yes load old prediction
            return fresh_analysis["x_domain"]
        else: 
            # fetch vt data
            data = await fetch_domain_data(domain)
            data = format_data(data, domain)
            
            # remove chars not allowed in mongo
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


@api.get("/domain/{endpoint}/{name}")
async def get_endpoint_json(endpoint: EndpointName, name: str):
    data = setup.db[DOMAINS_REAL_TIME_NAME].find_one({"name": name}, {f"vt.{endpoint}.data": 1})
    if data:
        df = format_endpoint(endpoint, data["vt"][endpoint]["data"])
        return df
    else:
        return {}


@api.get("/predict/all/result/{task_id}")
async def get_predictions_result(task_id: str):
    task = AsyncResult(task_id)
    if not task.ready():
        return JSONResponse(status_code=202, content={'task_id': str(task_id), 'status': 'Processing'})
    else:
        result = task.get()
        return result


@api.get("/predict/all", response_model=Task, status_code=202)
async def get_predictions():
    """
    Returns predictions for all real time alerts
    """
    task_id = assemble_data.delay()
    return {'task_id': str(task_id), 'status': 'Processing'}


@api.get("/predict/{name}/{task_id}", response_model=Prediction, status_code=200,
         responses={202: {'model': Task, 'description': 'Accepted: Not Ready'}})
async def predict_result(name: str, task_id: str):
    task = AsyncResult(task_id)
    
    if not task.ready():
        return JSONResponse(status_code=202, content={'task_id': str(task_id), 'status': 'Processing'})
    else:

        try:
            result = task.get()
        except TypeError as e:
            msg = str(e)
            if "only size-1 arrays" in msg:
                # bad data stuck somewhere in backend. Redirect client to bypass cache
                return RedirectResponse(api_url + f"/predict/{name}?bypass_cache=1")    
        
        # cache prediction in mongodb
        setup.db[DOMAINS_REAL_TIME_NAME].update_one({"name": result["name"]}, {"$set": {
            "last_analysis": datetime.now(), 
            "shap_values": result["shap_values"], 
            'x_domain': result["x_domain"],
            'log_odds': result["log_odds"],
            'verdict': result["verdict"]
            }
        }
        )
        result["task_id"] = task_id
        result["status"] = "Success"
        return result

@api.get("/predict/{name}",  response_model=Task, status_code=202)
async def get_prediction(name: str, bypass_cache: Optional[int] = None):
    """ Gets a prediction for `name`.

    If bypass_cache is specified, then fresh data will be fetched from vt.
    
    """
    data = await get_prediction_data(name, bypass_cache) # io bound
    task_id = predict.delay(data) #cpu bound
    return {'task_id': str(task_id), 'status': 'Processing'}


@api.post("/predict/",  response_model=Task, status_code=202)
async def post_prediction(alert: Alert):
    if not re.search(blacklist_sigs_regex, alert.name):
        raise HTTPException(422, f"alert name as to match a known blacklist signature. {blacklist_signatures}")
    domain = alert.dst
    if alert.timestamp:
        try:
            alert.date = datetime.fromtimestamp(float(alert.timestamp))
        except (TypeError, ValueError):
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
    try:
        setup.db[ALERTS_NAME].insert_one(tmp)
    except DuplicateKeyError:
        raise HTTPException(422, "{} has already been analyzed".format(tmp["sha"]))
    data = await get_prediction_data(domain) # io bound
    task_id = predict.delay(data) #cpu bound
    return {'task_id': str(task_id), 'status': 'Processing'}

def format_ticket_data(data: pd.DataFrame) -> pd.DataFrame:
    df = pd.DataFrame(data)
    df["id"] = df["id"].astype("str")
    df["karte_id"] = df["karte_id"].astype("str")
    df["url"] = df["karte_id"].apply(parse_karte_id)
    df["url"] = df["url"].apply(lambda url: "[{0}]({0})".format(url))
    df["date"] = df["date"].astype("datetime64")
    df["severity"] = df["severity"].astype("category")
    df.drop(columns=["shas", "karte_id"], inplace=True)
    df.drop_duplicates(subset=["id"], inplace=True)
    return df

def homogenize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """ reformats df to keep type and data and adds remaining columns as json data under key "data"
        df: a pandas dataframe that must have the columns `type` and `date` 
        returns: df_homogenized_columns: a pandas dataframe containing type date and data
     """
    
    data_columns = df.loc[:, ~df.columns.isin(["type", "date"])]
    try:
        df_homogenized_columns = df.loc[:,["type", "date"]]
    except KeyError as e:
        raise e
    df_homogenized_columns["data"] = data_columns.to_dict("records")
    return df_homogenized_columns

def get_vt_data(endpoint, data):
    try:
        items = data[endpoint]["data"]
        subtypes = [item["type"] for item in items]
        df_data = [item["attributes"] for item in items]
        dates = [ datetime.fromtimestamp(item["attributes"]["last_analysis_date"]) for item in items]
        return pd.DataFrame(data=dict(type=endpoint, subtype=subtypes, data=df_data, date=dates))
    except KeyError:
        return pd.DataFrame()

@api.get("/data/{name}")
async def get_data(name: str):
    
    # Alerts
    data = setup.db["domains_realtime"].find_one({"name": name}, {"vt":1, "alerts":1, "tickets.tickets":1, "acks": 1, "_id": 0})
    if "alerts" in data.keys():
        alerts = pd.DataFrame(data["alerts"])
        acks = pd.json_normalize(data["acks"])
        df = pd.merge(alerts, acks, on="sha")
        df["type"] = "alert"
        df.drop(columns=["data.ts", "sha", "timestamp", "data.origin"], inplace=True)
        df.rename(columns={"data.date": "ack time", "data.ref": "workstation", "data.user": "analyst", "data.level": "severity"}, inplace=True)
    else:
        df = pd.DataFrame() # no alerts

    
    
    df = homogenize_dataframe(df)

    # Tickets
    try:
        tickets = data["tickets"][0]["tickets"]
        tickets_df = format_ticket_data(tickets)
        tickets_df["type"] = "ticket"
        tickets_df = homogenize_dataframe(tickets_df)
    except (KeyError, IndexError, TypeError):
        tickets_df = pd.DataFrame() # no tickets

    df = df.append(tickets_df, ignore_index=True)
    df["subtype"] = ""
    
    # vt data
    vt_data = data["vt"]

    # domain endpoint
    t = vt_data["domain"]
    le_type = t["data"]["type"]
    
    date = t["data"]["attributes"]["last_modification_date"]
    domain_df = pd.DataFrame(data=dict(date=[datetime.fromtimestamp(date)], type=[le_type], subtype="", data=[t["data"]["attributes"]]))
    df = df.append(domain_df, ignore_index=True)

    endpoints = ["communicating_files", "downloaded_files", "referrer_files", "urls"]
    for endpoint in endpoints:
        try:
            vt_endpoint_df = get_vt_data(endpoint, vt_data)
        except TypeError as e:
            raise e
        df = df.append(vt_endpoint_df, ignore_index=True)
    return df.to_json()
    

@api.get("/alerts/{name}")
async def get_alerts(name: str):
    data = setup.db["domains_realtime"].find_one({"name": name}, {"alerts.sha": 1, "alerts.date": 1, "alerts.dst": 1, "alerts.timestamp": 1, "alerts.name": 1, "alerts.customer": 1,"acks": 1, "_id": 0})
    try:
        alerts_data = data["alerts"]
        acks_data = data["acks"]
        alerts = pd.DataFrame(alerts_data)
        acks =pd.json_normalize(acks_data)
        df = pd.merge(alerts, acks, on="sha")
        df.drop(columns=["data.ts", "sha", "timestamp", "data.origin"], inplace=True)
        df.rename(columns={"data.date": "ack time", "data.ref": "workstation", "data.user": "analyst", "data.level": "severity"}, inplace=True)
        return df.to_dict()
    except (KeyError, IndexError, TypeError):
        raise HTTPException(404, detail=f"could not retreive alerts for domain `{name}`")

@api.get("/dataframe/tickets_and_alerts")
async def get_dataframe_pre_scaling():
    try:
        df = pd.read_pickle("model/df_tickets_and_alerts.pickle")
        subset = df[["alert_first_date", "ticket_first_date", "alert_last_date"]]
        subset.dropna(inplace=True)
        return subset[["alert_first_date", "ticket_first_date"]].to_dict()
    except FileNotFoundError:
        raise HTTPException(404, "dataframe not found in backend. Perform manual investigation for df_tickets_and_alerts.pickle")

def parse_karte_id(karte_id):
    if karte_id != "nan":
        res = karte_id.split(".")[0]
        return karte_url + res
    else:
        return ""

@api.get("/tickets/{name}")
async def get_tickets(name: str):
    data = setup.db["domains_realtime"].find_one({"name": name}, {"tickets.tickets": 1, "_id":0})
    try:
        tickets = data["tickets"][0]["tickets"]
    except (KeyError, IndexError, TypeError):
        return {}
    df = pd.DataFrame(tickets)
    df["id"] = df["id"].astype("str")
    df["karte_id"] = df["karte_id"].astype("str")
    df["url"] = df["karte_id"].apply(parse_karte_id)
    df["url"] = df["url"].apply(lambda url: "[{0}]({0})".format(url))
    df["date"] = df["date"].astype("datetime64")
    df["severity"] = df["severity"].astype("category")
    df.drop(columns=["shas", "karte_id"], inplace=True)
    df.drop_duplicates(subset=["id"], inplace=True)
    return df.to_dict()

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
