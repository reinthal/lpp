import os, pickle

from requests.models import HTTPError
import streamlit as st
# To make things easier later, we're also importing numpy and pandas for
# working with sample data.
import numpy as np
import pandas as pd
import os
import requests
from time import sleep
from datetime import datetime, timedelta
from pandas import json_normalize
from utils.functions import verdict_symbols, make_freshness_gauge, format_url_entries, get_urls_figure, \
    format_resolutions_entries, format_siblings_entries, format_communicating_files_entries, get_com_files_figure, \
        get_domains,  format_historical_whois, get_explainer_fig
from utils.functions import NoDataFound
from utils.database import ConnectDatabase, DOMAINS_NAME, DOMAINS_REAL_TIME_NAME
import plotly.express as px
import plotly.offline as pyo
import plotly.graph_objects as go
from plotly.subplots import make_subplots

api_url = os.getenv("API_URL")
MAX_TIME = 72 # hours
MAX_ALERTS = 10 # nr alerts

def connect_database():
    connection = ConnectDatabase()
    return connection

def get_prediction(domain):
    resp = requests.get(api_url + "/predict/" + domain)
    while resp.status_code == 202:
        sleep(0.2)
        task_id = resp.json()["task_id"]
        resp = requests.get(api_url + "/predict/result/" + task_id)
    resp = resp.json()
    resp["symbol"] = verdict_symbols[resp["verdict"]]
    return resp

def get_tickets(connection, domain, collection=DOMAINS_NAME):

    doc = connection.db[collection].find_one({"name": domain}, {"tickets": 1})
    try:
        if doc and "tickets" in doc.keys():
            tickets_data = doc["tickets"][0]["tickets"]
            return pd.DataFrame(tickets_data)
        else:
            raise NoDataFound()
    except (IndexError, KeyError):
        raise NoDataFound

def get_data(field, connection, domain, collection=DOMAINS_REAL_TIME_NAME):
    doc = connection.db[collection].find_one({"name": domain}, {field: 1})
    
    if doc and field in doc.keys():
        data = doc[field]
        return json_normalize(data)
    else:
        raise NoDataFound()


def write_prediction(domain):
    resp = get_prediction(domain)
    st.write("**Verdict**: {symbol} `{verdict}`\n **evilness**: `{log_odds}`\n **threshold**: `{evil_threshold}`".format(
        symbol=resp["symbol"], 
        verdict=resp["verdict"],
        log_odds=resp["log_odds"],
        evil_threshold=resp["threshold"]
        )
    )

def get_freshness_ioc(connection, domain):
    df_alerts = get_data("alerts", connection, domain)
    df_alerts.sort_values("date", ascending=True, inplace=True)
    last_seen = df_alerts.tail(1)["date"].iloc[0]
    first_seen = df_alerts.head(1)["date"].iloc[0]
    elapsed_time = last_seen - first_seen
    nr_alerts = df_alerts.shape[0]
    freshness_time_left =  max(MAX_TIME - (elapsed_time.days  * 24 + elapsed_time.seconds // 3600), 0)
    freshness_alerts_left = max(MAX_ALERTS  - nr_alerts, 0)
    
    if freshness_time_left == 0:
        age = "old 👵"
    else:
        age ="fresh 🌱!"
    time_left_fig = make_freshness_gauge(freshness_time_left, MAX_TIME, title=f"Hours Left")
    alerts_left_fig = make_freshness_gauge(freshness_alerts_left, MAX_ALERTS, title=f"Alerts Left")
    
    return time_left_fig, alerts_left_fig, age, first_seen, df_alerts

st.title(f"l++ 🐨 domain analysis")
params = st.experimental_get_query_params()
if "domain" in params.keys():
    domain = params["domain"][0]
    st.title(f"Analyzing `{domain}`")

    connection = ConnectDatabase()
    
    # Prediction
    write_prediction(domain)
    
    # explanation
    resp  = requests.get(api_url + f"/explain/{domain}")
    if resp.ok:
        doc = connection.db[DOMAINS_REAL_TIME_NAME].find_one({"name": domain}, {"shap_values": 1, "x_domain": 1})
        if doc:
            shap_values = pickle.loads(doc["shap_values"])
            x_input = pickle.loads(doc["x_domain"])
            fig = get_explainer_fig(x_input, shap_values)
            st.write(fig)
            
    else:
        st.write(resp.reason)
    
    # Tickets
    try:
        tickets = get_tickets(connection, domain)
        tickets.drop_duplicates(subset=['id'], inplace=True)
        nr_tickets = int(tickets.shape[0])
        st.header(f"{nr_tickets} tickets found")
        st.write(tickets)
    except NoDataFound:
        pass
    
    # Acks
    try:
        acks = get_data("acks", connection, domain)
        acks.drop_duplicates(subset=["data.user"], inplace=True)
        nr_ackers = acks.shape[0]
        if nr_ackers == 1:
            noun = "analyst"
        else:
            noun = "analysts"
        st.header(f"Acknowledged by {nr_ackers} {noun}")
        st.write(acks.loc[:,["data.user", "data.date", "data.origin", "data.ref"]])
    except NoDataFound:
        pass

    # Freshness
    try:
        time_left_fig, alerts_left_fig, age, first_seen, df_alerts = get_freshness_ioc(connection, domain)
        st.header(f"`{domain}` is {age}")
        st.write("First Seen: {}".format(first_seen.strftime("%Y-%m-%d %H:%M:%S %Z")))
        col1, col2 = st.beta_columns(2)
        with col1:
            st.write(time_left_fig)
        with col2:
            st.write(alerts_left_fig)
        st.header("Alerts")
        st.write(df_alerts.drop(columns=["sha", "timestamp"]).sort_index(axis=1))
    except NoDataFound:
        pass        

    # Vt Features

    # Domains
    st.header("VT Domains")
    data = connection.db[DOMAINS_REAL_TIME_NAME].find_one({"name": domain}, {"vt": 1})
    d = json_normalize(data["vt"])
    fig = get_domains(d)
    st.write(fig)
    
    # URLs
    st.header("VT URLs")
    urls = format_url_entries(data["vt"]["urls"]["data"])
    if urls.shape[0]: # are there any urls?
        fig  = get_urls_figure(urls)
        st.write(fig)
        st.write(urls)
    else:
        st.write("no urls found")

    # Communicating files
    
    try:
        com_files = format_communicating_files_entries(data["vt"]["communicating_files"]["data"])
        fig = get_com_files_figure(com_files)
        st.header("VT Communcating Files")
        st.write(fig)
        st.write(com_files)
        # Resolutions
        st.header("VT Resolutions")
        resolutions = format_resolutions_entries(data["vt"]["resolutions"]["data"])
        if resolutions.shape[0]:
            resolutions.sort_values("date", ascending=False, inplace=True)
            st.write(resolutions)
        else:
            st.write("No resolutions found")
    except KeyError:
        pass
    
    # Historical Whois
    try:
        whois = format_historical_whois(data["vt"]["historical_whois"]["data"])
        st.header("Historical Whois")
        if not whois.empty:
            st.write(whois)
    except KeyError:
        st.write("No whois found")

    # Siblings
    st.header("VT Siblings")
    siblings = format_siblings_entries(data["vt"]["siblings"]["data"])
    if not siblings.empty:
        st.write(siblings.sort_values("last_modification_date", ascending=False).head(15))
    else:
        st.write("No siblings found")
else:
    st.write("use parameters `/?domain=<evil.com>` to query domain")
