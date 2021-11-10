# -*- coding: utf-8 -*-

# Run this app with `python app.py` and
# visit http://127.0.0.1:8050/ in your web browser.

import time, math
import dash, requests, os
from dash.dcc.Loading import Loading
from dash import dcc, html, dash_table

import plotly.express as px
import plotly.graph_objects as go

from sklearn.metrics import precision_recall_curve
import pandas as pd

from dash.dependencies import Input, Output, State

from dash.dependencies import Input, Output
from dash.exceptions import PreventUpdate
from utils.functions import make_graph, empty_graph

from app import app
api_url = os.getenv("API_URL")

def get_log_odds_graph(df, categories=None):
    if not categories:
        categories = list(df["verdict"].unique())
    fig = px.histogram(df[df["verdict"].isin(categories)], 
                    x="log_odds", 
                    color="verdict", 
                    nbins=66, 
                    title="Log-odds of SOC writing ticket on domain",
                    hover_name="domain")
    fig.update_xaxes(title_text='Maliciousness (log-odds)')
    fig.update_yaxes(title_text='Nr. Domains')
    return fig

layout = html.Div([
    html.H3('Overview'),
    html.Button('Request Data', id='submit-request-data', n_clicks=0),
    html.Div(id='overview-display-value'),
    dcc.Loading(
        id="loading-log-odds-histogram",
        type="default",
        children=dcc.Graph(id="log-odds-histogram", figure=empty_graph("Request the data!"))
    ),
    dcc.Loading(
        id="loading-precision-recall",
        type="default",
        children=dcc.Graph(id="precision-recall", figure=empty_graph("Request the data!"))
    ),
    dcc.Loading(
        id="loading-prediction-category",
        type="default",
        children=dcc.Dropdown(id="prediction-category", multi=True)
    ),
    dcc.Loading(id="loading-datatable-interactivity", 
        children=dash_table.DataTable(
            id="datatable-interactivity",
            filter_action="native",
            sort_action="native",
            sort_mode="multi",
            page_action="native",
            page_current= 0,
            page_size= 15,
            style_data={'whiteSpace': 'normal', 'height': 'auto', 'lineHeight': '15px'},
            style_cell_conditional=[{'if': {'column_id': col},'textAlign': 'left' } for col in ['domain']],
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': 'rgb(248, 248, 248)'
                },
                {
                    "if": { 'filter_query': '{verdict} != "Benign"', 'column_id': "verdict"},
                    'backgroundColor': 'tomato',
                    'color': 'white'
                }
            ],
            style_header={
                'backgroundColor': 'rgb(230, 230, 230)',
                'fontWeight': 'bold'
            },
        )
        ),
])

@app.callback(
    Output("precision-recall", "figure"),
    [Input("datatable-interactivity", "data")]
)
def make_precision_recall_curve(data):
    def sigmoid(x):
        return 1 / (1 + math.exp(-x))

    df = pd.DataFrame(data)
    probabilities = df["log_odds"].apply(sigmoid)
    precision, recall, _ = precision_recall_curve(df["ticket_label"], probabilities)
    fig = go.Figure(data=go.Scatter(x=recall, y=precision))
    fig.update_layout(xaxis_title="Recall: TP / (FN + TP)", yaxis_title="Precision: TP / (TP + FP)", title="Performance of Current Model")
    return fig

@app.callback(
    [
        Output("prediction-category", "options"),
        Output("prediction-category", "value"),  
        Output("datatable-interactivity", "data"),
        Output("datatable-interactivity", "columns"),
    ],
    [
        Input("submit-request-data", "n_clicks")]
)
def request_data(n_clicks):
    resp = requests.get(api_url + "/predict/all")
    while resp.status_code == 202:
        time.sleep(0.1)
        task_id = resp.json()["task_id"]
        resp = requests.get(api_url + f"/predict/all/result/{task_id}")    
    if resp.ok:
        data = resp.json()
        df = pd.DataFrame.from_dict(data)
    else:
        raise PreventUpdate(msg="Could not load data for log odds from backend. {}".format(resp.reason))
    df.insert(0, "domain", df.index)
    return [{"label": x, "value": x} for x in list(df["verdict"].unique())], \
        list(df["verdict"].unique()), \
        df.to_dict("records"), \
        [{"name": col, "id": col} for col in df.columns]

@app.callback(
    Output("log-odds-histogram", "figure"),
    [
        Input("datatable-interactivity", "data"),
        Input("prediction-category", "value")]
)
def display_graph(df_json, categories):
    data = pd.DataFrame(df_json)
    fig = get_log_odds_graph(data, categories)
    fig.update_xaxes(range=(min(data["log_odds"]), max(data["log_odds"])))
    return fig
