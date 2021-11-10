# -*- coding: utf-8 -*-

# Run this app with `python app.py` and
# visit http://127.0.0.1:8050/ in your web browser.


import requests, logging, sys
from time import sleep
from dash import dcc, html, dash_table
from dash.dcc.Location import Location


from datetime import timedelta, datetime
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
from dash.dependencies import Input, Output, State
from utils.functions import empty_graph, table_parameters, summary_table_parameters, endpoints, get_api_data, verdict_symbols, api_url
from utils.functions import get_tags, MissingColumnException, get_filter_link, get_incident_link, get_investigation_link_splunk, get_investigation_link_vt
import dash_bootstrap_components as dbc

from dash.dependencies import Input, Output
from dash.exceptions import PreventUpdate   
from app import app

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)

# Layout

search_bar = [
    dcc.Location(refresh=True, id='analysis-query'),
    dcc.Input(type="text", value="", debounce=True, id="search-bar"),
    html.Button(n_clicks=0, children='Analyze', id="submit-button-state"),
]

summary_element = [
    html.H3("Action"),
        dcc.Loading(
                id="loading-analysis-query",
                type="default",
                children=[
                    html.A(html.Button(id='action-button', hidden=True), href=""),
                    dcc.Markdown(id='action'),
                    html.H3("Summary"),
                    dash_table.DataTable(
                    id="datatable-summary",
                    **summary_table_parameters
                        )
                    ]
        ),
]

prediction_element = [
    html.H3("Prediction"),
    dcc.Markdown(id='prediction'),
    dcc.Dropdown(id="data-category",
        options= [
            {"value": "svd_domain_registrar", "label": "registrar"},
            {"value": "svd_historical_whois", "label": "historical whois"},
            {"value": "svd_domain_categories", "label": "domain category"},
            {"value": "svd_tld_", "label": "top-level-domain"},
            {"value": "svd_url_header_content", "label": "url header content"},
            {"value": "vt_stats.siblings", "label": "siblings"},
            {"value": "vt.domain", "label": "domain"},
            {"value": "vt_stats.downloaded_files", "label": "downloaded_files"},
            {"value": "vt_stats.referrer_files", "label": "referrer_files"},
            {"value": "vt_stats.historical_whois", "label": "historical_whois"},
            {"value": "vt_stats.communicating_files", "label": "communicating_files"},
            {"value": "vt_stats.urls", "label": "urls"},
            {"value": "vt_stats.subdomains", "label": "subdomains"},
            {"value": "vt_stats.resolutions", "label": "resolutions"}
        ],
        value=[],
        multi=True
    ),
    dcc.Loading(
        id="loading-explainer-graph",
        type="default",
        children=dcc.Graph(
            id="explainer-graph",
            figure=empty_graph()
        )
    ),
]

overview = [
    html.H3("Overview"),
    dcc.Loading(
        id="loading-overview-graph",
        type="default",
        children=[dcc.Dropdown(id="overview-categories",
            options= [],
            value=[],
            multi=True
            ),dcc.Graph(
            id="overview-graph",
            figure=empty_graph()
        )]
    ),
]

tickets = [
    html.H3("Tickets"),
    dcc.Loading(id="loading-datatable-tickets", 
    children=dash_table.DataTable(
        id="datatable-tickets",
        **table_parameters
    )
    ),
]

alerts = [
    html.H3("Alerts & Acknowledgements"),
    dcc.Loading(id="loading-datatable-alerts", 
    children=dash_table.DataTable(
        id="datatable-alerts",
        **table_parameters
    )
    ),
]

endpoint_elements = [
    html.H3("VT Endpoints"),
    dcc.Loading(
        id="loading-endpoint-tags",
        type="default",
        children=dcc.Dropdown(id="endpoint-tags",
            options= [],
            value=[],
            multi=True
            ) 
    )
    ]

for endpoint in endpoints:
    endpoint_elements.append(html.H4(endpoint))
    if endpoint == "resolutions":
        endpoint_elements.append(
            dcc.Loading(id="loading-figure-worldmap-resolutions",
                children=dcc.Graph(
                    id="resolutions-map",
                    figure=empty_graph("Could not find VT Resolutions for Map Visualitation")
                )
            )
        )
    endpoint_elements.append(
        dcc.Loading(id=f"loading-datatable-{endpoint}", 
            children=dash_table.DataTable(
                id=f"datatable-{endpoint}",
                **table_parameters
            )
        ),
    )


domain_element = [
    html.H3("Domain endpoint"),
    dcc.Loading(id=f"loading-datatable-domain", 
            children=dash_table.DataTable(
                id=f"datatable-domain",
                **table_parameters
            )
        ),

]

storage = [
    dcc.Loading(
        id='loading-session',
        type="default",
        children=[
            dcc.Store(id='overview-store', storage_type='session'),
            dcc.Store(
            id='session', storage_type='session'
            ),
            dcc.Store(
                id='tickets-store', storage_type='session'
            ),
            dcc.Store(
                id='summary-store', storage_type='session'
            ),
            
        ]
    )
]

layout = html.Div(
    search_bar + \
    summary_element +\
    prediction_element + \
    overview + \
    tickets + \
    alerts + \
    domain_element + \
    endpoint_elements + \
    storage
)


# Layer 0: Setting Query url parameter

@app.callback(
    Output('analysis-query', 'search'),
    [Input('search-bar', 'value')]
)
def update_searchquery(query):
    return f"?domain={query}"

# Layer 1: Backend data request layer

@app.callback(
    Output("overview-store", "data"),
    [Input('analysis-query', 'search')],
    prevent_initial_call=False
)
def overview_data(search):
    data, _ = get_api_data("data", search)
    df = pd.DataFrame(data=data)
    df["date"] = pd.to_datetime(df["date"], unit="ms")
    return  df.to_dict("records")
    
@app.callback(
    Output('session', 'data'),
    [Input("analysis-query", "search")],
    prevent_initial_call=False
)
def get_prediction_data(search):
    domain = search.split("=")[-1]
    url = api_url + "/predict/" + domain
    resp = requests.get(url)
    if resp.status_code == 202:
        while resp.status_code == 202:
            sleep(1)
            task_id = resp.json()["task_id"]
            resp = requests.get(f"{api_url}/predict/{domain}/{task_id}")
    if resp.status_code != 200:
        return {}
    else:
        resp = resp.json()
        resp["symbol"] = verdict_symbols[resp["verdict"]]
        return resp

@app.callback(
    [
        Output("datatable-siblings", "data"),
        Output("datatable-siblings", "columns")
    ],
     [Input("analysis-query", "search")],
     prevent_initial_call=False
    )
def get_siblings(search):
    return get_api_data("domain/siblings", search)

@app.callback(
    [
        Output("datatable-resolutions", "data"),
        Output("datatable-resolutions", "columns")
    ],
     [Input("analysis-query", "search")],
     prevent_initial_call=False
    )
def get_resolutions(search):
    return get_api_data("domain/resolutions", search)

@app.callback(
    [
        Output("datatable-historical_whois", "data"),
        Output("datatable-historical_whois", "columns")
    ],
     [Input("analysis-query", "search")],
     prevent_initial_call=False
    )
def get_historical_whois(search):
    return get_api_data("domain/historical_whois", search)

@app.callback(
    [Output("overview-categories", "options"),Output("overview-categories", "value")],
    [Input("overview-store", "data")]
)
def set_overview_categories(data):
    df = pd.DataFrame(data)
    values = df["type"].unique()
    options = [{"value": k, "label": v} for k,v in zip(values, values)]
    return options, list(values)
    
@app.callback(
    [
        Output("endpoint-tags", "options"),
        Output("endpoint-tags", "value")
    ],
    [
        Input("datatable-downloaded_files", "data"),
        Input("datatable-communicating_files", "data"),
        Input("datatable-urls", "data")
    ]
)
def set_endpoint_tags(downloaded_files_data, communicating_files_data, urls_data):
    final_values = []
    for data in [downloaded_files_data, communicating_files_data, urls_data]:
        try :
            new_tags = get_tags(data)
        except MissingColumnException:
            new_tags = []
        
        final_values = new_tags + final_values
    values =  list(set(final_values))
    options = [{"value": k, "label": v} for k,v in zip(values, values)]
    return options, values

@app.callback(
[
    Output("datatable-downloaded_files", "data"),
    Output("datatable-downloaded_files", "columns"),
],
    [Input("analysis-query", "search")],
    prevent_initial_call=False
)
def get_downloaded_files(search):
    return   get_api_data("domain/downloaded_files", search)

@app.callback(
    [
        Output("datatable-communicating_files", "data"),
        Output("datatable-communicating_files", "columns")
    ],
     [Input("analysis-query", "search")],
     prevent_initial_call=False
    )
def get_communicating_files(search):
    return get_api_data("domain/communicating_files", search)

@app.callback(
    [
        Output("datatable-urls", "data"),
        Output("datatable-urls", "columns")
    ],
     [Input("analysis-query", "search")],
     prevent_initial_call=False
    )
def get_urls(search):
    return get_api_data("domain/urls", search)

@app.callback(
[
    Output("datatable-domain", "data"),
    Output("datatable-domain", "columns")
],
    [Input("analysis-query", "search")],
    prevent_initial_call=False
)
def get_domain(search):
    if search:
        domain = search.split("=")[-1]
        url = api_url + f"/domain/domain/" + domain
        resp = requests.get(url)
        if resp.status_code == 200:
            temp = resp.json()            
            columns =  [dict(name=col, id=col) for col in temp.keys()]
            try:
                temp["last_analysis_date"] = datetime.fromtimestamp(temp["last_analysis_date"])
            except KeyError:
                pass
            try : 
                temp["Umbrella Rank Date"] = datetime.fromtimestamp(temp["Umbrella Rank Date"])
            except KeyError:
                pass
            return [temp], columns
    raise PreventUpdate(msg=f"Callback error for {endpoint}. Did you enter a correct domain name?")

@app.callback(
    [
        Output("datatable-alerts", "data"),
        Output("datatable-alerts", "columns")
    ],
     [Input("analysis-query", "search")],
     prevent_initial_call=False
)
def get_alerts(search):
    return get_api_data("alerts", search)    

@app.callback(
    [
        Output("datatable-tickets", "data"),
        Output("datatable-tickets", "columns")
    ],
    [Input("analysis-query", "search")],
    prevent_initial_call=False
)
def get_tickets(search):
    logger.info(f"getting tickets for :`{search}`")
    domain = search.split("=")[-1]
    url = api_url + "/tickets/" + domain
    resp = requests.get(url)
    if resp.status_code != 200:
        raise PreventUpdate(msg="Could not load tickets from backend. {}".format(resp.reason))
    else:
        df = pd.DataFrame(resp.json())
        data = df.to_dict("records")
        columns  = [dict(name=col, id=col) if col !="url" else dict(name=col, id=col, type="text", presentation="markdown") for col in df.columns]
        return data, columns

# Layer 2: Compute & Formatting Layer 

@app.callback(
    Output("prediction", "children"),
    [Input('session', 'data')]
)
def get_prediction(data):
    if not data:
        return f"** Input Valid Domain name.**"
    else:
        ret_val = """
        **Verdict**: {symbol} `{verdict}` 
        **evilness**: `{log_odds}` 
        **threshold**: `{threshold}`""".format(**data)
        return ret_val

@app.callback(
    Output("explainer-graph", "figure"),
    [
        Input("session", "data"), 
        Input("data-category", "options"),
        Input("data-category", "value")
    ]
)
def get_explainer_fig(data, options, value):
    if data and "x_domain" in data.keys():
        x_input = pd.DataFrame(data["x_domain"])
        shap_values = pd.DataFrame(data["shap_values"])
        tmp_shap = shap_values.T 
        tmp_shap.index = x_input.columns
        tmp_x_input = x_input.T
        df_shap = pd.concat([tmp_shap, tmp_x_input], axis=1)
        feature_categories = []

        for col in df_shap.T.columns:
            has_appended = False
            for category in options:
                category_substring = category["value"]
                clean_name = category["label"]

                aggregate_this_category = not (category_substring in value)
                category_substring_matches_column_name = category_substring in col
                no_match_for_this_category_so_far = not has_appended
                
                if aggregate_this_category and \
                    category_substring_matches_column_name and \
                    no_match_for_this_category_so_far:
                    feature_categories.append(clean_name)
                    has_appended = True

            if not has_appended:
                feature_categories.append(col)
            

        df_shap["categories"] = feature_categories
        df_shap = df_shap.rename(columns={0: "shap_value"})

        df_sum = df_shap.groupby(by="categories").sum()

        df_abs_sorted = df_sum.sort_values(by="shap_value", key=lambda col: np.absolute(col))

        final_data = df_abs_sorted.cumsum()

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=final_data["shap_value"], y=final_data.index,
                            mode='lines+markers',
                            name='Path'))
        fig.update_xaxes(title_text="Prediction (logg odds)")
        fig.update_yaxes(title_text="Contribution By Category")
        return fig
    else:
        return empty_graph()

@app.callback(
    Output("resolutions-map", "figure"),
    [Input("datatable-resolutions", "data")]
)
def write_resolutions_worldmap(data):
    df = pd.DataFrame(data)
    if df.empty:
        raise PreventUpdate(msg="no resolutions")
    df.sort_values(by="date", inplace=True)
    
    
    fig = go.Figure()

    fig.add_trace(go.Scattergeo(
        lon = df['long'],
        lat = df['lat'],
        hoverinfo = 'text',
        hoverlabel=dict(
            bgcolor="white",
            font_size=16,
            font_family="Consolas"
        ),
        text = df['AS Org'],
        mode = 'markers',
        marker = dict(size=20,color='rgb(255, 0, 0)'),
        line=dict(width=3,color = 'rgba(68, 68, 68, 0)')
        )
    )

    if df.shape[0] > 1: # Multiple resolutions exist, add the trace
        df_moves = []
        
        for i in range(0, len(df.index) - 1):
            start = df.index[i]
            stop = df.index[i + 1]
            row = dict(start_lat=df.loc[start, "lat"],
                start_lon=df.loc[start, "long"],
                stop_lat=df.loc[stop, "lat"],
                stop_lon=df.loc[stop, "long"],
                date=df.loc[stop, "date"]
            )
            df_moves.append(row)
        df_moves = pd.DataFrame(df_moves)
        
        lons = np.empty(3 * len(df_moves))
        lons[::3] = df_moves['start_lon']
        lons[1::3] = df_moves['stop_lon']
        lons[2::3] = None
        lats = np.empty(3 * len(df_moves))
        lats[::3] = df_moves['start_lat']
        lats[1::3] = df_moves['stop_lat']
        lats[2::3] = None

        fig.add_trace(
            go.Scattergeo(
                lon = lons,
                lat = lats,
                text = None,
                mode = 'lines',
                line = dict(width = 3, color = 'red'),
                opacity = 0.5
            )
        )

    fig.update_layout(
        title_text = 'Travel Trajectory For Resolutions',
        showlegend = False,
        geo = dict(
        showland = True,
        showcountries = True,
        showocean = True,
        countrywidth = 0.5,
        landcolor = 'rgb(230, 145, 56)',
        lakecolor = 'rgb(0, 255, 255)',
        oceancolor = 'rgb(0, 255, 255)',
        projection = dict(
            type = 'orthographic',
            rotation = dict(
                lon = float(df["long"].tail(1)),
                lat = float(df["lat"].tail(1)),
                roll = 0
            )
        ),
        lonaxis = dict(
            showgrid = True,
            gridcolor = 'rgb(102, 102, 102)',
            gridwidth = 0.5
        ),
        lataxis = dict(
            showgrid = True,
            gridcolor = 'rgb(102, 102, 102)',
            gridwidth = 0.5
        )
    ),
        height=900,
    )

    return fig

@app.callback(
    Output("overview-graph", "figure"),
    [
        Input("overview-store", "data"),
        Input("overview-categories", "value")
    ]
)
def make_overview(data, categories):
    df = pd.DataFrame(data)    
    df = df.loc[df["type"].isin(categories),:]
    if df.empty:
        return empty_graph("No Data to Present")
    else:
        fig = px.scatter(df, y="type", x="date", color="type", marginal_x="histogram")
        return fig

@app.callback(
    [Output("datatable-summary", "data"), Output("datatable-summary", "columns")],
    [Input("datatable-alerts", "data"), Input("datatable-tickets", "data")]
)
def summarize(data_alerts, data_tickets):
    df = pd.DataFrame(data_alerts)
    if df.empty:
        raise PreventUpdate(msg="no alerts. then no tickets. stop.")
    
    first_alert = np.min(df["date"].astype("datetime64[ns]"))
    last_alert = np.max(df["date"].astype("datetime64[ns]"))
    time_since_first_alert = last_alert - first_alert
    days_since_first_alert = time_since_first_alert.days
    nr_alerts = df.shape[0]
    nr_analysts = len(df.analyst.unique())
    nr_customers = len(df.customer.unique())

    df = pd.DataFrame(data_tickets)
    
    if not df.empty:
        date_last_ticket  = np.max(df["date"])
        nr_tickets = df.shape[0]
    else:
        nr_tickets = 0
        
        date_last_ticket = "No Tickets exist" 
    summary_records = [
        {"Statistic": "Days since first Alert", "Value": days_since_first_alert},
        {"Statistic": "Nr. Tickets", "Value":  nr_tickets},
        {"Statistic": "Date Last Ticket", "Value":  date_last_ticket},
        {"Statistic": "Nr. Alerts", "Value": nr_alerts},
        {"Statistic": "Seen by nr. Analysts", "Value": nr_analysts},
        {"Statistic": "Triggered for Nr. Customers", "Value": nr_customers}
    ]
    
    return summary_records, [{"name": "Statistic", "id": "Statistic", "type": "text"}, {"name": "Value", "id": "Value"}]    


# Layer 3: Summarize

@app.callback(
    Output("action", "children"),
    [Input("datatable-summary", "data"), Input("session", "data"), Input("datatable-alerts", "data")]
)
def get_action(data, prediction, alerts):
    df = pd.DataFrame(data)
    if df.empty:
        raise PreventUpdate(msg="cannot get action without summary data")
    
    df.index = df["Statistic"]
    try:
        verdict = prediction["verdict"]
    except (KeyError, ValueError):
        raise PreventUpdate(msg="cannot get action without prediction")
    
    nr_tickets = df.loc["Nr. Tickets","Value"]
    days_since_first_alert = df.loc["Days since first Alert", "Value"]
    nr_alerts = df.loc["Nr. Alerts", "Value"]
    seen_by_nr_analysts = df.loc["Seen by nr. Analysts", "Value"]
    q75_ticket_to_incident = 25
    df_alerts = pd.DataFrame(alerts)
    if df_alerts.empty:
        raise PreventUpdate(msg="Cannot give recommendation when no alerts exist") # TODO
    df_alerts["date"] = pd.to_datetime(df_alerts["date"])
    latest_alert = df_alerts.iloc[np.argmax(df_alerts["date"]),]
    customers = list(df_alerts["customer"].unique())
    dst = latest_alert.dst
    customer =  latest_alert.customer

    filter_url = get_filter_link(customers, dst)
    incident_url = get_incident_link()
    investigate_splunk = get_investigation_link_splunk(customer, dst)
    investigation_vt = get_investigation_link_vt(dst)
    
    if nr_alerts > 0 and nr_tickets > 0:
        latest_ticket_date = pd.to_datetime(df.loc["Date Last Ticket", "Value"])
        if datetime.now() - latest_ticket_date < timedelta(days=180):
            return f"[Write Incident]({incident_url})! At least one incident exists and has been written within 6 months"
        elif verdict != "Benign":
            return f"[Investigate VT!]({investigation_vt}). Ticket is old but verdict is not benign."
        else:
            return f"[Filter!]({filter_url}) Ticket is old and verdict is benign."
    elif nr_alerts > 0 and days_since_first_alert > q75_ticket_to_incident and verdict == "Benign" and seen_by_nr_analysts > 3:
        return  f"[Filter!]({filter_url}) No incident. Domain is old and seen by multiple analysts"
    elif nr_alerts > 0 and days_since_first_alert < q75_ticket_to_incident:
        return f"[Investigate Splunk!]({investigate_splunk}) Alert is relatively fresh. Only {days_since_first_alert} days old and seen by {seen_by_nr_analysts} nr analysts."
    elif nr_alerts > 0 and verdict != "Benign":
        return  f"Investigate [VT]({investigation_vt}) and l++! Domain looks interesting. ML Verdict: {verdict}"
    elif nr_alerts > 0 and seen_by_nr_analysts >= 3:
        return f"[Filter!]({filter_url}). Domain analyzed by at least 3 analysts and no incidents."
    elif nr_alerts > 0:
        return f"Investigate [VT]({investigation_vt}) and [Splunk]({investigate_splunk}). Domain not analysed by enough analysts (<3). Currently, {seen_by_nr_analysts} nr analysts have investigated."
    else:
        return f"Action not applicable since no alerts exist."