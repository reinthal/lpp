import json
import pandas as pd
import dash_core_components as dcc
import dash_table
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import requests, os
from dash.exceptions import PreventUpdate
import urllib

api_url = os.getenv("API_URL")

verdict_symbols = {
    "Benign": "✅",
    "Not Sure": "❓",
    "Malicious": "😎"
}

sky_colors =  ['rgb(253, 156, 140)', 'rgb(118, 91, 140)', 'rgb(205, 193, 229)']
endpoints = ["urls", "communicating_files", "downloaded_files", "historical_whois", "resolutions", "siblings"]

summary_table_parameters = dict(
        style_data={'whiteSpace': 'normal', 'height': 'auto', 'lineHeight': '15px'},
        style_cell={'textAlign': 'left'},
        style_data_conditional=[
            {
                'if': {'row_index': 'odd'},
                'backgroundColor': 'rgb(248, 248, 248)'
            },
        ],
        style_header={
            'backgroundColor': 'rgb(230, 230, 230)',
            'fontWeight': 'bold'
        },
)

table_parameters = dict(filter_action="native",
        sort_action="native",
        sort_mode="multi",
        page_action="native",
        page_current= 0,
        page_size= 15,
        style_data={'whiteSpace': 'normal', 'height': 'auto', 'lineHeight': '15px'},
        style_data_conditional=[
            {
                'if': {'row_index': 'odd'},
                'backgroundColor': 'rgb(248, 248, 248)'
            },
        ],
        style_header={
            'backgroundColor': 'rgb(230, 230, 230)',
            'fontWeight': 'bold'
        },
)

class MissingColumnException(Exception):
    pass
def get_investigation_link_vt(dst):
    return f"https://www.virustotal.com/gui/domain/{dst}/detection"

def get_investigation_link_splunk(customer, dst):
    return f"https://global-sh01.gss01.nttsecurity.net:8000/en-US/app/search/search?q=search+`{customer}`+{dst}+&earliest=-7d@h&latest=now&display.page.search.mode=verbose"
    

def get_incident_link():
    return "https://karte.gss01.nttsecurity.net/ticket-new"

def get_filter_link(customers, dst):
    if len(customers) > 1:
        customer_regex = "(" + "|".join(customers) + ")"
    else:
        customer_regex = customers[0]
    url =  f"http://filter.gcs.gmssp.io/admin/filterconf/filter/add/?criterium-key-0=customer&criterium-value-0={customer_regex}&criterium-key-1=dst&criterium-value-1={dst}"
    return url

def get_tags(data):
    df = pd.DataFrame(data)
    if "tags" not in df.columns:
        raise MissingColumnException
    else:
        return list(df.tags.apply(pd.Series).stack().reset_index(drop=True).unique())

def get_api_data(endpoint, search) -> tuple:
    """fetches data from the api and formats into return values"""
    if search:
        domain = search.split("=")[-1]
        url = api_url + f"/{endpoint}/" + domain
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.json()
            if type(data) == str: 
                data = json.loads(data)
            df = pd.DataFrame(data=data)
            if not df.empty:
                return df.to_dict("records"), [dict(name=col, id=col) for col in df.columns if col != "tags"]
    raise PreventUpdate(msg=f"Callback error for {endpoint}. Did you enter a correct domain name?")

def empty_graph(message="No Matching data found"):
    empty_graph =  {
        "layout": {
            "xaxis": {
                "visible": False
            },
            "yaxis": {
                "visible": False
            },
            "annotations": [
                {
                    "text": message,
                    "xref": "paper",
                    "yref": "paper",
                    "showarrow": False,
                    "font": {
                        "size": 28
                    }
                }
            ]
        }
    }
    return empty_graph

def make_graph(id):
    graph_component = dcc.Loading(
        id=f"loading-{id}",
        type="default",
        children=dcc.Graph(id=id, figure=empty_graph)
    )
    return graph_component

verdict_symbols = {
    "Benign": "✅",
    "Not Sure": "❓",
    "Malicious": "😎"
}

category_list = {
    "svd_domain_registrar": "registrar",
    "svd_historical_whois": "historical whois",
    "svd_domain_categories": "domain category",
    "svd_tld_": "top-level-domain",
    "svd_url_header_content": "url header content",
    "vt_stats.siblings": "siblings",
    "vt.domain": "domain",
    "vt_stats.downloaded_files": "downloaded_files",
    "vt_stats.referrer_files": "referrer_files",
    "vt_stats.historical_whois": "historical_whois",
    "vt_stats.communicating_files": "communicating_files",
    "vt_stats.urls": "urls"
}

class NoDataFound(Exception):
    pass

def get_explainer_fig(x_input, shap_values):
    tmp_shap = pd.DataFrame(shap_values.T, index=x_input.columns)
    tmp_x_input = x_input.T
    df_shap = pd.concat([tmp_shap, tmp_x_input], axis=1)
    feature_categories = []
    category_list = {
        "svd_domain_registrar": "registrar",
        "svd_historical_whois": "historical whois",
        "svd_domain_categories": "domain category",
        "svd_tld_": "top-level-domain",
        "svd_url_header_content": "url header content",
        "vt_stats.siblings": "siblings",
        "vt.domain": "domain",
        "vt_stats.downloaded_files": "downloaded_files",
        "vt_stats.referrer_files": "referrer_files",
        "vt_stats.historical_whois": "historical_whois",
        "vt_stats.communicating_files": "communicating_files",
        "vt_stats.urls": "urls",
        "vt_stats.subdomains": "subdomains",
        "vt_stats.resolutions": "resolutions"
    }

    for col in df_shap.T.columns:
        has_appended = False
        for category_substring, clean_name in category_list.items():
            if category_substring in col and not has_appended:
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

def get_urls_figure(data):
    nr_samples = 20
    data = data.sort_values(by=['last_analysis_date', 'malicious'], ascending=False).head(nr_samples)

    data_melt_url = data.melt(id_vars=["url", "last_analysis_date"], 
                value_vars=["malicious", "harmless",  "undetected"])
    fig = px.bar(
        data_melt_url, 
        x="last_analysis_date", y="value", color="variable", 
        color_discrete_sequence=sky_colors,
        hover_name="url", hover_data=["url"])
    fig.update_yaxes(title="Votes")
    return fig 

def make_pie(malicious, undetected, harmless, title):
    labels = ['Malicious','harmless','undetected']
    values = [malicious, undetected,harmless]
    pie = go.Pie(labels=labels, values=values, marker_colors=sky_colors, pull=[0.2, 0, 0], name=title)
    return pie


def get_com_files_figure(data):
    data = data.sort_values(by=["last_analysis_date", "malicious"], ascending=False).head(10)


    data_melt_communicating_files = data.melt(id_vars=["sha", "last_analysis_date", "magic"], 
                  value_vars=["malicious", "harmless",  "undetected"])
    data_melt_communicating_files["magic"] = data_melt_communicating_files["magic"].apply(lambda a: a[:60]) # truncate this for nicer output in the mouse-over
    fig = px.bar(
        data_melt_communicating_files, 
        x="last_analysis_date", y="value", color="variable", 
        color_discrete_sequence=sky_colors,
        hover_name="magic", 
        hover_data=["sha", "last_analysis_date"]
    )
    fig.update_yaxes(title="Votes")
    return fig