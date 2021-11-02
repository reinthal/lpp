import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np

sky_colors =  ['rgb(253, 156, 140)', 'rgb(118, 91, 140)', 'rgb(205, 193, 229)']

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


def format_historical_whois(data):
    d = []
    for entry in data:
        attributes = entry["attributes"] 
        temp =  {
            "registrar": attributes["registrar_name"],
            "first_seen_date": pd.Timestamp(attributes["first_seen_date"], unit='s').floor('D'),
            "last_updated": pd.Timestamp(attributes["last_updated"], unit='s').floor('D'),
            "Creation Date": attributes["whois_map"]["Creation Date"],
            "Registry Expiry Date": attributes["whois_map"]["Registry Expiry Date"],
            "Updated Date": attributes["whois_map"]["Updated Date"],
        }

        d.append(temp)
    return pd.DataFrame(d)


def make_freshness_gauge(number, reference, title):
    
    fig = go.Figure(go.Indicator(
        mode = "number+delta",
        value = number,
        delta = {"reference": reference},
        title = {'text': f"{title}"},
    ))
    fig.update_layout(
        autosize=False,
        width=500,
        height=500
    )
    return fig

def get_domains(d):
    labels = ['Malicious','harmless','undetected']
    values = [
        int(d["domain.data.attributes.last_analysis_stats.malicious"]), 
        int(d["domain.data.attributes.last_analysis_stats.undetected"]),
        int(d["domain.data.attributes.last_analysis_stats.harmless"])
    ]
    sky_colors =  ['rgb(253, 156, 140)', 'rgb(118, 91, 140)', 'rgb(205, 193, 229)']
    fig = go.Figure(data=[go.Pie(labels=labels, 
                                values=values, 
                                marker_colors=sky_colors,
                                pull=[0.2, 0, 0])])
    fig.update_traces(textposition='inside', textinfo='percent+label')
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

def format_siblings_entries(data):
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"] 
        temp =  {
            "registrar": attributes["registrar"],
            "last_modification_date": pd.Timestamp(attributes["last_modification_date"], unit='s').floor('D'),
            "last_update_date": pd.Timestamp(attributes["last_update_date"], unit='s').floor('D'),
            "harmless": attributes["last_analysis_stats"]["harmless"],
            "malicious": attributes["last_analysis_stats"]["malicious"],
            "undetected": attributes["last_analysis_stats"]["undetected"],
            "whois": attributes["whois"]
        }
        
        
        try:
            temp["tags"] = " ".join(attributes["tags"])
        except KeyError:
            temp["tags"] = ""
        
        categories = []
        for key in attributes["categories"].keys():
            categories.append(attributes["categories"][key])
        temp["categories"] = " ".join(categories)
        d.append(temp)
    df = pd.DataFrame(d)
    return df

def format_resolutions_entries(data):
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"]
        temp =  {
            "date": pd.Timestamp(attributes["date"], unit='s'),
            "host": attributes["host_name"],
            "ip": attributes["ip_address"],
            "resolver": attributes["resolver"]
        }
        d.append(temp)
    df = pd.DataFrame(d)
    return df

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

def format_communicating_files_entries(data):
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"]
        temp =  {
            "tags": " ".join(attributes["tags"]),
            "last_analysis_date": pd.Timestamp(attributes["last_analysis_date"], unit='s').floor('D'),
            "harmless": attributes["last_analysis_stats"]["harmless"],
            "malicious": attributes["last_analysis_stats"]["malicious"],
            "undetected": attributes["last_analysis_stats"]["undetected"],
            "sha": attributes["sha256"],
            "magic": attributes["magic"] 
        }
        d.append(temp)
    df = pd.DataFrame(d)
    return df

def format_downloaded_files_entries(data):
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"]
        temp =  {
            "tags": " ".join(attributes["tags"]),
            "last_analysis_date": pd.Timestamp(attributes["last_analysis_date"], unit='s').floor('D'),
            "harmless": attributes["last_analysis_stats"]["harmless"],
            "malicious": attributes["last_analysis_stats"]["malicious"],
            "undetected": attributes["last_analysis_stats"]["undetected"],
            "reputation": attributes["reputation"],
            "sha": attributes["sha256"]
        }
        d.append(temp)
    df = pd.DataFrame(d)
    return df

def format_url_entries(data):
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"]
        temp =  {
            "tags": " ".join(attributes["tags"]),
            "last_analysis_date": pd.Timestamp(attributes["last_analysis_date"], unit='s').floor('D'),
            "harmless": attributes["last_analysis_stats"]["harmless"],
            "malicious": attributes["last_analysis_stats"]["malicious"],
            "undetected": attributes["last_analysis_stats"]["undetected"],
            "url": attributes["url"]
        }
        d.append(temp)
    df = pd.DataFrame(d)
    return df