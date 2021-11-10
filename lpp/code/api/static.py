from datetime import datetime
import pandas as pd
from pydantic.types import Json
import re
from geoip2.errors import AddressNotFoundError
blacklist_signatures = ".*(blacklisted domain|blacklisted hostname|threatlist hostname|known C2 hostname|known Malware hostname|Typosquat domain|malicious executable download|outbound requests \(vendor malicious category, sparse single host\)).*"
blacklist_sigs_regex = re.compile(blacklist_signatures)

from geoip2.database import Reader
import logging, sys

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)

asn_reader = Reader("/usr/src/app/data/GeoLite2-ASN_20210511/GeoLite2-ASN.mmdb")
city_reader = Reader("/usr/src/app/data/GeoLite2-City_20210511/GeoLite2-City.mmdb")

def _format_domain(data: dict) -> Json:
    attributes = data["attributes"]
    categories = [val for _,val in attributes["categories"].items()]
    temp =  {
        "last_analysis_date": attributes["last_modification_date"],
        "malicious": attributes["last_analysis_stats"]["malicious"],

        "tags": attributes["tags"] + categories
    }
    try:
        temp["registrar"] =  attributes["registrar"],
    except KeyError:
        pass
    try:
        temp["Umbrella Rank"] = attributes["popularity_ranks"]["Cisco Umbrella"]["rank"]
        temp["Umbrella Rank Date"] = attributes["popularity_ranks"]["Cisco Umbrella"]["timestamp"]
    except KeyError:
        pass    
    return temp


def _format_communicating_files_entries(data: dict) -> Json:
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"]
        temp =  {
            "tags": attributes["tags"],
            "last_analysis_date": pd.Timestamp(attributes["last_analysis_date"], unit='s').floor('D'),
            "malicious": attributes["last_analysis_stats"]["malicious"],
            "sha": attributes["sha256"],
            "magic": attributes["magic"] 
        }        
        d.append(temp)
    df = pd.DataFrame(d)
    return df.to_dict()

def _format_downloaded_files_entries(data: dict) -> Json:
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"]
        temp =  {
            "tags": attributes["tags"],
            "last_analysis_date": pd.Timestamp(attributes["last_analysis_date"], unit='s').floor('D'),
            "malicious": attributes["last_analysis_stats"]["malicious"],
            "name": attributes["meaningful_name"],
            "reputation": attributes["reputation"],
            "sha": attributes["sha256"]
        }
        d.append(temp)
    df = pd.DataFrame(d)
    return df.to_dict()

def _format_url_entries(data: dict) -> Json:
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"]
        categories = []
        for _, val in attributes["categories"].items():
            categories.append(f"{val}")
        temp =  {
            "tags": attributes["tags"] + categories,
            "last_analysis_date": pd.Timestamp(attributes["last_analysis_date"], unit='s').floor('D'),
            "malicious": attributes["last_analysis_stats"]["malicious"],
            "url": attributes["url"]
        }
        d.append(temp)
    df = pd.DataFrame(d)
    return df.to_dict()

def add_ip_lookup(destination_json, ip):
        
        # add some defaults
        destination_json["AS Number"] = -1
        destination_json["AS Org"] = ""
        destination_json["lat"] =  90.0
        destination_json["long"] = 0.0
        destination_json["acc radius"] = 1
        
        try:
            response_asn = asn_reader.asn(destination_json["ip"])
            destination_json["AS Number"] = response_asn.autonomous_system_number
            destination_json["AS Org"] = response_asn.autonomous_system_organization
        except AddressNotFoundError:
            pass
        try:
            response_city = city_reader.city(destination_json["ip"])
            destination_json["lat"] = response_city.location.latitude
            destination_json["long"] = response_city.location.longitude
            destination_json["acc radius"] = response_city.location.accuracy_radius
        except AddressNotFoundError:
            pass


def _format_resolutions_entries(data: dict) -> Json:
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"]
        temp =  {
            "date": pd.Timestamp(attributes["date"], unit='s'),
            "host": attributes["host_name"],
            "ip": attributes["ip_address"],
            "resolver": attributes["resolver"],
        }
        add_ip_lookup(temp, temp["ip"])
        d.append(temp)
    df = pd.DataFrame(d)
    return df.to_dict()


def _format_siblings_entries(data: dict) -> Json:
    """Formats a url entry into a data row"""
    d = []
    for entry in data:
        attributes = entry["attributes"] 
        temp =  {
            "registrar": attributes["registrar"],
            "last_modification_date": pd.Timestamp(attributes["last_modification_date"], unit='s').floor('D'),
            "last_update_date": pd.Timestamp(attributes["last_update_date"], unit='s').floor('D'),
            "malicious": attributes["last_analysis_stats"]["malicious"],
            "whois": attributes["whois"]
        }
        
        
        try:
            temp["tags"] = attributes["tags"]
        except KeyError:
            temp["tags"] = ""
        
        categories = []
        for key in attributes["categories"].keys():
            categories.append(attributes["categories"][key])
        temp["categories"] = categories
        d.append(temp)
    df = pd.DataFrame(d)
    return df.to_dict()

def try_update(json_input, data, dest_key, k1, k2):
    try:
        json_input[dest_key] = data[k1][k2]
    except (KeyError, TypeError) as e:
        json_input[dest_key] = "N/A"

def _format_historical_whois(data: dict) -> Json:
    if not data:
        return {}
    d = []
    for entry in data:
        attributes = entry["attributes"]
        temp = {
            "registrar": "N/A",
            "Creation Date": datetime.strptime("1970-01-01", "%Y-%m-%d"),
            "Email": "-",
            "City": "-",
            "Country": "-",
            "org.": "-",
            "Expiry Date": "-",
            "Name Server": "-",
            "first_seen_date":  datetime.timestamp(datetime.strptime("1970-01-01", "%Y-%m-%d")),
            "last_updated":  datetime.timestamp(datetime.strptime("1970-01-01", "%Y-%m-%d")),
        }
        
        try:
            temp["registrar"] = attributes["registrar_name"]
        except KeyError:
            pass
        try:
            temp["Creation Date"] = attributes["whois_map"]["Creation Date"],
        except (ValueError, KeyError):
            pass
        
        try:
            temp["first_seen_date"] = pd.Timestamp(attributes["first_seen_date"], unit='s').floor('D'),
        except (KeyError, ValueError):
            pass
        try:
            temp["last_updated"] = pd.Timestamp(attributes["last_updated"], unit='s').floor('D'),
        except (KeyError, ValueError):
            pass
        try_update(temp, attributes, "Email",  "whois_map", "Admin Email")
        try_update(temp, attributes, "City",  "whois_map", "Admin City")
        try_update(temp, attributes, "Country",  "whois_map", "Admin Country")
        try_update(temp, attributes, "org.",  "whois_map", "Admin Organization")
        try_update(temp, attributes, "Expiry Date",  "whois_map", "Expiry Date")
        try_update(temp, attributes, "Name Server",  "whois_map", "Name Server")
        d.append(temp)
    return pd.DataFrame(d).to_dict()

def format_endpoint(endpoint, data: dict) -> Json:
    formating_functions = {
    "urls": _format_url_entries,
    "communicating_files": _format_communicating_files_entries,
    "downloaded_files": _format_downloaded_files_entries,
    "historical_whois": _format_historical_whois,
    "resolutions": _format_resolutions_entries,
    "siblings": _format_siblings_entries,
    "domain": _format_domain
    }
    callback = formating_functions[endpoint]
    return callback(data)

