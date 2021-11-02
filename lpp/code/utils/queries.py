import pprint
API_ENDPOINTS = [
    "communicating_files",
    "downloaded_files",
    "historical_whois",
    "referrer_files",
    "resolutions",
    "siblings",
    "subdomains",
    "urls"
]

HAS_TICKET = {
    "tickets.tickets.id": {"$exists": True}
}

TICKETS_ARRAY_DOESNT_EXIST = {
    "tickets": {"$exists": False},
}

VALID_TICKETS = {
    "date": {"$exists": True},
    "date": {"$type": "date"},
    "shas": {"$exists": True},
    "shas": {"$type": "array"},
    "id": {"$exists": True},
    "id": {"$type": "string"},
    "severity": {"$exists": True},
    "severity": {"$type": "string"},
}

VALID_ALERTS = {
    "timestamp": {"$exists": True},
    "$or": [{"timestamp": {"$type": "string"}}, {"timestamp": {"$type": "double"}}],
    "name": {"$exists": True},
    "name": {"$type": "string"},
    "sha": {"$exists": True},
    "sha": {"$type": "string"},
    "date": {"$exists": True},
    "date": {"$type": "date"}
}



def has_domain_enrichment(switch=False):
    if switch:
        return {
            "domain": {"$exists": True},
            "subdomain": {"$exists": True},
            "tld": {"$exists": True}
        }
    else:
        return {
            "$or": [
                {"domain": {"$exists": False}},
                {"subdomain": {"$exists": False}},
                {"tld": {"$exists": False}}
            ]
        }

def has_domain_errors(switch=False):
    errors = [{"vt.{}.error".format(endpoint): {"$exists": switch}} for endpoint in API_ENDPOINTS]
    errors.append({"error.code": {"$exists": switch}})
    errors.append({"tickets": {"$exists": not switch}})
    errors.append({"alerts": {"$exists": not switch}})
    errors.append({"vt": {"$exists": not switch}})
    errors.append({"name": {"$exists": not switch}})
    errors.append({"tld": {"$exists": not switch}})
    errors.append({"domain": {"$exists": not switch}})

    if switch:
        return {"$or": errors} 
    else:
        return {"$and": errors}

NO_ERROR_AND_NO_VT_OR_QUOTA_ERROR = {
    "$or": [
        {"vt.domain.error.code": "QuotaExceededError"},
        { "vt": {"$exists": False}}  # if no queries have been made for vt
    ],
    "error.type": {"$exists": False}
}

HAS_NO_ALERT_ENRICHMENT = {
    "hosts_array": {"$exists": False}
}

def date_fields_exists_and_is_date(switch=True):
    if switch:
        return {
            "$and": [{"date": {"$exists": True}}, {"date": {"$type": "date"}}]
        }  
    else:
        return {
        "$or": [{"date": {"$exists": False}},{"date": {"$not": {"$type": "date"}}}]
        }

if __name__ == "__main__":
    query = has_domain_errors()
    pprint.pprint(query)