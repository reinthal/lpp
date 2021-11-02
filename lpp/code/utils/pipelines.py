import re

VALID_ALERTS_REGEX = "( ** valid regex ** )).*"

def incidents_to_tickets_pipeline(output_collection):
    """outputs relevant incidents from SNOW collection to internal tickets collection"""
    return [
    {
        '$match': {
            'u_json.related_alerts.alert_name': re.compile(r".*{}".format(VALID_ALERTS_REGEX))
        }
    }, {
        '$project': {
            'number': 1, 
            'u_json': 1, 
            'sys_created_on': 1
        }
    }, {
        '$addFields': {
            'date': {
                '$toDate': '$sys_created_on'
            }, 
            'id': '$number', 
            'shas': '$u_json.related_alerts.log_sha1',
            "severity": "$u_json.severity"
        }
    }, {
        '$project': {
            'date': 1, 
            'id': 1, 
            'shas': 1,
            "severity":1
        }
    }, {
        '$merge': {
            'into': output_collection, 
            'on': 'id', 
            'whenMatched': 'replace', 
            'whenNotMatched': 'insert'
        }
    }
]

def pipeline_join_tickets_aggregation_on_domains(output_collection):
    pipeline = [
            {
                "$lookup": {
                    "from": "tickets_aggregation",
                    "let": {"name": "$name"},
                    "pipeline": [
                        {"$match": {"$expr": {"$eq": ["$name","$$name"]}}}
                    ],
                    "as": "tickets"
                }
            },
            {
                "$out": output_collection
            }
    ]
    return pipeline


def pipeline_alerts(matching_stage, output_collection):
    pipeline_alerts = [
        {
            '$unwind': {
                'path': '$hosts_array'
            }
        }, {
            '$group': {
                '_id': '$hosts_array', 
                'alerts': {
                    '$addToSet': {
                        'sha': '$sha', 
                        'date': '$date', 
                        'name': '$name', 
                        'customer': '$customer'
                    }
                }
            }
        }, {
            '$project': {
                'name': '$_id', 
                'alerts': 1, 
                '_id': 0
            }
        }, {
            '$merge': {
                'into': output_collection, 
                'on': 'name', 
                'whenMatched': 'merge', 
                'whenNotMatched': 'insert'
            }
        }
    ]
    pipeline_alerts.insert(0, {"$match": matching_stage})
    return pipeline_alerts

def pipeline_tickets(matching_stage):
    pipeline_tickets = [
        {
            '$project': {
                'date': 1, 
                'shas': 1, 
                'id': 1, 
                'severity': 1
            }
        }, {
            '$unwind': {
                'path': '$shas'
            }
        }, {
            '$lookup': {
                'from': 'alerts', 
                'let': {
                    'sha': '$shas'
                }, 
                'pipeline': [
                    {
                        '$match': {
                            '$expr': {
                                '$eq': [
                                    '$sha', '$$sha'
                                ]
                            }
                        }
                    }, {
                        '$project': {
                            'sha': 1, 
                            '_time': 1, 
                            'name': 1, 
                            'hosts_array': 1
                        }
                    }
                ], 
                'as': 'alert'
            }
        }, {
            '$match': {
                'alert': {
                    '$ne': []
                }
            }
        }, {
            '$unwind': {
                'path': '$alert', 
                'preserveNullAndEmptyArrays': False
            }
        }, {
            '$unwind': {
                'path': '$alert.hosts_array'
            }
        }, {
            '$lookup': {
                'from': 'domains', 
                'let': {
                    'alert_name': '$alert.hosts_array'
                }, 
                'pipeline': [
                    {
                        '$match': {
                            '$expr': {
                                '$eq': [
                                    '$name', '$$alert_name'
                                ]
                            }
                        }
                    }, {
                        '$project': {
                            'name': 1
                        }
                    }
                ], 
                'as': 'domains'
            }
        }, {
            '$match': {
                'domains': {
                    '$ne': []
                }
            }
        }, {
            '$unwind': {
                'path': '$domains', 
                'preserveNullAndEmptyArrays': False
            }
        }, {
            '$group': {
                '_id': '$domains.name', 
                'tickets': {
                    '$addToSet': {
                        'id': '$id', 
                        'date': '$date', 
                        'severity': '$severity', 
                        'shas': '$shas'
                    }
                }
            }
        }, {
            '$project': {
                'name': '$_id', 
                'tickets': 1, 
                '_id': 0
            }
        }, {
            '$out': "tickets_aggregation"
        }
    ]
    pipeline_tickets.insert(0, {"$match": matching_stage})
    return pipeline_tickets



def pipeline_domains_dataframe(matching_stage, output_collection="domains_dataframe"):
    pipeline = [
    {
        "$project": {
            "alerts": 1.0,
            "real_alerts":1,
            "tickets": 1.0,
            "tld": 1.0,
            "subdomain": 1.0,
            "domain": 1.0,
            "name": 1.0,
            "ioc_first_date": 1,
            "vt.domain.data.attributes.creation_date": 1,
            "vt.domain.data.attributes.last_dns_records_date": 1,
            "vt.domain.data.attributes.last_https_certificate_date": 1,
            "vt.domain.data.attributes.last_modification_date": 1,
            "vt.domain.data.attributes.last_update_date": 1,
            "vt.domain.data.attributes.last_analysis_stats": 1,
            "vt.domain.data.attributes.popularity_ranks": 1,
            "vt.domain.data.attributes.categories": 1,
            "vt.domain.data.attributes.registrar": 1,
            "vt.domain.data.attributes.reputation": 1,
            "vt.communicating_files.data.attributes.creation_date": 1,
            "vt.communicating_files.data.attributes.first_submission_date": 1,
            "vt.communicating_files.data.attributes.last_analysis_date": 1,
            "vt.communicating_files.data.attributes.last_modification_date": 1,
            "vt.communicating_files.data.attributes.last_submission_date": 1,
            "vt.communicating_files.data.attributes.last_analysis_stats": 1,
            "vt.downloaded_files.data.attributes.creation_date": 1,
            "vt.downloaded_files.data.attributes.first_submission_date": 1,
            "vt.downloaded_files.data.attributes.last_analysis_date": 1,
            "vt.downloaded_files.data.attributes.last_modification_date": 1,
            "vt.downloaded_files.data.attributes.last_submission_date": 1,
            "vt.downloaded_files.data.attributes.last_analysis_stats": 1,
            "vt.downloaded_files.data.attributes.size": 1,
            "vt.downloaded_files.data.attributes.reputation": 1,
            "vt.downloaded_files.data.attributes.pe_info.entry_point": 1,
            "vt.referrer_files.data.attributes.creation_date": 1,
            "vt.referrer_files.data.attributes.first_submission_date": 1,
            "vt.referrer_files.data.attributes.last_analysis_date": 1,
            "vt.referrer_files.data.attributes.last_modification_date": 1,
            "vt.referrer_files.data.attributes.last_submission_date": 1,
            "vt.referrer_files.data.attributes.signature_info.copyright": 1,
            "vt.urls.data.attributes.creation_date": 1,
            "vt.urls.data.attributes.last_https_certificate_date": 1,
            "vt.urls.data.attributes.last_modification_date": 1,
            "vt.urls.data.attributes.last_update_date": 1,
            "vt.urls.data.attributes.last_analysis_stats": 1,
            "vt.urls.data.attributes.last_http_response_headers.content-type": 1,
            "vt.urls.data.attributes.reputation": 1,
            "vt.historical_whois.data.attributes.first_seen_date": 1,
            "vt.historical_whois.data.attributes.last_updated": 1,
            "vt.historical_whois.data.attributes.registrar_name": 1,
            "vt.historical_whois.data.attributes.whois_map.Creation Date": 1,
            "vt.resolutions.data.attributes.date": 1,
            "vt.siblings.data.attributes.last_analysis_stats": 1,
            "vt.subdomains.data.attributes.creation_date": 1,
            "vt.subdomains.data.attributes.last_dns_records_date": 1,
            "vt.subdomains.data.attributes.last_https_certificate_date": 1,
            "vt.subdomains.data.attributes.last_modification_date": 1,
            "vt.subdomains.data.attributes.last_update_date": 1,
            "vt.subdomains.data.attributes.last_analysis_stats": 1,
            "_id": 0.0
        }
    },
    {
        "$out": output_collection
    }
    ]
    pipeline.insert(0, {"$match": matching_stage})
    return pipeline
