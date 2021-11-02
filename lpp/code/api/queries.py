tickets_aggregation_projection = {
    "karte_id": "$ujson.reference_id", 
    "opened_at": 1, 
    "alerts": "$u_json.related_alerts", 
    "_id":0
}