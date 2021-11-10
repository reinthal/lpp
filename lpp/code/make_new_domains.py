import re

from utils.database import SetupDatabase
from utils.queries import VALID_ALERTS

from pymongo.errors import OperationFailure

pipeline = [
    {
        "$match": VALID_ALERTS
    },
    {
        '$unwind': {
            'path': '$hosts_array'
        }
    }, {
        '$group': {
            '_id': '$hosts_array',
            'alerts': {
                '$addToSet': {
                    'sha': "$sha",
                    'date': '$date', 
                }
            }
        }
    },
    {
        "$project": {
            "name": "$_id",
            "alerts": 1,
            "_id": 0
        }
    },
     {
            '$merge': {
                'into': "domains_no_filter", 
                'on': 'name', 
                'whenMatched': 'merge', 
                'whenNotMatched': 'insert'
            }
     }
]
regex = "First element: _id: \"(?P<dst>.*?)\""
new_alerts = "alerts_new2"
def main():
    setup = SetupDatabase()
    while True:
        try:
            res = setup.db[new_alerts].aggregate(pipeline, allowDiskUse=True)
            print("aggregation query successful.")
            return
        except OperationFailure as e:
            if e.code == 10334: # bsonobject too large
                print("found domain which contained too many alerts")
                msg = e.details["errmsg"]
                print(msg)
                dst  = re.findall(regex, msg)[0]
                setup.db[new_alerts].delete_many({"hosts_array": dst})
            elif e.code == 11000:
                print("duplicate key error for domain! Something has gone wrong.")
                raise e
            else:
                print("unhandled exception found. Crashing")
                raise e


if __name__ == "__main__":
    main()