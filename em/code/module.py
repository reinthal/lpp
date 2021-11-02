
import requests
import re, os

custom_header = {"Content-Type": "application/json", "accept": "application/json"}
blacklist_signatures = ".*(blacklisted domain|blacklisted hostname|threatlist hostname|known C2 hostname|known Malware hostname|Typosquat domain|malicious executable download|outbound requests \(vendor malicious category, sparse single host\)).*"
regex = re.compile(blacklist_signatures)

from isaac.chassis.embase import BaseModule, Skeleton

api_url = os.getenv("API_URL")

def format_ack(item):
    data = item["data"]
    return {
        "sha": item["sha"],
        "data": {
            "level": data["level"],
            "ts": data["ts"],
            "user": data["user"],
            "ref": data["ref"],
            "origin": data["__origin__"]
        }
    }

def format_alert(item):
    return {
        "sha": item["data"]["sha"],
        "dst_ip": item["data"]["dst_ip"],
        "dst": item["data"]["dst"],
        "timestamp": item["data"]["timestamp"],
        "name": item["data"]["name"],
        "customer": item["data"]["customer"]
    }
    

class EnrichmentModule(BaseModule):
    shortname = "l++"
    longname = "Lookerplusplus"
    conffile = "./module.conf"
    api_uri = ""

    def enrich(self, enrichment, item):

        if item.get('kind') == "acks":
            ack = format_ack(item)
            url = "{}/domains/".format(api_url)
            res = requests.put(url, json=ack)
            if res.ok:
                self.logger.info("matching ack inserted")    
            else:
                self.logger.debug("ack not found in db {}".format(ack["sha"]))
        elif item.get('kind') == "alert":
            alert = item.get("data", {})
            
            if re.search(blacklist_signatures, alert['name']):      
                
                self.logger.info("found match: {}".format(alert['name']))
                data = format_alert(item)
                url = "{api_url}/predict/".format(api_url=api_url)
                
                resp = requests.post(url, json=data)
                
                if resp.ok:
                    self.logger.info("OK reply from {}")
                    prediction = resp.json()
                    comment = "Verdict: {verdict}, score: {evilness}, threshold: {evil_threshold}".format(**prediction)
                    enrichment["ack"] = False
                    enrichment['comment'] = comment
                    enrichment["data"] = prediction
                else:
                    reason = resp.json()["detail"]
                    self.logger.warn("alert with dst {} could not be predicted. Reason: {}".format(alert["dst"], reason))
                
        else:
            return
                


def main():
    with Skeleton() as skel:
        EnrichmentModule(skel).run()

if __name__ == "__main__":
    main()
