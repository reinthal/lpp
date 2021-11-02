import tldextract
from datetime import datetime

def format_data(vtdata, domain):
    extractor = tldextract.extract(domain)
    return {
        "vt": vtdata,
        "tickets": [],
        "name": domain,
        "domain": "{dom}.{tld}".format(dom=extractor.domain, tld=extractor.suffix),
        "subdomain": extractor.subdomain,
        "tld": extractor.suffix
    }

def create_mock_alert():
    return [{
            "sha": "62fd3f52f016106db393fcf7df58a4a919bf09290b6d4850ff8514716166caac",
            "date": datetime.now(),
            "name": "MOCK-D.PCK-1337: Mock alert blacklisted hostname",
            "customer": "1337"
        }]