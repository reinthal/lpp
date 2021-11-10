import os, sys, re, requests, logging, asyncio

from aiohttp.client_exceptions import ContentTypeError

from datetime import datetime
from ratelimit import limits, sleep_and_retry
import copy

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)-8s:%(name)s:  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("l++ apis")

def clean_keys(data):
    """ remove forbidden characters from chars in keys of json """
    if isinstance(data, dict):
        for key, val in data.copy().items():
            new_key = re.sub(r"[\[\]\$,\.]", "_", key)
            if new_key != key:
                data[new_key] = clean_keys(val)
                del data[key]
            else:
                data[key] = clean_keys(val)
        return data
    elif isinstance(data, list):
        for item in data:
            clean_keys(item)
        return data
    else:
        return data

class DomainNotFoundException(Exception):
    def __init__(self, message, *args: object) -> None:
        self.message = message
        super().__init__(*args)

class IsIpException(Exception):
    def __init__(self, message, *args: object) -> None:
        self.message = message
        super().__init__(*args)
    

class InvalidDomainException(Exception):
    def __init__(self, message, *args: object) -> None:
        self.message = message
        super().__init__(*args)
    

class QuotaExceededException(Exception):
    def __init__(self, message, *args: object) -> None:
        self.message = message
        super().__init__(*args)
    

class OtherVtException(Exception):
    def __init__(self, message: str, *args: object) -> None:
        self.message = message
        super().__init__(*args)
    

def format_data(tuples):
    retval = {}
    for data, endpoint in tuples:
        if endpoint:
            retval[endpoint] = data
        else:
            retval["domain"] = data
    return retval

def is_ip(domain):
    regex2_ip = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    test_ip = re.fullmatch(regex2_ip, domain)

    if test_ip:
        return True
    else:
        return False

def is_valid_domainname(domain):
    """
        Checks for valid domain names.

        Valid domain names limited to containing at least one dot. 

        This does not cover all the cases but should work for what i'm trying to do.

    """
    regex_dom = r"(?=.*[.])[a-zA-Z0-9\.\_\-]+"
    test_dom = re.fullmatch(regex_dom, domain)

    if test_dom:
        return True
    else:
        return False


async def fetch(url, headers, params, session):
    """
    
    takes a url and an aiohttp.Clientsession and returns the json response.

    """
    async with session.get(url, headers=headers, params=params) as response:
        return await response.json()

class UninitializedAPIException(Exception):
    pass

class SnowApi(object):

    def __init__(self, date=None):
        self.logger = logging.getLogger("l++ snow api")
        self.user = os.getenv("SNOW_API_USER")
        self.passphrase =  os.getenv("SNOW_API_PASS")
        self.base_url = os.getenv("SNOW_API_URL")
        if not self.base_url or not self.passphrase or not self.user:
            raise UninitializedAPIException
        self.headers = {"Content-Type":"application/json","Accept":"application/json"}
        if date:
            try:
                datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
            except ValueError as e:
                self.logger.error("Incorrect date format to SnowAPI. Need `%Y-%m-%d %H:%M:%S`, got {}".format(date))
                raise e
            self.params_get_incidents_tde = {
                "sysparm_query": f"assignment_group=e64a33284f9fd3846d532e35f110c75f^contact_type=td_event^u_created_by_name=KARTE API^sys_created_on>{date}",
                "sysparm_limit": 50,
                "sysparm_offset": 0
            }
        else:
            self.params_get_incidents_tde = {
                "sysparm_query": "assignment_group=e64a33284f9fd3846d532e35f110c75f^contact_type=td_event^u_created_by_name=KARTE API",
                "sysparm_limit": 50,
                "sysparm_offset": 0
            }
    
    @sleep_and_retry
    @limits(calls=60, period=60)
    def make_api_call(self, table, params, offset):
        self.params_get_incidents_tde["sysparm_offset"] = offset
        self.logger.debug("requesting : {} with params {}".format(self.base_url.format(table), params))
        response = requests.get(self.base_url.format(table), 
            auth=(self.user, self.passphrase), 
            headers=self.headers, 
            params=params
        )

        if response.status_code == 200:
            return response.json(),response
        else:
            self.logger.warn("URL: {url}, \nStatus: {status}, \nheaders: {headers}, \nError Response: {response}".format(
                    url=response.url,
                    status=response.status_code,
                    headers=response.headers,
                    response=response.json()
                )
            )
            return {}, response
            
    def get_incident_chunk(self, offset=0, from_date=None):
        return self.make_api_call("incident", self.params_get_incidents_tde, offset)

class VtApi(object):

    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.header = {"x-apikey": self.api_key}
        self.querystring = {"limit": 25} # max number of entries to return
        self.endpoints = ["communicating_files", "downloaded_files", "historical_whois", "referrer_files", "resolutions", "siblings", "subdomains", "urls", "votes"]

    async def get(self, id, end_point, session):
        if end_point:
            url = "{}domains/{}/{}".format(self.base_url, id, end_point)
        else:
            url = "{}domains/{}".format(self.base_url, id)
        return await fetch(url, headers=self.header, params=self.querystring, session=session), end_point
    
    async def fetch_vt(self, fqdn, session):
        """fetches vt data. 
        
        Throws IsIpException, InvalidDomainException, QuotaExceededException, DomainNotFoundException and  OtherVtException
        
        """
        if is_ip(fqdn):
            logger.debug("domain name is ip `{}`".format(fqdn))
            raise IsIpException("domain is ip")

        if not is_valid_domainname(fqdn):
            raise InvalidDomainException(f"{fqdn} not a valid domain name")
        logger.info(f"running queries for `{fqdn}`.")
        
        # For each document, call vt api endpoints
        tasks = []
    
        task = asyncio.ensure_future(
            self.get(
                id=fqdn,
                end_point=None,
                session=session
            )
        )

        tasks.append(task)
        for endpoint in self.endpoints:
            task = asyncio.ensure_future(
                self.get(
                    id=fqdn, 
                    end_point=endpoint, 
                    session=session
                )
            )
            tasks.append(task)
        tuples = await asyncio.gather(*tasks)
        data = format_data(tuples)
        
        try:
            code = data["domain"]["error"]["code"]
            if code == "QuotaExceededError":
                raise QuotaExceededException(f"Quota reached when looking up `{fqdn}`")
            elif code == "NotFoundError":
                raise DomainNotFoundException(message=data["domain"]["error"]["message"])
            else:
                logger.error(data["domain"]["error"]["message"])
                raise OtherVtException(message=data["domain"]["error"]["message"])
        except KeyError:
            pass
            
        return data