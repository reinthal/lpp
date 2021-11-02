import logging
import tldextract
import numpy as np

from datetime import datetime
from pydantic import BaseModel
from typing import Any, Optional 
from ipaddress import IPv4Address

log = logging.getLogger("uvicorn")

class AckData(BaseModel):
    level: int
    origin: str
    ts: int
    date: Optional[datetime] = None
    user: str
    ref: str

class Acknowledgement(BaseModel):
    sha: str
    data: AckData

class Alert(BaseModel):
    sha: str
    dst_ip: Optional[str] = None
    dst: str
    timestamp: Any
    date: Optional[datetime] = None
    name: str
    customer: str

class Task(BaseModel):
    """ Celery task representation """
    task_id: str
    status: str


class Prediction(BaseModel):
    """ Prediction task result """
    task_id: str
    status: str
    verdict: str
    name: str
    log_odds: float
    threshold: float
    x_domain: dict
    shap_values: list