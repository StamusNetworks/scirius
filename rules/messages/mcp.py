from datetime import datetime
from typing import Literal
from pydantic import BaseModel, IPvAnyAddress


class BaseInfo(BaseModel):
    first_seen: datetime
    last_seen: datetime


class ProductInfoMessage(BaseModel):
    name: str
    version: str
    flavor: Literal["Community", "Enterprise"]


class AlertMessage(BaseModel):
    timestamp: datetime
    method: str | None
    signature_id: int
    src_ip: IPvAnyAddress
    dest_ip: IPvAnyAddress
    protocol: str
    category: str
    community_id: str
    hostname: str | None = None


class HitTimelineEntryMessage(BaseModel):
    timestamp: datetime
    hits: int


class HitProbeMessage(BaseModel):
    name: str
    hits: int = 0


class RuleReferenceMessage(BaseModel):
    key: str
    value: str
    url: str


class RuleMessage(BaseModel):
    sid: int
    message: str
    hits: int = 0
    timeline_data: list[HitTimelineEntryMessage] = []  # TODO:
    probes: list[HitProbeMessage] = []
    content: str
    references: list[RuleReferenceMessage] = []


class TalkersInfoMessage(BaseInfo):
    event_type: str
    src_ip: IPvAnyAddress
    dest_ip: IPvAnyAddress
    app_proto: str
    host: str | None
    count: int
