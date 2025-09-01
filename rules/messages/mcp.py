from datetime import datetime
from typing import Literal
from pydantic import BaseModel, IPvAnyAddress


class ProductInfoMessage(BaseModel):
    name: str
    version: str
    flavor: Literal["Community", "Enterprise"]


class AlertMessage(BaseModel):
    when: datetime
    method: str | None
    signature_id: int
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    protocol: str
    category: str
    community_id: str


class HitTimelineEntryMessage(BaseModel):
    when: datetime
    hits: int


class RuleReferenceMessage(BaseModel):
    key: str
    value: str
    url: str


class RuleMessage(BaseModel):
    sid: int
    # category: str
    # category_description: str
    # category_source: str
    message: str
    hits: int = 0
    timeline_data: list[HitTimelineEntryMessage] = []  # TODO:
    probes: list[str] = []
    content: str
    references: list[RuleReferenceMessage] = []
