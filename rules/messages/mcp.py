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
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    protocol: str
    category: str
    community_id: str
