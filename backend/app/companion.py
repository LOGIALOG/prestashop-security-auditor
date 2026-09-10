from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class CompanionModule(BaseModel):
    model_config=ConfigDict(extra="forbid")
    name:str=Field(min_length=1,max_length=80,pattern=r"^[a-zA-Z0-9_-]+$")
    version:str|None=Field(default=None,max_length=40)
    active:Literal[True]


class CompanionShop(BaseModel):
    model_config=ConfigDict(extra="forbid")
    id:int=Field(gt=0)
    name:str=Field(min_length=1,max_length=120)
    url:HttpUrl
    active:bool


class CompanionInventory(BaseModel):
    model_config=ConfigDict(extra="forbid")
    schema_version:Literal["1.0"]
    generated_at:datetime
    prestashop_version:str=Field(min_length=3,max_length=40)
    modules:list[CompanionModule]=Field(max_length=1000)
    shops:list[CompanionShop]=Field(max_length=100)


async def fetch_companion_inventory(endpoint:str,secret:str,authorized:bool,transport:httpx.AsyncBaseTransport|None=None,now:int|None=None)->CompanionInventory:
    if not authorized:
        raise ValueError("Une autorisation explicite est obligatoire")
    parts=urlsplit(endpoint)
    if parts.scheme!="https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("L’endpoint companion doit être une URL HTTPS exacte sans credentials, query ni fragment")
    if len(secret)<32:
        raise ValueError("Le secret HMAC est trop court")
    timestamp=str(now if now is not None else int(time.time()))
    path=parts.path or "/"
    signature=hmac.new(secret.encode("utf-8"),f"GET\n{path}\n{timestamp}".encode("utf-8"),hashlib.sha256).hexdigest()
    headers={"X-Logialog-Timestamp":timestamp,"X-Logialog-Signature":signature,"User-Agent":"LOGIALOG-Companion-Client/1.0"}
    async with httpx.AsyncClient(transport=transport,follow_redirects=False,timeout=10,headers=headers) as client:
        response=await client.get(endpoint)
    if 300<=response.status_code<400:
        raise ValueError("Les redirections companion sont refusées")
    response.raise_for_status()
    if len(response.content)>1_000_000:
        raise ValueError("La réponse companion dépasse 1 Mio")
    return CompanionInventory.model_validate_json(response.content)
