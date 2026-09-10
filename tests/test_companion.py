import hashlib
import hmac
import json

import httpx
import pytest
from pydantic import ValidationError

from backend.app.companion import CompanionInventory,fetch_companion_inventory


@pytest.mark.asyncio
async def test_companion_fetch_uses_timestamped_hmac_get_and_validates_response():
    secret="s"*64
    def handler(request:httpx.Request):
        timestamp=request.headers["X-Logialog-Timestamp"]
        expected=hmac.new(secret.encode(),f"GET\n/module/logialogsecuritybridge/inventory\n{timestamp}".encode(),hashlib.sha256).hexdigest()
        assert request.method=="GET"
        assert request.headers["X-Logialog-Signature"]==expected
        payload={"schema_version":"1.0","generated_at":"2026-09-08T00:00:00Z","prestashop_version":"8.2.8","modules":[{"name":"ps_emailsubscription","version":"2.7.0","active":True}],"shops":[{"id":1,"name":"Main","url":"https://shop.test/","active":True}]}
        return httpx.Response(200,json=payload)
    inventory=await fetch_companion_inventory("https://shop.test/module/logialogsecuritybridge/inventory",secret,True,httpx.MockTransport(handler),now=1000)
    assert inventory.prestashop_version=="8.2.8"
    assert inventory.modules[0].name=="ps_emailsubscription"


@pytest.mark.asyncio
async def test_companion_requires_authorization_https_and_strong_secret():
    with pytest.raises(ValueError,match="autorisation"):
        await fetch_companion_inventory("https://shop.test/inventory","s"*64,False)
    with pytest.raises(ValueError,match="HTTPS"):
        await fetch_companion_inventory("http://shop.test/inventory","s"*64,True)
    with pytest.raises(ValueError,match="trop court"):
        await fetch_companion_inventory("https://shop.test/inventory","short",True)


@pytest.mark.asyncio
async def test_companion_refuses_redirects():
    transport=httpx.MockTransport(lambda request:httpx.Response(302,headers={"location":"https://other.test/"}))
    with pytest.raises(ValueError,match="redirections"):
        await fetch_companion_inventory("https://shop.test/inventory","s"*64,True,transport,now=1000)


def test_companion_schema_rejects_unknown_or_sensitive_fields():
    payload={"schema_version":"1.0","generated_at":"2026-09-08T00:00:00Z","prestashop_version":"8.2.8","modules":[],"shops":[],"database_password":"secret"}
    with pytest.raises(ValidationError):
        CompanionInventory.model_validate(payload)
