import httpx
import pytest
from pydantic import ValidationError

from backend.app.models import AuditRequest
from backend.app.extractor_sdk import PluginSignal
from backend.app.scanner import AuditPolicyError, PassiveScanner, assert_allowed, normalized_origin


def test_authorization_is_required():
    with pytest.raises(ValidationError):
        AuditRequest(target="https://shop.test", authorization_confirmed=False)


def test_non_allowed_domain_is_rejected():
    with pytest.raises(AuditPolicyError):
        assert_allowed("https://evil.test/a", normalized_origin("https://shop.test"))


@pytest.mark.asyncio
async def test_external_redirect_is_refused():
    def handler(request: httpx.Request):
        return httpx.Response(302, headers={"location": "https://evil.test/a"})
    scanner = PassiveScanner(httpx.MockTransport(handler))
    request = AuditRequest(target="https://shop.test", authorization_confirmed=True, delay_seconds=1)
    with pytest.raises(AuditPolicyError):
        await scanner.run(request)


@pytest.mark.asyncio
async def test_request_limit_and_get_only(monkeypatch):
    async def no_sleep(_): pass
    monkeypatch.setattr("backend.app.scanner.asyncio.sleep", no_sleep)
    body = ''.join(f'<script src="/asset{i}.js"></script>' for i in range(30))
    requests = []
    def handler(request: httpx.Request):
        requests.append(request)
        return httpx.Response(200, text=body if request.url.path == '/' else '', headers={"content-type":"text/html" if request.url.path == '/' else "application/javascript"})
    scanner = PassiveScanner(httpx.MockTransport(handler))
    result = await scanner.run(AuditRequest(target="https://shop.test", authorization_confirmed=True, max_requests=4, delay_seconds=1))
    assert result.request_count <= 4
    assert scanner.methods and set(scanner.methods) == {"GET"}
    assert all(request.method == "GET" and request.content == b"" for request in requests)
    assert all("select" not in str(request.url).lower() for request in requests)
    assert "php" not in result.model_dump_json().lower()


@pytest.mark.asyncio
async def test_explicit_plugin_is_applied_without_additional_requests():
    class Plugin:
        plugin_id = "community.sample-module"
        api_version = "1.0"

        def extract(self, context):
            start = context.body.find("samplemodule")
            return [] if start < 0 else [PluginSignal(kind="active_module",name="samplemodule",confidence="medium",method="marker",start=start,end=start+12)]

    requests = []
    def handler(request: httpx.Request):
        requests.append(request)
        return httpx.Response(200,text="samplemodule",headers={"content-type":"text/html"})

    scanner = PassiveScanner(httpx.MockTransport(handler),plugins=[Plugin()])
    result = await scanner.run(AuditRequest(target="https://shop.test",authorization_confirmed=True,max_requests=1))

    assert len(requests) == 1
    assert result.findings[0].subject == "samplemodule"
    assert result.findings[0].evidence[0].detection_method == "plugin:community.sample-module:marker"
