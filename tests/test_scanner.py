import httpx
import pytest
from pydantic import ValidationError

from backend.app.models import AuditRequest
from backend.app.extractor_sdk import PluginSignal
from backend.app.scanner import AuditPolicyError, PassiveScanner, assert_allowed, normalized_origin


def _install_mock_client(monkeypatch, handler):
    def factory(*, timeout=12.0, headers=None):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            timeout=timeout,
            headers=headers,
        )

    monkeypatch.setattr("backend.app.scanner.build_safe_async_client", factory)
    return factory


def test_authorization_is_required():
    with pytest.raises(ValidationError):
        AuditRequest(target="https://shop.test", authorization_confirmed=False)


def test_non_allowed_domain_is_rejected():
    with pytest.raises(AuditPolicyError):
        assert_allowed("https://evil.test/a", normalized_origin("https://shop.test"))


@pytest.mark.asyncio
async def test_external_redirect_is_refused(monkeypatch):
    def handler(request: httpx.Request):
        return httpx.Response(302, headers={"location": "https://evil.test/a"})
    _install_mock_client(monkeypatch, handler)
    scanner = PassiveScanner()
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
    _install_mock_client(monkeypatch, handler)
    scanner = PassiveScanner()
    result = await scanner.run(AuditRequest(target="https://shop.test", authorization_confirmed=True, max_requests=4, delay_seconds=1))
    assert result.request_count <= 4
    assert scanner.methods and set(scanner.methods) == {"GET"}
    assert all(request.method == "GET" and request.content == b"" for request in requests)
    assert all("select" not in str(request.url).lower() for request in requests)
    assert "php" not in result.model_dump_json().lower()


@pytest.mark.asyncio
async def test_explicit_plugin_is_applied_without_additional_requests(monkeypatch):
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

    _install_mock_client(monkeypatch, handler)
    scanner = PassiveScanner(plugins=[Plugin()])
    result = await scanner.run(AuditRequest(target="https://shop.test",authorization_confirmed=True,max_requests=1))

    assert len(requests) == 1
    assert result.findings[0].subject == "samplemodule"
    assert result.findings[0].evidence[0].detection_method == "plugin:community.sample-module:marker"


import hashlib
import json
from pathlib import Path

from backend.app.models import AuditResult, HttpMetadataObservation, SECURITY_HEADERS


def demo_audit_result() -> AuditResult:
    fixture = Path(__file__).parents[1] / "backend" / "fixtures" / "demo-audit.json"
    return AuditResult.model_validate(json.loads(fixture.read_text(encoding="utf-8")))


async def run_scanner(monkeypatch, handler, *, target="https://shop.test", max_requests=5, public_pages=()):
    async def no_sleep(_):
        return None

    monkeypatch.setattr("backend.app.scanner.asyncio.sleep", no_sleep)
    _install_mock_client(monkeypatch, handler)
    scanner = PassiveScanner()
    return await scanner.run(
        AuditRequest(
            target=target,
            authorization_confirmed=True,
            max_requests=max_requests,
            delay_seconds=1,
            public_pages=list(public_pages),
        )
    )


@pytest.mark.asyncio
async def test_direct_root_creates_observed_http_metadata(monkeypatch):
    def handler(_request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/html", "x-frame-options": "DENY"})

    result = await run_scanner(monkeypatch, handler)

    observation = result.http_observation
    assert observation is not None
    assert observation.observed is True
    assert observation.url.startswith("https://shop.test/")
    assert len(observation.headers_sha256) == 64
    assert len(observation.cookies_sha256) == 64
    assert "x-frame-options" not in observation.absent_headers
    assert "content-security-policy" in observation.absent_headers


@pytest.mark.asyncio
async def test_literal_absent_header_value_is_present(monkeypatch):
    def handler(_request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/html", "content-security-policy": "Absent"})

    result = await run_scanner(monkeypatch, handler)

    assert "content-security-policy" not in result.http_observation.absent_headers
    assert not any(finding.subject == "content-security-policy" for finding in result.findings)


@pytest.mark.asyncio
async def test_genuinely_missing_required_header_produces_finding_and_binding(monkeypatch):
    def handler(_request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    result = await run_scanner(monkeypatch, handler)

    assert "content-security-policy" in result.http_observation.absent_headers
    finding = next(finding for finding in result.findings if finding.subject == "content-security-policy")
    evidence = finding.evidence[0]
    assert evidence.observation_sha256 == result.http_observation.headers_sha256
    assert evidence.response_sha256 == hashlib.sha256(b"ok").hexdigest()
    assert evidence.url == result.http_observation.url


@pytest.mark.asyncio
async def test_header_projection_digest_is_deterministic_and_changes(monkeypatch):
    def handler_one(_request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/html", "x-frame-options": "DENY"})

    def handler_two(_request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/html", "x-frame-options": "SAMEORIGIN"})

    first = await run_scanner(monkeypatch, handler_one)
    second = await run_scanner(monkeypatch, handler_one)
    changed = await run_scanner(monkeypatch, handler_two)

    assert first.http_observation.headers_sha256 == second.http_observation.headers_sha256
    assert first.http_observation.headers_sha256 != changed.http_observation.headers_sha256


@pytest.mark.asyncio
async def test_same_origin_root_redirect_captures_terminal_response(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/home"})
        return httpx.Response(
            200,
            text="terminal-body",
            headers={"content-type": "text/html", "x-frame-options": "DENY", "set-cookie": "session=SUPER_SECRET_COOKIE_VALUE; Secure; HttpOnly; SameSite=Lax"},
        )

    result = await run_scanner(monkeypatch, handler)
    observation = result.http_observation

    assert observation.observed is True
    assert observation.url.endswith("/home")
    assert result.headers.get("x-frame-options") == "DENY"
    assert result.cookies and result.cookies[0]["name"] == "session"
    finding = next(finding for finding in result.findings if finding.subject == "content-security-policy")
    assert finding.evidence[0].response_sha256 == hashlib.sha256(b"terminal-body").hexdigest()


@pytest.mark.asyncio
async def test_failed_root_is_not_observed(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("synthetic failure", request=request)

    result = await run_scanner(monkeypatch, handler)
    observation = result.http_observation

    assert observation is not None
    assert observation.observed is False
    assert observation.absent_headers == []
    assert observation.headers_sha256 is None
    assert observation.cookies_sha256 is None
    assert not any(finding.evidence and finding.evidence[0].evidence_type == "http_header" for finding in result.findings)
    assert result.scan_completeness == "INCOMPLETE"


@pytest.mark.asyncio
async def test_no_cookies_is_observed_empty_not_unobserved(monkeypatch):
    def handler(_request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    result = await run_scanner(monkeypatch, handler)

    assert result.http_observation.observed is True
    assert result.cookies == []
    assert len(result.http_observation.cookies_sha256) == 64
    assert result.http_observation.cookies_sha256 == hashlib.sha256(b"[]").hexdigest()
    assert result.http_observation.cookies_sha256 != result.http_observation.headers_sha256


@pytest.mark.asyncio
async def test_raw_cookie_value_is_never_persisted(monkeypatch):
    def handler(_request):
        return httpx.Response(
            200,
            text="ok",
            headers={"content-type": "text/html", "set-cookie": "session=SUPER_SECRET_COOKIE_VALUE; Secure; HttpOnly; SameSite=Lax"},
        )

    result = await run_scanner(monkeypatch, handler)
    serialized = result.model_dump_json()

    assert "SUPER_SECRET_COOKIE_VALUE" not in serialized
    assert result.cookies[0]["name"] == "session"
    assert "value" not in result.cookies[0]


@pytest.mark.asyncio
async def test_multiple_set_cookie_headers_remain_ordered_and_distinct(monkeypatch):
    def handler(_request):
        return httpx.Response(
            200,
            text="ok",
            headers=[("content-type", "text/html"), ("set-cookie", "alpha=ALPHA_RAW_VALUE; Secure"), ("set-cookie", "beta=BETA_RAW_VALUE; HttpOnly")],
        )

    result = await run_scanner(monkeypatch, handler)
    serialized = result.model_dump_json()

    assert [cookie["name"] for cookie in result.cookies] == ["alpha", "beta"]
    assert all("value" not in cookie for cookie in result.cookies)
    assert "ALPHA_RAW_VALUE" not in serialized
    assert "BETA_RAW_VALUE" not in serialized


def test_legacy_audit_without_observation_deserializes_with_none():
    result = demo_audit_result()

    assert result.http_observation is None
    assert all(
        evidence.observation_sha256 is None
        for finding in result.findings
        for evidence in finding.evidence
    )


def test_http_metadata_observation_rejects_contradictory_states():
    from datetime import datetime, timezone

    now = datetime(2000, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValidationError):
        HttpMetadataObservation(url="https://shop.test/", captured_at=now, observed=False, headers_sha256="a" * 64)
    with pytest.raises(ValidationError):
        HttpMetadataObservation(url="https://shop.test/", captured_at=now, observed=False, absent_headers=["content-security-policy"])
    with pytest.raises(ValidationError):
        HttpMetadataObservation(url="https://shop.test/", captured_at=now, observed=True)
    with pytest.raises(ValidationError):
        HttpMetadataObservation(url="https://shop.test/", captured_at=now, observed=True, headers_sha256="a" * 64, cookies_sha256="b" * 64, absent_headers=["not-a-tracked-header"])
