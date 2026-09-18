import httpx
import pytest

from backend.app import network_policy as np
from backend.app.models import AuditRequest
from backend.app.scanner import PassiveScanner


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


async def _no_sleep(_):
    return None


def _unsafe_client(**kwargs):
    transport = np.SafeAsyncHTTPTransport(
        network_backend=np.SafeAsyncNetworkBackend(resolver=lambda host, port: ("10.0.0.1",))
    )
    return httpx.AsyncClient(transport=transport, follow_redirects=False, timeout=12, headers=kwargs.get("headers"))


@pytest.mark.asyncio
async def test_egress_policy_error_becomes_transport_error_and_incomplete(monkeypatch):
    monkeypatch.setattr("backend.app.scanner.asyncio.sleep", _no_sleep)
    monkeypatch.setattr("backend.app.scanner.build_safe_async_client", _unsafe_client)

    result = await PassiveScanner().run(
        AuditRequest(target="https://shop.test", authorization_confirmed=True, delay_seconds=1)
    )

    assert result.scan_completeness == "INCOMPLETE"
    transport_issues = [issue for issue in result.scan_issues if issue.kind == "TRANSPORT_ERROR"]
    assert transport_issues and transport_issues[0].required is True
    assert result.http_observation.observed is False


@pytest.mark.asyncio
async def test_same_origin_unsafe_redirect_is_blocked_and_incomplete(monkeypatch):
    def handler(request: httpx.Request):
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/home"})
        raise np.EgressPolicyError("blocked destination")

    monkeypatch.setattr("backend.app.scanner.asyncio.sleep", _no_sleep)
    _install_mock_client(monkeypatch, handler)

    result = await PassiveScanner().run(
        AuditRequest(target="https://shop.test", authorization_confirmed=True, delay_seconds=1)
    )

    assert result.scan_completeness == "INCOMPLETE"
    assert any(issue.kind == "TRANSPORT_ERROR" for issue in result.scan_issues)
    assert all(issue.kind != "REDIRECT_LOOP" for issue in result.scan_issues)


def test_public_constructor_rejects_transport_bypass():
    with pytest.raises(TypeError):
        PassiveScanner(httpx.MockTransport(lambda request: httpx.Response(200)))
