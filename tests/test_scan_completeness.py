import httpx
import pytest

from backend.app.models import AuditRequest
from backend.app.policy import PolicyPack, evaluate_policy
from backend.app.scanner import PassiveScanner


POLICY = PolicyPack(
    policy_id="synthetic.completeness",
    title="Synthetic completeness control",
    fail_on_statuses=[],
    require_report_hash=False,
)


async def run_synthetic(handler, monkeypatch, max_requests=4):
    async def no_sleep(_delay):
        return None

    monkeypatch.setattr("backend.app.scanner.asyncio.sleep", no_sleep)
    requests = []

    def recording_handler(request: httpx.Request):
        requests.append(request)
        return handler(request)

    scanner = PassiveScanner(httpx.MockTransport(recording_handler))
    result = await scanner.run(
        AuditRequest(
            target="https://completeness.test",
            authorization_confirmed=True,
            max_requests=max_requests,
            delay_seconds=1,
        )
    )
    assert requests
    assert all(request.url.host == "completeness.test" for request in requests)
    assert all(request.method == "GET" for request in requests)
    return result


def assert_incomplete_unknown(result):
    assert evaluate_policy(result, POLICY).decision == "UNKNOWN"
    assert result.scan_completeness == "INCOMPLETE"
    assert result.scan_issues


@pytest.mark.asyncio
async def test_case_a_complete_success_remains_completed_and_policy_passes(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(200, text="ok", headers={"content-type": "text/html"}),
        monkeypatch,
        max_requests=2,
    )

    assert result.scan_completeness == "COMPLETED"
    assert result.scan_issues == []
    assert evaluate_policy(result, POLICY).decision == "PASS"


@pytest.mark.asyncio
async def test_case_b_root_404_is_incomplete_and_policy_unknown(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(404 if request.url.path == "/" else 200),
        monkeypatch,
        max_requests=2,
    )
    assert_incomplete_unknown(result)
    assert result.scan_issues[0].status_code == 404


@pytest.mark.asyncio
async def test_case_c_root_500_is_incomplete_and_policy_unknown(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(500 if request.url.path == "/" else 200),
        monkeypatch,
        max_requests=2,
    )
    assert_incomplete_unknown(result)
    assert result.scan_issues[0].status_code == 500


@pytest.mark.asyncio
async def test_case_d_missing_optional_robots_remains_completed(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(404 if request.url.path == "/robots.txt" else 200),
        monkeypatch,
        max_requests=2,
    )
    assert result.scan_completeness == "COMPLETED"
    assert result.scan_issues == []
    assert evaluate_policy(result, POLICY).decision == "PASS"


@pytest.mark.asyncio
async def test_case_e_asset_404_is_incomplete_and_policy_unknown(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text='<script src="/asset.js"></script>', headers={"content-type": "text/html"})
        return httpx.Response(404 if request.url.path == "/asset.js" else 200)

    result = await run_synthetic(handler, monkeypatch, max_requests=3)
    assert_incomplete_unknown(result)
    assert result.scan_issues[0].url.endswith("/asset.js")


@pytest.mark.asyncio
async def test_case_f_root_timeout_is_incomplete_and_policy_unknown(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        return httpx.Response(200)

    result = await run_synthetic(handler, monkeypatch, max_requests=2)
    assert_incomplete_unknown(result)
    assert result.scan_issues[0].kind == "TRANSPORT_ERROR"


@pytest.mark.asyncio
async def test_case_g_asset_timeout_is_incomplete_and_policy_unknown(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text='<link href="/asset.css">', headers={"content-type": "text/html"})
        if request.url.path == "/asset.css":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        return httpx.Response(200)

    result = await run_synthetic(handler, monkeypatch, max_requests=3)
    assert_incomplete_unknown(result)
    assert result.scan_issues[0].url.endswith("/asset.css")


@pytest.mark.asyncio
async def test_case_h_same_origin_redirect_to_503_is_incomplete(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/maintenance"})
        if request.url.path == "/maintenance":
            return httpx.Response(503)
        return httpx.Response(200)

    result = await run_synthetic(handler, monkeypatch, max_requests=3)
    assert_incomplete_unknown(result)
    assert result.scan_issues[0].status_code == 503


@pytest.mark.asyncio
async def test_case_i_redirect_without_location_is_incomplete(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(302 if request.url.path == "/" else 200),
        monkeypatch,
        max_requests=2,
    )
    assert_incomplete_unknown(result)
    assert result.scan_issues[0].kind == "HTTP_STATUS"


@pytest.mark.asyncio
async def test_case_j_mixed_success_and_failure_never_passes(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/good.js"></script><script src="/bad.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/bad.js":
            return httpx.Response(500)
        return httpx.Response(200, text="samplemodule", headers={"content-type": "application/javascript"})

    result = await run_synthetic(handler, monkeypatch, max_requests=4)
    assert_incomplete_unknown(result)
    assert result.request_count == 4
    assert any(issue.url.endswith("/bad.js") for issue in result.scan_issues)
