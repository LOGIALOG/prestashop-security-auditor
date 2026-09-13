import httpx
import pytest

from backend.app.extractor_sdk import PluginSignal
from backend.app.models import AuditRequest
from backend.app.policy import PolicyPack, evaluate_policy
from backend.app.scanner import PassiveScanner


POLICY = PolicyPack(
    policy_id="synthetic.completeness",
    title="Synthetic completeness control",
    fail_on_statuses=[],
    require_report_hash=False,
)


async def run_synthetic(
    handler,
    monkeypatch,
    *,
    max_requests=4,
    public_pages=(),
    plugins=(),
):
    async def no_sleep(_delay):
        return None

    monkeypatch.setattr("backend.app.scanner.asyncio.sleep", no_sleep)
    requests = []

    def recording_handler(request: httpx.Request):
        requests.append(request)
        return handler(request)

    scanner = PassiveScanner(httpx.MockTransport(recording_handler), plugins=plugins)
    result = await scanner.run(
        AuditRequest(
            target="https://completeness.test",
            authorization_confirmed=True,
            public_pages=list(public_pages),
            max_requests=max_requests,
            delay_seconds=1,
        )
    )
    assert requests
    assert all(request.url.host == "completeness.test" for request in requests)
    assert all(request.method == "GET" for request in requests)
    return result


def assert_incomplete_unknown(result):
    assert result.scan_completeness == "INCOMPLETE"
    assert result.scan_issues
    assert evaluate_policy(result, POLICY).decision == "UNKNOWN"


@pytest.mark.asyncio
async def test_original_case_a_complete_success_allows_policy_pass(monkeypatch):
    result = await run_synthetic(
        lambda _request: httpx.Response(200, text="ok", headers={"content-type": "text/html"}),
        monkeypatch,
        max_requests=2,
    )

    assert result.scan_completeness == "COMPLETED"
    assert result.scan_issues == []
    assert evaluate_policy(result, POLICY).decision == "PASS"


@pytest.mark.asyncio
async def test_original_case_b_root_404_is_incomplete_and_never_passes(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(404 if request.url.path == "/" else 200),
        monkeypatch,
        max_requests=2,
    )

    assert_incomplete_unknown(result)
    assert result.scan_issues[0].status_code == 404


@pytest.mark.asyncio
async def test_original_case_c_root_500_is_incomplete_and_never_passes(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(500 if request.url.path == "/" else 200),
        monkeypatch,
        max_requests=2,
    )

    assert_incomplete_unknown(result)
    assert result.scan_issues[0].status_code == 500


@pytest.mark.asyncio
async def test_original_case_d_root_timeout_is_incomplete_and_never_passes(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        return httpx.Response(200)

    result = await run_synthetic(handler, monkeypatch, max_requests=2)

    assert_incomplete_unknown(result)
    assert result.scan_issues[0].kind == "TRANSPORT_ERROR"


@pytest.mark.asyncio
async def test_original_case_e_connection_refusal_is_structured_and_never_passes(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("synthetic connection refused", request=request)

    result = await run_synthetic(handler, monkeypatch, max_requests=2)

    assert_incomplete_unknown(result)
    assert all(issue.kind == "TRANSPORT_ERROR" for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_transport_dns_failure_is_injected_and_never_passes(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("synthetic name resolution failure", request=request)

    result = await run_synthetic(handler, monkeypatch, max_requests=2)

    assert_incomplete_unknown(result)
    assert all(issue.kind == "TRANSPORT_ERROR" for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_original_case_f_required_asset_http_failure_is_incomplete(monkeypatch):
    def handler(request):
        if request.url.path == "/required.js":
            return httpx.Response(503)
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=3,
        public_pages=["https://completeness.test/required.js"],
    )

    assert_incomplete_unknown(result)
    assert any(issue.url.endswith("/required.js") for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_original_case_g_optional_asset_failure_does_not_overharden(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/optional.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/optional.js":
            return httpx.Response(404)
        return httpx.Response(200)

    result = await run_synthetic(handler, monkeypatch, max_requests=3)

    assert result.scan_completeness == "COMPLETED"
    assert evaluate_policy(result, POLICY).decision == "PASS"
    assert any(issue.url.endswith("/optional.js") and not issue.required for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_original_case_h_required_extractor_failure_is_explicit_and_never_passes(monkeypatch):
    class FailingPlugin:
        plugin_id = "synthetic.required-extractor"
        api_version = "1.0"

        def extract(self, _context):
            raise RuntimeError("synthetic extractor failure")

    result = await run_synthetic(
        lambda _request: httpx.Response(200, text="ok", headers={"content-type": "text/html"}),
        monkeypatch,
        max_requests=2,
        plugins=[FailingPlugin()],
    )

    assert_incomplete_unknown(result)
    assert any(issue.kind == "EXTRACTOR_ERROR" and issue.required for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_original_case_i_budget_exhaustion_before_required_coverage_is_incomplete(monkeypatch):
    result = await run_synthetic(
        lambda _request: httpx.Response(200, text="ok", headers={"content-type": "text/html"}),
        monkeypatch,
        max_requests=1,
        public_pages=["https://completeness.test/required-page"],
    )

    assert_incomplete_unknown(result)
    assert any(issue.kind == "BUDGET_EXHAUSTED" and issue.required for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_original_case_j_unsupported_plugin_is_not_tested_and_never_passes(monkeypatch):
    class UnsupportedPlugin:
        plugin_id = "synthetic.unsupported-plugin"
        api_version = "999.0"

        def extract(self, _context):
            return [
                PluginSignal(
                    kind="theme",
                    name="synthetic-theme",
                    method="synthetic-marker",
                    start=0,
                    end=1,
                )
            ]

    result = await run_synthetic(
        lambda _request: httpx.Response(200, text="x", headers={"content-type": "text/html"}),
        monkeypatch,
        max_requests=2,
        plugins=[UnsupportedPlugin()],
    )

    assert_incomplete_unknown(result)
    assert any(issue.kind == "CHECK_NOT_TESTED" and issue.required for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_redirect_to_503_retains_structured_failure_and_never_passes(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/maintenance"})
        if request.url.path == "/maintenance":
            return httpx.Response(503)
        return httpx.Response(200)

    result = await run_synthetic(handler, monkeypatch, max_requests=3)

    assert_incomplete_unknown(result)
    assert any(issue.kind == "HTTP_STATUS" and issue.status_code == 503 for issue in result.scan_issues)
    assert any(url.endswith("/maintenance") for url in result.scope)


@pytest.mark.asyncio
async def test_redirect_without_location_is_structured_and_never_passes(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(302 if request.url.path == "/" else 200),
        monkeypatch,
        max_requests=2,
    )

    assert_incomplete_unknown(result)
    assert any(issue.kind == "HTTP_STATUS" and issue.status_code == 302 for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_redirect_chain_respects_budget_and_never_passes(monkeypatch):
    def handler(request):
        destinations = {"/": "/step-one", "/step-one": "/step-two"}
        if request.url.path in destinations:
            return httpx.Response(302, headers={"location": destinations[request.url.path]})
        return httpx.Response(200)

    result = await run_synthetic(handler, monkeypatch, max_requests=2)

    assert result.request_count == 2
    assert_incomplete_unknown(result)
    assert any(issue.kind == "BUDGET_EXHAUSTED" and issue.required for issue in result.scan_issues)
