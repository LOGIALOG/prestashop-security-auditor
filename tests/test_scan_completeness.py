import httpx
import pytest

from backend.app import scanner as scanner_module
from backend.app.extractor_sdk import PluginSignal
from backend.app.models import AuditRequest, ScanIssue
from backend.app.policy import PolicyPack, evaluate_policy
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

    scanner = PassiveScanner(plugins=plugins)
    _install_mock_client(monkeypatch, recording_handler)
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
async def test_required_self_redirect_is_incomplete_and_never_passes(monkeypatch):
    result = await run_synthetic(
        lambda request: httpx.Response(
            302,
            headers={"location": "/"},
        )
        if request.url.path == "/"
        else httpx.Response(404),
        monkeypatch,
        max_requests=3,
    )

    assert_incomplete_unknown(result)
    assert any(issue.kind == "REDIRECT_LOOP" and issue.required for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_required_two_node_redirect_loop_is_incomplete_and_never_passes(monkeypatch):
    def handler(request):
        destinations = {"/": "/loop", "/loop": "/"}
        if request.url.path in destinations:
            return httpx.Response(302, headers={"location": destinations[request.url.path]})
        return httpx.Response(404)

    result = await run_synthetic(handler, monkeypatch, max_requests=4)

    assert_incomplete_unknown(result)
    assert any(issue.kind == "REDIRECT_LOOP" and issue.required for issue in result.scan_issues)


@pytest.mark.asyncio
async def test_optional_redirect_loop_is_retained_without_overhardening(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/optional-loop.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/optional-loop.js":
            return httpx.Response(302, headers={"location": "/optional-loop.js"})
        return httpx.Response(404)

    result = await run_synthetic(handler, monkeypatch, max_requests=4)

    assert result.scan_completeness == "COMPLETED"
    assert any(issue.kind == "REDIRECT_LOOP" and not issue.required for issue in result.scan_issues)
    assert evaluate_policy(result, POLICY).decision == "PASS"


@pytest.mark.asyncio
async def test_converging_redirects_do_not_create_redirect_loop(monkeypatch):
    def handler(request):
        if request.url.path in {"/left", "/right"}:
            return httpx.Response(302, headers={"location": "/shared"})
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=6,
        public_pages=(
            "https://completeness.test/left",
            "https://completeness.test/right",
        ),
    )

    assert result.scan_completeness == "COMPLETED"
    assert not any(issue.kind == "REDIRECT_LOOP" for issue in result.scan_issues)
    assert evaluate_policy(result, POLICY).decision == "PASS"


@pytest.mark.asyncio
async def test_optional_http_failure_is_retried_and_retained_as_required_failure(monkeypatch):
    shared_requests = 0

    def handler(request):
        nonlocal shared_requests
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/shared.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/required":
            return httpx.Response(302, headers={"location": "/shared.js"})
        if request.url.path == "/shared.js":
            shared_requests += 1
            return httpx.Response(503)
        return httpx.Response(404)

    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=6,
        public_pages=("https://completeness.test/required",),
    )

    assert shared_requests == 2
    assert any(issue.kind == "HTTP_STATUS" and not issue.required for issue in result.scan_issues)
    assert any(issue.kind == "HTTP_STATUS" and issue.required for issue in result.scan_issues)
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_optional_http_failure_can_recover_under_required_context(monkeypatch):
    shared_requests = 0

    def handler(request):
        nonlocal shared_requests
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/shared.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/required":
            return httpx.Response(302, headers={"location": "/shared.js"})
        if request.url.path == "/shared.js":
            shared_requests += 1
            return httpx.Response(503 if shared_requests == 1 else 200)
        return httpx.Response(404)

    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=6,
        public_pages=("https://completeness.test/required",),
    )

    assert shared_requests == 2
    assert any(issue.kind == "HTTP_STATUS" and not issue.required for issue in result.scan_issues)
    assert not any(issue.required for issue in result.scan_issues)
    assert result.scan_completeness == "COMPLETED"
    assert evaluate_policy(result, POLICY).decision == "PASS"


@pytest.mark.asyncio
async def test_prior_optional_success_satisfies_required_convergence(monkeypatch):
    shared_requests = 0

    def handler(request):
        nonlocal shared_requests
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/shared.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/required":
            return httpx.Response(302, headers={"location": "/shared.js"})
        if request.url.path == "/shared.js":
            shared_requests += 1
            return httpx.Response(200)
        return httpx.Response(404)

    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=4,
        public_pages=("https://completeness.test/required",),
    )

    assert shared_requests == 1
    assert not any(issue.kind == "REDIRECT_LOOP" for issue in result.scan_issues)
    assert not any(issue.required for issue in result.scan_issues)
    assert result.scan_completeness == "COMPLETED"
    assert evaluate_policy(result, POLICY).decision == "PASS"


@pytest.mark.asyncio
async def test_optional_extractor_failure_is_retried_as_required(monkeypatch):
    shared_requests = 0
    original_extract_html = scanner_module.extract_html

    def handler(request):
        nonlocal shared_requests
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/shared.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/required":
            return httpx.Response(302, headers={"location": "/shared.js"})
        if request.url.path == "/shared.js":
            shared_requests += 1
            return httpx.Response(200, text="ok", headers={"content-type": "text/html"})
        return httpx.Response(404)

    def failing_extract_html(url, body, content_type):
        if url.endswith("/shared.js"):
            raise RuntimeError("synthetic extractor failure")
        return original_extract_html(url, body, content_type)

    monkeypatch.setattr("backend.app.scanner.extract_html", failing_extract_html)
    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=6,
        public_pages=("https://completeness.test/required",),
    )

    assert shared_requests == 2
    assert any(issue.kind == "EXTRACTOR_ERROR" and not issue.required for issue in result.scan_issues)
    assert any(issue.kind == "EXTRACTOR_ERROR" and issue.required for issue in result.scan_issues)
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_optional_transport_failure_is_retried_as_required(monkeypatch):
    shared_requests = 0

    def handler(request):
        nonlocal shared_requests
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/shared.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/required":
            return httpx.Response(302, headers={"location": "/shared.js"})
        if request.url.path == "/shared.js":
            shared_requests += 1
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        return httpx.Response(404)

    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=6,
        public_pages=("https://completeness.test/required",),
    )

    assert shared_requests == 2
    assert any(issue.kind == "TRANSPORT_ERROR" and not issue.required for issue in result.scan_issues)
    assert any(issue.kind == "TRANSPORT_ERROR" and issue.required for issue in result.scan_issues)
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_optional_http_failure_without_retry_budget_is_required_budget_exhaustion(monkeypatch):
    shared_requests = 0

    def handler(request):
        nonlocal shared_requests
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/shared.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/required":
            return httpx.Response(302, headers={"location": "/shared.js"})
        if request.url.path == "/shared.js":
            shared_requests += 1
            return httpx.Response(503)
        return httpx.Response(404)

    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=4,
        public_pages=("https://completeness.test/required",),
    )

    assert shared_requests == 1
    assert result.request_count == 4
    assert any(
        issue.kind == "HTTP_STATUS"
        and issue.status_code == 503
        and not issue.required
        for issue in result.scan_issues
    )
    assert any(
        issue.kind == "BUDGET_EXHAUSTED"
        and issue.required
        and issue.check_id == "http:public-page"
        and issue.url.endswith("/shared.js")
        for issue in result.scan_issues
    )
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_repeated_required_failure_is_deduplicated(monkeypatch):
    shared_requests = 0

    def handler(request):
        nonlocal shared_requests
        if request.url.path in {"/one", "/two"}:
            return httpx.Response(302, headers={"location": "/shared.js"})
        if request.url.path == "/shared.js":
            shared_requests += 1
            return httpx.Response(503)
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=10,
        public_pages=(
            "https://completeness.test/one",
            "https://completeness.test/two",
        ),
    )

    required_failures = [
        issue
        for issue in result.scan_issues
        if issue.kind == "HTTP_STATUS" and issue.status_code == 503 and issue.required
    ]
    assert shared_requests == 1
    assert result.request_count == 5
    assert len(required_failures) == 1
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_optional_extractor_failure_can_recover_under_required_context(monkeypatch):
    shared_requests = 0
    extractor_attempts = 0
    original_extract_html = scanner_module.extract_html

    def handler(request):
        nonlocal shared_requests
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/shared.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/required":
            return httpx.Response(302, headers={"location": "/shared.js"})
        if request.url.path == "/shared.js":
            shared_requests += 1
            return httpx.Response(200, text="ok", headers={"content-type": "text/html"})
        return httpx.Response(404)

    def recovering_extract_html(url, body, content_type):
        nonlocal extractor_attempts
        if url.endswith("/shared.js"):
            extractor_attempts += 1
            if extractor_attempts == 1:
                raise RuntimeError("synthetic optional extractor failure")
        return original_extract_html(url, body, content_type)

    monkeypatch.setattr("backend.app.scanner.extract_html", recovering_extract_html)
    result = await run_synthetic(
        handler,
        monkeypatch,
        max_requests=6,
        public_pages=("https://completeness.test/required",),
    )

    assert shared_requests == 2
    assert extractor_attempts == 2
    assert any(issue.kind == "EXTRACTOR_ERROR" and not issue.required for issue in result.scan_issues)
    assert not any(issue.required for issue in result.scan_issues)
    assert result.scan_completeness == "COMPLETED"
    assert evaluate_policy(result, POLICY).decision == "PASS"


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


def test_scan_issue_legacy_payload_defaults_optional_detail_fields():
    issue = ScanIssue(kind="TRANSPORT_ERROR", url="https://shop.test/", required=True)

    assert issue.detail is None
    assert issue.captured_at is None

    reloaded = ScanIssue.model_validate(
        {"kind": "TRANSPORT_ERROR", "url": "https://shop.test/", "required": True}
    )
    assert reloaded.detail is None
    assert reloaded.captured_at is None


@pytest.mark.asyncio
async def test_required_transport_error_captures_bounded_redacted_detail(monkeypatch):
    def handler(request):
        raise httpx.ConnectError(
            "synthetic refusal token=SUPERSECRET123 contact=ops@example.test",
            request=request,
        )

    result = await run_synthetic(handler, monkeypatch, max_requests=2)

    issue = next(issue for issue in result.scan_issues if issue.kind == "TRANSPORT_ERROR")
    assert issue.required is True
    assert issue.detail
    assert len(issue.detail) <= 200
    assert issue.captured_at is not None
    assert "SUPERSECRET123" not in issue.detail
    assert "ops@example.test" not in issue.detail
    assert_incomplete_unknown(result)


def test_redact_parameters_masks_sensitive_query_keys():
    from backend.app.redaction import redact_parameters

    text = (
        "session=SESSVAL&auth=AUTHVAL&password=PASSVAL&pass=PASS2VAL&pwd=PWDVAL"
        "&token=TOKVAL&secret=SECVAL&api_key=APIVAL&key=KEYVAL&email=ops@example.test"
    )

    redacted = redact_parameters(text)

    for secret in (
        "SESSVAL",
        "AUTHVAL",
        "PASSVAL",
        "PASS2VAL",
        "PWDVAL",
        "TOKVAL",
        "SECVAL",
        "APIVAL",
        "KEYVAL",
        "ops@example.test",
    ):
        assert secret not in redacted
    assert redacted.count("[MASQUÉ]") >= 10


def test_redact_parameters_masks_compound_and_alternate_keys():
    from backend.app.redaction import redact_parameters

    text = (
        "session_id=SESSIDVAL&sessionid=SESSIONID2VAL&secret_key=SECKEYVAL"
        "&private_key=PRIVKEYVAL&access_key=ACCKEYVAL&passwd=PASSWDVAL"
        "&csrf=CSRFVAL&jwt=JWTVAL"
    )

    redacted = redact_parameters(text)

    for secret in (
        "SESSIDVAL",
        "SESSIONID2VAL",
        "SECKEYVAL",
        "PRIVKEYVAL",
        "ACCKEYVAL",
        "PASSWDVAL",
        "CSRFVAL",
        "JWTVAL",
    ):
        assert secret not in redacted
    assert redacted.count("[MASQUÉ]") >= 8


@pytest.mark.asyncio
async def test_transport_error_detail_masks_compound_sensitive_keys(monkeypatch):
    def handler(request):
        raise httpx.ConnectError(
            "connection failed GET https://shop.test/?session_id=SESSIDVAL"
            "&sessionid=SESSIONID2VAL&secret_key=SECKEYVAL&private_key=PRIVKEYVAL"
            "&access_key=ACCKEYVAL&passwd=PASSWDVAL&csrf=CSRFVAL&jwt=JWTVAL",
            request=request,
        )

    result = await run_synthetic(handler, monkeypatch, max_requests=2)
    detail = next(issue for issue in result.scan_issues if issue.kind == "TRANSPORT_ERROR").detail

    assert detail
    assert len(detail) <= 200
    for secret in (
        "SESSIDVAL",
        "SESSIONID2VAL",
        "SECKEYVAL",
        "PRIVKEYVAL",
        "ACCKEYVAL",
        "PASSWDVAL",
        "CSRFVAL",
        "JWTVAL",
    ):
        assert secret not in detail
    assert "[MASQUÉ]" in detail
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_transport_error_detail_masks_sensitive_query_parameters(monkeypatch):
    def handler(request):
        raise httpx.ConnectError(
            "connection failed GET https://shop.test/?token=TOK456&secret=SEC123"
            "&api_key=API789&key=KEY000&password=PW789&pass=PW111&pwd=PW222"
            "&auth=AUTHTOK&session=SESSID123&sid=SID999"
            "&email=ops@example.test&phone=+212600000000",
            request=request,
        )

    result = await run_synthetic(handler, monkeypatch, max_requests=2)
    detail = next(issue for issue in result.scan_issues if issue.kind == "TRANSPORT_ERROR").detail

    assert detail
    assert len(detail) <= 200
    for secret in (
        "TOK456",
        "SEC123",
        "API789",
        "KEY000",
        "PW789",
        "PW111",
        "PW222",
        "AUTHTOK",
        "SESSID123",
        "SID999",
        "ops@example.test",
        "+212600000000",
    ):
        assert secret not in detail
    assert "[MASQUÉ]" in detail
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_optional_transport_error_records_detail_without_becoming_incomplete(monkeypatch):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<script src="/optional-transport.js"></script>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/optional-transport.js":
            raise httpx.ConnectError("synthetic optional transport failure", request=request)
        return httpx.Response(200)

    result = await run_synthetic(handler, monkeypatch, max_requests=3)

    issue = next(
        issue
        for issue in result.scan_issues
        if issue.kind == "TRANSPORT_ERROR" and not issue.required
    )
    assert issue.detail
    assert issue.captured_at is not None
    assert result.scan_completeness == "COMPLETED"
    assert evaluate_policy(result, POLICY).decision == "PASS"


@pytest.mark.asyncio
async def test_builtin_extractor_error_captures_detail(monkeypatch):
    def handler(_request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    def failing_extract_html(_url, _body, _content_type):
        raise RuntimeError("synthetic builtin extractor failure")

    monkeypatch.setattr("backend.app.scanner.extract_html", failing_extract_html)
    result = await run_synthetic(handler, monkeypatch, max_requests=2)

    issue = next(
        issue
        for issue in result.scan_issues
        if issue.kind == "EXTRACTOR_ERROR" and issue.check_id == "builtin:html-extractor"
    )
    assert issue.required is True
    assert issue.detail
    assert "RuntimeError" in issue.detail
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_plugin_extractor_error_captures_detail_and_check_id(monkeypatch):
    class FailingPlugin:
        plugin_id = "synthetic.detail-extractor"
        api_version = "1.0"

        def extract(self, _context):
            raise RuntimeError("synthetic plugin failure")

    result = await run_synthetic(
        lambda _request: httpx.Response(200, text="ok", headers={"content-type": "text/html"}),
        monkeypatch,
        max_requests=2,
        plugins=[FailingPlugin()],
    )

    issue = next(
        issue
        for issue in result.scan_issues
        if issue.kind == "EXTRACTOR_ERROR" and issue.check_id == "plugin:configured-extractors"
    )
    assert issue.required is True
    assert issue.detail
    assert "RuntimeError" in issue.detail
    assert_incomplete_unknown(result)


@pytest.mark.asyncio
async def test_complete_scan_binds_advisory_snapshot_identity(monkeypatch):
    from backend.app.advisories import advisory_snapshot_identity

    def handler(_request):
        return httpx.Response(
            200,
            text='<script src="/modules/ybc_blog/views/js/tracking.js"></script>',
            headers={"content-type": "text/html"},
        )

    result = await run_synthetic(handler, monkeypatch, max_requests=2)
    identity = advisory_snapshot_identity()

    assert result.advisory_snapshot_sha256 == identity.snapshot_sha256
    assert result.advisory_snapshot_date == identity.snapshot_date
    advisory_findings = [finding for finding in result.findings if finding.source]
    assert advisory_findings
    assert all(
        finding.advisory_snapshot_sha256 == identity.snapshot_sha256
        for finding in advisory_findings
    )


@pytest.mark.asyncio
async def test_extractor_failure_after_root_keeps_http_metadata_observed(monkeypatch):
    def handler(_request):
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    def failing_extract_html(_url, _body, _content_type):
        raise RuntimeError("synthetic builtin extractor failure")

    monkeypatch.setattr("backend.app.scanner.extract_html", failing_extract_html)
    result = await run_synthetic(handler, monkeypatch, max_requests=2)

    assert result.http_observation is not None
    assert result.http_observation.observed is True
    assert len(result.http_observation.headers_sha256) == 64
    assert len(result.http_observation.cookies_sha256) == 64
    assert result.scan_completeness == "INCOMPLETE"
