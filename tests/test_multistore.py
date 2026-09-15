from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.app.models import AuditResult, ScanIssue
from backend.app.multistore import MultistoreManifest, MultistoreScannerError, run_multistore
from backend.app.scanner import AuditPolicyError


def manifest(**overrides) -> MultistoreManifest:
    payload = {
        "schema_version":"1.0",
        "authorization_confirmed":True,
        "delay_seconds":1,
        "shops":[
            {"shop_id":"ma","name":"Boutique Maroc","target":"https://ma.example","max_requests":2},
            {"shop_id":"fr","name":"Boutique France","target":"https://fr.example","max_requests":3},
        ],
    }
    payload.update(overrides)
    return MultistoreManifest.model_validate(payload)


def audit_for(request, complete=True) -> AuditResult:
    now = datetime(2000, 1, 1, tzinfo=timezone.utc)
    target = str(request.target).rstrip("/")
    return AuditResult(
        target=target,
        id=f"audit-{request.target.host}",
        domain=request.target.host,
        started_at=now,
        completed_at=now,
        request_count=1,
        scope=[target],
        findings=[],
        headers={},
        cookies=[],
        scan_completeness="COMPLETED" if complete else "INCOMPLETE",
        scan_issues=[] if complete else [ScanIssue(kind="HTTP_STATUS",url=target,required=True,status_code=503)],
        report_path="C:/private/report.html",
    )


def test_manifest_requires_authorization_and_unique_shop_ids():
    with pytest.raises(ValidationError, match="autorisation explicite"):
        manifest(authorization_confirmed=False)
    duplicate = [
        {"shop_id":"shop","name":"One","target":"https://one.example"},
        {"shop_id":"SHOP","name":"Two","target":"https://two.example"},
    ]
    with pytest.raises(ValidationError, match="shop_id unique"):
        manifest(shops=duplicate)


def test_manifest_rejects_cross_origin_pages_and_excessive_budget():
    with pytest.raises(ValidationError, match="origine exacte"):
        manifest(shops=[{"shop_id":"shop","name":"Shop","target":"https://one.example","public_pages":["https://two.example/page"]}])
    shops = [{"shop_id":f"shop-{index}","name":f"Shop {index}","target":f"https://shop-{index}.example","max_requests":20} for index in range(6)]
    with pytest.raises(ValidationError, match="100 requêtes"):
        manifest(shops=shops)


@pytest.mark.asyncio
async def test_multistore_keeps_each_shop_audit_separate_and_export_portable():
    requests = []

    class FakeScanner:
        async def run(self, request):
            requests.append(request)
            now = datetime.now(timezone.utc)
            target = str(request.target).rstrip("/")
            return AuditResult(target=target,id=target.rsplit("/",1)[-1],domain=request.target.host,started_at=now,completed_at=now,request_count=1,scope=[target],findings=[],headers={},cookies=[],scan_completeness="COMPLETED",scan_issues=[],report_path="C:/private/report.html")

    result = await run_multistore(manifest(), FakeScanner)
    exported = result.portable_export()

    assert [shop.shop_id for shop in result.shops] == ["ma","fr"]
    assert [request.max_requests for request in requests] == [2,3]
    assert all(request.authorization_confirmed for request in requests)
    assert "report_path" not in str(exported)
    assert exported["format"] == "logialog-multistore-audit"


@pytest.mark.asyncio
async def test_multistore_retains_first_incomplete_shop_and_stops_following_shop():
    requests = []

    class FakeScanner:
        async def run(self, request):
            requests.append(request.target.host)
            return audit_for(request,complete=False)

    result = await run_multistore(manifest(), FakeScanner)
    exported = result.portable_export()

    assert requests == ["ma.example"]
    assert [shop.shop_id for shop in result.shops] == ["ma"]
    assert result.shops[0].audit.scan_completeness == "INCOMPLETE"
    assert result.shops[0].audit.scan_issues[0].kind == "HTTP_STATUS"
    assert result.shops[0].audit.scan_issues[0].required is True
    assert exported["shops"][0]["audit"]["scan_issues"][0]["status_code"] == 503
    assert "report_path" not in str(exported)


@pytest.mark.asyncio
async def test_multistore_retains_completed_and_later_incomplete_then_stops():
    shops = [
        {"shop_id":"a","name":"Synthetic A","target":"https://a.example","max_requests":2},
        {"shop_id":"b","name":"Synthetic B","target":"https://b.example","max_requests":2},
        {"shop_id":"c","name":"Synthetic C","target":"https://c.example","max_requests":2},
    ]
    requests = []

    class FakeScanner:
        async def run(self, request):
            requests.append(request.target.host)
            return audit_for(request,complete=request.target.host != "b.example")

    result = await run_multistore(manifest(shops=shops), FakeScanner)

    assert requests == ["a.example","b.example"]
    assert [shop.shop_id for shop in result.shops] == ["a","b"]
    assert result.shops[0].audit.scan_completeness == "COMPLETED"
    assert result.shops[1].audit.scan_completeness == "INCOMPLETE"
    assert result.shops[1].audit.scan_issues[0].required is True


@pytest.mark.asyncio
async def test_multistore_scanner_exception_stops_without_fabricating_audit():
    requests = []

    class FailingScanner:
        async def run(self, request):
            requests.append(request.target.host)
            raise OSError("synthetic scanner failure")

    with pytest.raises(OSError,match="synthetic scanner failure"):
        await run_multistore(manifest(), FailingScanner)

    assert requests == ["ma.example"]


@pytest.mark.asyncio
async def test_multistore_scanner_failure_preserves_completed_and_identifies_failed_shop():
    shops = [
        {"shop_id":"a","name":"Synthetic A","target":"https://a.example","max_requests":2},
        {"shop_id":"b","name":"Synthetic B","target":"https://b.example","max_requests":2},
        {"shop_id":"c","name":"Synthetic C","target":"https://c.example","max_requests":2},
    ]
    requests = []

    class FlakyScanner:
        async def run(self, request):
            requests.append(request.target.host)
            if request.target.host == "b.example":
                raise OSError("synthetic scanner failure on B")
            return audit_for(request,complete=True)

    with pytest.raises(MultistoreScannerError,match="synthetic scanner failure on B") as exc_info:
        await run_multistore(manifest(shops=shops), FlakyScanner)

    assert requests == ["a.example","b.example"]
    assert exc_info.value.failed_shop_id == "b"
    assert [shop.shop_id for shop in exc_info.value.partial_shops] == ["a"]
    assert exc_info.value.partial_shops[0].audit.scan_completeness == "COMPLETED"
    assert isinstance(exc_info.value.__cause__,OSError)


@pytest.mark.asyncio
async def test_multistore_first_shop_scanner_failure_carries_empty_partial():
    requests = []

    class FailingScanner:
        async def run(self, request):
            requests.append(request.target.host)
            raise OSError("synthetic scanner failure")

    with pytest.raises(MultistoreScannerError) as exc_info:
        await run_multistore(manifest(), FailingScanner)

    assert requests == ["ma.example"]
    assert exc_info.value.failed_shop_id == "ma"
    assert exc_info.value.partial_shops == ()


@pytest.mark.asyncio
async def test_multistore_multiple_completed_preserved_before_failure():
    shops = [
        {"shop_id":"a","name":"Synthetic A","target":"https://a.example","max_requests":2},
        {"shop_id":"b","name":"Synthetic B","target":"https://b.example","max_requests":2},
        {"shop_id":"c","name":"Synthetic C","target":"https://c.example","max_requests":2},
        {"shop_id":"d","name":"Synthetic D","target":"https://d.example","max_requests":2},
    ]
    requests = []

    class FlakyScanner:
        async def run(self, request):
            requests.append(request.target.host)
            if request.target.host == "c.example":
                raise OSError("synthetic scanner failure on C")
            return audit_for(request,complete=True)

    with pytest.raises(MultistoreScannerError) as exc_info:
        await run_multistore(manifest(shops=shops), FlakyScanner)

    assert requests == ["a.example","b.example","c.example"]
    assert exc_info.value.failed_shop_id == "c"
    assert [shop.shop_id for shop in exc_info.value.partial_shops] == ["a","b"]


@pytest.mark.asyncio
async def test_multistore_http_error_wrapped_without_fabricating_audit():
    import httpx

    requests = []

    class FlakyScanner:
        async def run(self, request):
            requests.append(request.target.host)
            raise httpx.ConnectError("synthetic connection failure")

    with pytest.raises(MultistoreScannerError,match="synthetic connection failure"):
        await run_multistore(manifest(), FlakyScanner)

    assert requests == ["ma.example"]


@pytest.mark.asyncio
async def test_multistore_policy_error_stays_unwrapped_for_invalid_input_exit():
    requests = []

    class PolicyScanner:
        async def run(self, request):
            requests.append(request.target.host)
            raise AuditPolicyError("synthetic policy refusal")

    with pytest.raises(AuditPolicyError,match="synthetic policy refusal") as exc_info:
        await run_multistore(manifest(), PolicyScanner)

    assert not isinstance(exc_info.value,MultistoreScannerError)
    assert requests == ["ma.example"]
