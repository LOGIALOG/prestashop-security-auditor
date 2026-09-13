from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.app.models import AuditResult
from backend.app.multistore import MultistoreManifest, run_multistore


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
