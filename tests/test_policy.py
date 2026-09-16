import json
from datetime import datetime,timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.app.models import AuditResult,Evidence,Finding,ScanIssue,ScoreResult,Status
from backend.app.policy import PolicyPack,evaluate_policy,load_policy_pack


def clean_audit()->AuditResult:
    now=datetime.now(timezone.utc)
    return AuditResult(target="https://shop.test",id="audit-1",domain="shop.test",started_at=now,completed_at=now,request_count=1,scope=["https://shop.test/"],findings=[],headers={},cookies=[],scan_completeness="COMPLETED",scan_issues=[],report_sha256="a"*64,score=ScoreResult(value=100,formula="fixture",factors=[]))


def test_bundled_policy_packs_validate():
    root=Path(__file__).parents[1]
    assert load_policy_pack(root/"policies/agency-release.json").policy_id=="logialog.agency-release"
    assert load_policy_pack(root/"policies/triage.json").policy_id=="logialog.triage"


def test_clean_real_audit_passes_agency_release_policy():
    policy=load_policy_pack(Path(__file__).parents[1]/"policies/agency-release.json")
    result=evaluate_policy(clean_audit(),policy)
    assert result.decision=="PASS"
    assert result.violations==[]


def test_incomplete_policy_result_uses_unknown_aware_schema_version():
    audit=clean_audit().model_copy(update={"scan_completeness":"INCOMPLETE","scan_issues":[ScanIssue(kind="TRANSPORT_ERROR",url="https://shop.test/")]})

    result=evaluate_policy(audit,PolicyPack(policy_id="test.incomplete",title="Incomplete",fail_on_statuses=[],require_report_hash=False))

    assert result.schema_version=="1.1"
    assert result.decision=="UNKNOWN"


def test_policy_reports_status_score_confidence_and_hash_failures():
    audit=clean_audit()
    evidence=Evidence(url="https://shop.test/",evidence_type="fixture",excerpt="marker",response_sha256="b"*64,confidence="low",detection_method="fixture")
    audit.findings=[Finding(subject="module_x",status=Status.CONFIRMED,severity="High",version="1.0.0",interpretation="fixture",business_risk="fixture",remediation="fixture",evidence=[evidence])]
    audit.score=ScoreResult(value=50,formula="fixture",factors=[])
    audit.report_sha256=None
    policy=PolicyPack(policy_id="test.strict",title="Strict",minimum_score=70,fail_on_statuses=[Status.CONFIRMED],minimum_evidence_confidence="medium",require_report_hash=True)
    result=evaluate_policy(audit,policy)
    rules={violation.rule for violation in result.violations}
    assert result.decision=="FAIL"
    assert {"minimum_score","forbidden_status:CONFIRMED","minimum_evidence_confidence","report_hash_required"}<=rules


def test_demo_is_rejected_without_changing_findings():
    data=json.loads((Path(__file__).parents[1]/"backend/fixtures/demo-audit.json").read_text(encoding="utf-8"))
    audit=AuditResult.model_validate(data)
    before=audit.model_dump_json()
    result=evaluate_policy(audit,PolicyPack(policy_id="test.demo",title="No demo",fail_on_statuses=[],require_report_hash=False))
    assert result.decision=="FAIL"
    assert result.violations[0].rule=="demo_not_allowed"
    assert audit.model_dump_json()==before


def test_policy_schema_rejects_unknown_fields_and_duplicate_statuses():
    with pytest.raises(ValidationError):
        PolicyPack.model_validate({"policy_id":"test.extra","title":"Extra","unknown":True})
    with pytest.raises(ValidationError,match="dupliqué"):
        PolicyPack(policy_id="test.duplicate",title="Duplicate",fail_on_statuses=[Status.CONFIRMED,Status.CONFIRMED])
