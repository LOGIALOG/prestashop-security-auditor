from datetime import datetime,timezone

import pytest
from pydantic import ValidationError

from backend.app.comparison import compare_audits
from backend.app.models import AuditResult,Evidence,Finding,ScoreResult,Status
from backend.app.monitoring import MonitorConfig,evaluate_monitor


def config(**overrides)->MonitorConfig:
    payload={"schema_version":"1.0","monitor_id":"shop.production","target":"https://shop.test","authorization_confirmed":True,"max_requests":5,"delay_seconds":1}
    payload.update(overrides)
    return MonitorConfig.model_validate(payload)


def audit(identifier:str,findings:list[Finding]|None=None,score:int=100)->AuditResult:
    now=datetime.now(timezone.utc)
    return AuditResult(target="https://shop.test",id=identifier,domain="shop.test",started_at=now,completed_at=now,request_count=1,scope=["https://shop.test/"],findings=findings or [],headers={},cookies=[],scan_completeness="COMPLETED",scan_issues=[],report_sha256="a"*64,score=ScoreResult(value=score,formula="fixture",factors=[]))


def finding(subject:str,status:Status)->Finding:
    evidence=Evidence(url="https://shop.test/",evidence_type="fixture",excerpt=subject,response_sha256="b"*64,confidence="high",detection_method="fixture")
    return Finding(subject=subject,status=status,interpretation="fixture",business_risk="fixture",remediation="fixture",evidence=[evidence])


def test_monitor_config_requires_authorization_and_same_origin_pages():
    with pytest.raises(ValidationError,match="autorisation explicite"):
        config(authorization_confirmed=False)
    with pytest.raises(ValidationError,match="origine exacte"):
        config(public_pages=["https://other.test/page"])


def test_first_run_creates_quiet_baseline():
    current=audit("current")
    result=evaluate_monitor(config(),current,compare_audits(current,None))
    assert result.state=="BASELINE"
    assert result.notification_required is False
    assert result.reasons==[]


def test_unchanged_audit_stays_quiet():
    previous=audit("previous",[finding("module_x",Status.REQUIRES_ACCESS)],98)
    current=audit("current",[finding("module_x",Status.REQUIRES_ACCESS)],98)
    result=evaluate_monitor(config(),current,compare_audits(current,previous))
    assert result.state=="UNCHANGED"
    assert result.notification_required is False


def test_new_watched_finding_and_score_drop_require_notification():
    previous=audit("previous",score=100)
    current=audit("current",[finding("module_x",Status.CONFIRMED)],75)
    result=evaluate_monitor(config(),current,compare_audits(current,previous))
    assert result.state=="CHANGED"
    assert result.notification_required is True
    assert any("module_x" in reason for reason in result.reasons)
    assert any("-25" in reason for reason in result.reasons)


def test_resolved_finding_is_a_meaningful_positive_change():
    previous=audit("previous",[finding("module_x",Status.REQUIRES_ACCESS)],98)
    current=audit("current",score=100)
    result=evaluate_monitor(config(),current,compare_audits(current,previous))
    assert result.notification_required is True
    assert result.reasons==["Findings résolus: module_x"]
