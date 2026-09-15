import json
import sqlite3
from datetime import datetime,timedelta,timezone

import pytest
from pydantic import ValidationError

from backend.app import database
from backend.app.comparison import compare_audits
from backend.app.models import AuditResult,Evidence,Finding,ScanIssue,ScoreResult,Status
from backend.app.monitoring import MonitorConfig,MonitorResult,evaluate_monitor,incomplete_monitor_result


NOW=datetime(2000,1,1,tzinfo=timezone.utc)


def config(**overrides)->MonitorConfig:
    payload={"schema_version":"1.0","monitor_id":"shop.production","target":"https://shop.test","authorization_confirmed":True,"max_requests":5,"delay_seconds":1}
    payload.update(overrides)
    return MonitorConfig.model_validate(payload)


def audit(identifier:str,findings:list[Finding]|None=None,score:int=100,completed_at:datetime=NOW,complete:bool=True)->AuditResult:
    return AuditResult(target="https://shop.test",id=identifier,domain="shop.test",started_at=completed_at,completed_at=completed_at,request_count=1,scope=["https://shop.test/"],findings=findings or [],headers={},cookies=[],scan_completeness="COMPLETED" if complete else "INCOMPLETE",scan_issues=[] if complete else [ScanIssue(kind="TRANSPORT_ERROR",url="https://shop.test/",required=True)],report_sha256="a"*64,score=ScoreResult(value=score,formula="fixture",factors=[]))


def demo_audit(identifier:str,completed_at:datetime)->AuditResult:
    return AuditResult(is_demo=True,target="demo.local",id=identifier,domain="shop.test",started_at=completed_at,completed_at=completed_at,request_count=1,scope=["demo.local"],findings=[],headers={},cookies=[],scan_completeness="COMPLETED",scan_issues=[],report_sha256="a"*64,score=ScoreResult(value=100,formula="fixture",factors=[]))


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
    assert result.schema_version=="1.1"
    assert result.scan_completeness=="COMPLETED"
    assert result.scan_issues==[]
    assert result.comparison is not None


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


def test_incomplete_monitor_result_preserves_structured_issues_without_comparison():
    result=incomplete_monitor_result(config(),audit("incomplete",complete=False))

    assert result.schema_version=="1.1"
    assert result.state=="INCOMPLETE"
    assert result.notification_required is False
    assert result.comparison is None
    assert result.scan_completeness=="INCOMPLETE"
    assert result.scan_issues[0].kind=="TRANSPORT_ERROR"
    assert result.scan_issues[0].required is True


def test_monitor_result_rejects_contradictory_state_and_comparison():
    valid=evaluate_monitor(config(),audit("current"),compare_audits(audit("current"),None)).model_dump(mode="json")

    with pytest.raises(ValidationError,match="résultat de monitoring incomplet"):
        MonitorResult.model_validate(valid|{"state":"INCOMPLETE"})
    with pytest.raises(ValidationError,match="résultat de monitoring normal"):
        MonitorResult.model_validate(valid|{"comparison":None})


def test_monitor_result_rejects_incomplete_state_with_completed_coverage():
    incomplete=incomplete_monitor_result(config(),audit("incomplete",complete=False)).model_dump(mode="json")

    with pytest.raises(ValidationError,match="résultat de monitoring incomplet"):
        MonitorResult.model_validate(incomplete|{"scan_completeness":"COMPLETED"})


def test_monitor_result_rejects_incomplete_state_with_comparison():
    incomplete=incomplete_monitor_result(config(),audit("incomplete",complete=False)).model_dump(mode="json")
    comparison=compare_audits(audit("current"),None).model_dump(mode="json")

    with pytest.raises(ValidationError,match="résultat de monitoring incomplet"):
        MonitorResult.model_validate(incomplete|{"comparison":comparison})


def test_monitor_result_rejects_completed_state_with_incomplete_coverage():
    completed=evaluate_monitor(config(),audit("current"),compare_audits(audit("current"),None)).model_dump(mode="json")
    required_issue=ScanIssue(kind="TRANSPORT_ERROR",url="https://shop.test/",required=True).model_dump(mode="json")

    with pytest.raises(ValidationError,match="résultat de monitoring normal"):
        MonitorResult.model_validate(completed|{"scan_completeness":"INCOMPLETE","scan_issues":[required_issue]})


def test_previous_audit_skips_newer_incomplete_evidence(monkeypatch,tmp_path):
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"mixed.sqlite3")
    completed=audit("completed",completed_at=NOW)
    incomplete=audit("incomplete",completed_at=NOW+timedelta(minutes=1),complete=False)
    current=audit("current",completed_at=NOW+timedelta(minutes=2))
    database.save_audit(completed)
    database.save_audit(incomplete)

    selected=database.get_previous_real_audit(current)

    assert selected is not None
    assert selected.id=="completed"
    assert selected.scan_completeness=="COMPLETED"


def test_previous_audit_returns_none_when_history_is_only_incomplete(monkeypatch,tmp_path):
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"incomplete.sqlite3")
    database.save_audit(audit("incomplete",completed_at=NOW,complete=False))

    assert database.get_previous_real_audit(audit("current",completed_at=NOW+timedelta(minutes=1))) is None


def test_previous_audit_skips_legacy_incomplete_without_mutating_row(monkeypatch,tmp_path):
    db_path=tmp_path/"legacy.sqlite3"
    monkeypatch.setattr(database,"DB_PATH",db_path)
    database.init_db()
    legacy=audit("legacy",completed_at=NOW).model_dump(mode="json")
    legacy.pop("scan_completeness")
    legacy.pop("scan_issues")
    serialized=json.dumps(legacy,sort_keys=True)
    with sqlite3.connect(db_path) as db:
        db.execute("INSERT INTO audits VALUES (?,?,?,?)",("legacy","shop.test",NOW.isoformat(),serialized))

    selected=database.get_previous_real_audit(audit("current",completed_at=NOW+timedelta(minutes=1)))

    assert selected is None
    with sqlite3.connect(db_path) as db:
        persisted=db.execute("SELECT payload FROM audits WHERE id = ?",("legacy",)).fetchone()[0]
    assert persisted==serialized


def test_previous_audit_reaches_completed_past_newer_legacy_without_mutating_row(monkeypatch,tmp_path):
    db_path=tmp_path/"completed-before-legacy.sqlite3"
    monkeypatch.setattr(database,"DB_PATH",db_path)
    completed=audit("completed",completed_at=NOW)
    database.save_audit(completed)
    legacy=audit("legacy",completed_at=NOW+timedelta(minutes=1)).model_dump(mode="json")
    legacy.pop("scan_completeness")
    legacy.pop("scan_issues")
    serialized=json.dumps(legacy,sort_keys=True)
    with sqlite3.connect(db_path) as db:
        db.execute("INSERT INTO audits VALUES (?,?,?,?)",("legacy","shop.test",(NOW+timedelta(minutes=1)).isoformat(),serialized))

    selected=database.get_previous_real_audit(audit("current",completed_at=NOW+timedelta(minutes=2)))

    assert selected is not None
    assert selected.id=="completed"
    with sqlite3.connect(db_path) as db:
        persisted=db.execute("SELECT payload FROM audits WHERE id = ?",("legacy",)).fetchone()[0]
    assert persisted==serialized


def test_previous_audit_selects_newest_of_multiple_completed(monkeypatch,tmp_path):
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"multiple-completed.sqlite3")
    database.save_audit(audit("oldest-completed",completed_at=NOW))
    database.save_audit(audit("newest-completed",completed_at=NOW+timedelta(minutes=1)))

    selected=database.get_previous_real_audit(audit("current",completed_at=NOW+timedelta(minutes=2)))

    assert selected is not None
    assert selected.id=="newest-completed"


def test_previous_real_audit_skips_newer_completed_demo(monkeypatch,tmp_path):
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"real-before-demo.sqlite3")
    database.save_audit(audit("completed-real",completed_at=NOW))
    database.save_audit(demo_audit("completed-demo",completed_at=NOW+timedelta(minutes=1)))

    selected=database.get_previous_real_audit(audit("current-real",completed_at=NOW+timedelta(minutes=2)))

    assert selected is not None
    assert selected.id=="completed-real"
    assert selected.is_demo is False


def test_previous_real_audit_returns_none_for_demo_only_history(monkeypatch,tmp_path):
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"demo-only.sqlite3")
    database.save_audit(demo_audit("completed-demo",completed_at=NOW))

    selected=database.get_previous_real_audit(audit("current-real",completed_at=NOW+timedelta(minutes=1)))

    assert selected is None
