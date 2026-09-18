import sqlite3
from datetime import datetime,timezone

import pytest

from backend.app import database
from backend.app.models import AuditResult,ScoreResult


def audit()->AuditResult:
    now=datetime.now(timezone.utc)
    return AuditResult(target="https://shop.test",id="audit-1",domain="shop.test",started_at=now,completed_at=now,request_count=1,scope=["https://shop.test/"],findings=[],headers={},cookies=[],scan_completeness="COMPLETED",scan_issues=[],score=ScoreResult(value=100,formula="fixture",factors=[]))


def test_audit_and_review_events_form_a_valid_append_only_chain(monkeypatch,tmp_path):
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"audits.sqlite3")
    item=audit()
    database.save_audit(item)
    database.add_history_event(item.id,"reviewed","alice@example.test","Evidence reviewed")
    database.save_audit(item)

    events=database.list_history(item.id)

    assert [event["event_type"] for event in events]==["audit_created","reviewed","audit_updated"]
    assert events[1]["actor"]=="alice@example.test"
    assert events[1]["previous_hash"]==events[0]["event_hash"]
    assert database.verify_history()==3
    with sqlite3.connect(database.DB_PATH) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0]==4


def test_history_verification_detects_database_tampering(monkeypatch,tmp_path):
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"audits.sqlite3")
    database.save_audit(audit())
    with sqlite3.connect(database.DB_PATH) as connection:
        connection.execute("UPDATE audit_events SET actor='mallory' WHERE id=1")
    with pytest.raises(ValueError,match="Hash d’historique"):
        database.verify_history()


def test_history_rejects_invalid_actor_and_multiline_note(monkeypatch,tmp_path):
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"audits.sqlite3")
    database.save_audit(audit())
    with pytest.raises(ValueError,match="opérateur"):
        database.add_history_event("audit-1","reviewed","bad actor")
    with pytest.raises(ValueError,match="une ligne"):
        database.add_history_event("audit-1","reviewed","alice","line one\nline two")
