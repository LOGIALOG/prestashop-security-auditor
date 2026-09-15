import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from backend.app import database
from backend.app.models import AuditResult, ScanIssue
from backend.app.policy import PolicyPack, evaluate_policy


NOW = datetime(2000, 1, 1, tzinfo=timezone.utc)


def historical_payload(identifier: str = "legacy-audit", completed_at: datetime = NOW) -> dict:
    return {
        "is_demo": False,
        "target": "https://legacy-audit.test",
        "id": identifier,
        "domain": "legacy-audit.test",
        "started_at": (completed_at - timedelta(minutes=1)).isoformat(),
        "completed_at": completed_at.isoformat(),
        "request_count": 1,
        "scope": ["https://legacy-audit.test/"],
        "findings": [],
        "headers": {},
        "cookies": [],
    }


def current_payload(identifier: str = "current-audit") -> dict:
    return {
        **historical_payload(identifier),
        "scan_completeness": "COMPLETED",
        "scan_issues": [],
    }


def insert_historical_payload(db_path, payload: dict) -> str:
    database.DB_PATH = db_path
    database.init_db()
    serialized = json.dumps(payload, sort_keys=True)
    with sqlite3.connect(db_path) as db:
        db.execute(
            "INSERT INTO audits (id, domain, created_at, payload) VALUES (?, ?, ?, ?)",
            (payload["id"], payload["domain"], payload["completed_at"], serialized),
        )
    return serialized


def permissive_policy() -> PolicyPack:
    return PolicyPack(
        policy_id="test.legacy-coverage",
        title="Legacy coverage",
        fail_on_statuses=[],
        require_report_hash=False,
    )


def assert_legacy_coverage_issue(audit: AuditResult) -> None:
    assert audit.scan_completeness == "INCOMPLETE"
    assert len(audit.scan_issues) == 1
    issue = audit.scan_issues[0]
    assert issue.kind == "CHECK_NOT_TESTED"
    assert issue.url == "https://legacy-audit.test"
    assert issue.required is True
    assert issue.check_id == "coverage:legacy-record"


def test_get_audit_fails_closed_for_historical_payload(monkeypatch, tmp_path):
    db_path = tmp_path / "legacy-audits.sqlite3"
    monkeypatch.setattr(database, "DB_PATH", db_path)
    original_payload = insert_historical_payload(db_path, historical_payload())

    audit = database.get_audit("legacy-audit")

    assert audit is not None
    assert_legacy_coverage_issue(audit)
    assert evaluate_policy(audit, permissive_policy()).decision == "UNKNOWN"
    with sqlite3.connect(db_path) as db:
        persisted_payload = db.execute(
            "SELECT payload FROM audits WHERE id = ?", ("legacy-audit",)
        ).fetchone()[0]
    assert persisted_payload == original_payload


def test_get_previous_real_audit_fails_closed_for_historical_payload(monkeypatch, tmp_path):
    db_path = tmp_path / "legacy-previous.sqlite3"
    monkeypatch.setattr(database, "DB_PATH", db_path)
    insert_historical_payload(db_path, historical_payload(completed_at=NOW))
    current = AuditResult.model_validate(
        current_payload("current-audit")
        | {
            "started_at": (NOW + timedelta(minutes=1)).isoformat(),
            "completed_at": (NOW + timedelta(minutes=2)).isoformat(),
        }
    )

    previous = database.get_previous_real_audit(current)

    assert previous is not None
    assert_legacy_coverage_issue(previous)


def test_partial_schema_with_only_completeness_is_rejected():
    payload = historical_payload() | {"scan_completeness": "COMPLETED"}

    with pytest.raises(ValidationError, match="fournis ensemble"):
        AuditResult.model_validate(payload)


def test_partial_schema_with_only_issues_is_rejected():
    payload = historical_payload() | {"scan_issues": []}

    with pytest.raises(ValidationError, match="fournis ensemble"):
        AuditResult.model_validate(payload)


def test_current_complete_payload_remains_complete():
    audit = AuditResult.model_validate(current_payload())

    assert audit.scan_completeness == "COMPLETED"
    assert audit.scan_issues == []


def test_current_incomplete_payload_remains_incomplete():
    payload = historical_payload("current-incomplete") | {
        "scan_completeness": "INCOMPLETE",
        "scan_issues": [
            ScanIssue(
                kind="TRANSPORT_ERROR",
                url="https://legacy-audit.test",
                required=True,
            ).model_dump()
        ],
    }

    audit = AuditResult.model_validate(payload)

    assert audit.scan_completeness == "INCOMPLETE"
    assert audit.scan_issues[0].kind == "TRANSPORT_ERROR"


def test_current_completed_payload_with_required_issue_is_rejected():
    payload = current_payload("invalid-completed") | {
        "scan_issues": [
            ScanIssue(
                kind="TRANSPORT_ERROR",
                url="https://legacy-audit.test",
                required=True,
            ).model_dump()
        ]
    }

    with pytest.raises(ValidationError, match="audit complet"):
        AuditResult.model_validate(payload)


def test_current_incomplete_payload_without_required_issue_is_rejected():
    payload = historical_payload("invalid-incomplete") | {
        "scan_completeness": "INCOMPLETE",
        "scan_issues": [],
    }

    with pytest.raises(ValidationError, match="incident obligatoire"):
        AuditResult.model_validate(payload)


def test_direct_constructor_without_completeness_fails_closed():
    audit = AuditResult(**historical_payload("direct-legacy"))

    assert_legacy_coverage_issue(audit)
    assert evaluate_policy(audit, permissive_policy()).decision == "UNKNOWN"
