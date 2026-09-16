from datetime import datetime, timezone

import pytest

from backend.app.comparison import compare_audits
from backend.app.models import AuditResult, Evidence, Finding, ScoreResult, Status


NOW = datetime(2026, 9, 6, tzinfo=timezone.utc)


def finding(subject: str, status: Status, version: str | None = None) -> Finding:
    evidence = Evidence(url="https://shop.test/", captured_at=NOW, evidence_type="test", excerpt=subject, response_sha256="a" * 64, confidence="high", detection_method="fixture")
    return Finding(subject=subject, status=status, version=version, interpretation="Test", business_risk="Test", remediation="Test", evidence=[evidence])


def audit(audit_id: str, findings: list[Finding], score: int = 90, domain: str = "shop.test") -> AuditResult:
    return AuditResult(is_demo=False, target=f"https://{domain}", id=audit_id, domain=domain, started_at=NOW, completed_at=NOW, request_count=1, scope=[f"https://{domain}/"], findings=findings, headers={}, cookies=[], scan_completeness="COMPLETED", scan_issues=[], score=ScoreResult(value=score, formula="fixture", factors=[]))


def test_comparison_classifies_added_resolved_changed_and_unchanged():
    previous = audit("old", [finding("removed", Status.CONFIRMED), finding("changed", Status.REQUIRES_ACCESS), finding("same", Status.HARDENING)], 80)
    current = audit("new", [finding("added", Status.CONFIRMED), finding("changed", Status.NOT_AFFECTED, "2.0.0"), finding("same", Status.HARDENING)], 92)

    result = compare_audits(current, previous)

    assert result.available is True
    assert result.score_delta == 12
    assert [item.subject for item in result.added] == ["added"]
    assert [item.subject for item in result.resolved] == ["removed"]
    assert [item.subject for item in result.changed] == ["changed"]
    assert result.unchanged_count == 1


def test_first_real_audit_has_no_fabricated_comparison():
    result = compare_audits(audit("new", []), None)
    assert result.available is False
    assert result.previous_audit_id is None
    assert result.score_delta is None


def test_demo_and_cross_domain_comparisons_are_rejected():
    current = audit("new", [])
    demo = current.model_copy(update={"is_demo": True, "target": "demo.local", "domain": "demo.local"})
    with pytest.raises(ValueError):
        compare_audits(demo, None)
    with pytest.raises(ValueError):
        compare_audits(current, audit("old", [], domain="other.test"))
