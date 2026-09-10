from datetime import date

import pytest

from backend.app.advisory_ingest import propose_advisory


def module_payload():
    return {"module": "sample", "cve": "CVE-2026-12345", "type": "Authorization flaw", "cwe": "CWE-862", "cvss": "8.1 High", "affected_max": "1.2.0", "fixed_version": "1.2.1", "authentication_required": False, "business_risk": "Unauthorized action may be possible on affected versions.", "source": "https://security.friendsofpresta.org/modules/sample.html", "published": "2026-09-01"}


def test_friendsofpresta_adapter_creates_pending_review_only():
    candidate = propose_advisory("friendsofpresta", module_payload(), date(2026, 9, 6))
    assert candidate.review_status == "pending"
    assert candidate.proposed_record["record_id"] == "friendsofpresta-CVE-2026-12345"
    assert candidate.proposed_record["retrieved_at"] == "2026-09-06"
    assert len(candidate.source_payload_sha256) == 64


def test_prestashop_adapter_is_deterministic():
    payload = {"release": "8.2.9", "published": "2026-09-05", "summary": "Security release.", "source": "https://build.prestashop-project.org/news/release/"}
    first = propose_advisory("prestashop", payload, date(2026, 9, 6))
    second = propose_advisory("prestashop", payload, date(2026, 9, 6))
    assert first == second


def test_adapter_rejects_incomplete_or_invalid_upstream_data():
    payload = module_payload()
    payload["cve"] = "invalid"
    with pytest.raises(ValueError):
        propose_advisory("friendsofpresta", payload, date(2026, 9, 6))
