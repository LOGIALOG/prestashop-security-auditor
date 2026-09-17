import json
from datetime import datetime, timezone
from pathlib import Path

from backend.app.exports import render_json_export, render_sarif
from backend.app.models import AuditResult, ScanIssue


def demo_audit() -> AuditResult:
    fixture = Path(__file__).parents[1] / "backend" / "fixtures" / "demo-audit.json"
    return AuditResult.model_validate(json.loads(fixture.read_text(encoding="utf-8")))


def test_portable_json_excludes_local_report_path():
    audit = demo_audit()
    audit.report_path = "C:/private/reports/audit.html"

    exported = render_json_export(audit)

    assert exported["format"] == "logialog-audit"
    assert exported["format_version"] == "1.0"
    assert exported["demo"] is True
    assert "report_path" not in exported["audit"]
    evidence = exported["audit"]["findings"][0]["evidence"][0]
    assert set(("url", "captured_at", "evidence_type", "excerpt", "response_sha256", "confidence", "detection_method")) <= evidence.keys()


def test_sarif_preserves_evidence_provenance_and_demo_marker():
    exported = render_sarif(demo_audit())
    run = exported["runs"][0]
    result = run["results"][0]
    location = result["locations"][0]

    assert exported["version"] == "2.1.0"
    assert run["tool"]["driver"]["informationUri"] == "https://github.com/logialog/prestashop-security-auditor"
    assert run["properties"]["demo"] is True
    assert result["properties"]["demo"] is True
    assert location["physicalLocation"]["artifactLocation"]["uri"].startswith("https://demo.local/")
    assert len(location["properties"]["responseSha256"]) == 64


def test_sarif_uses_unique_rules_for_repeated_subjects():
    audit = demo_audit()
    audit.findings.append(audit.findings[0].model_copy(deep=True))

    exported = render_sarif(audit)

    rules = exported["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == len({rule["id"] for rule in rules})


def test_sarif_preserves_incomplete_scan_state_and_structured_issues():
    audit = demo_audit()
    audit.scan_completeness = "INCOMPLETE"
    audit.scan_issues = [
        ScanIssue(kind="BUDGET_EXHAUSTED", url="https://demo.local/required", check_id="http:public-page")
    ]

    properties = render_sarif(audit)["runs"][0]["properties"]

    assert properties["scanCompleteness"] == "INCOMPLETE"
    assert properties["scanIssues"] == [
        {
            "kind": "BUDGET_EXHAUSTED",
            "url": "https://demo.local/required",
            "required": True,
            "checkId": "http:public-page",
            "statusCode": None,
            "detail": None,
            "capturedAt": None,
        }
    ]


def test_exports_preserve_transport_issue_detail_and_timestamp():
    audit = demo_audit()
    audit.scan_completeness = "INCOMPLETE"
    captured = datetime(2000, 1, 1, tzinfo=timezone.utc)
    audit.scan_issues = [
        ScanIssue(
            kind="TRANSPORT_ERROR",
            url="https://demo.local/",
            required=True,
            detail="ConnectError: [MASQUÉ]",
            captured_at=captured,
        )
    ]

    run_properties = render_sarif(audit)["runs"][0]["properties"]
    assert run_properties["scanIssues"][0]["detail"] == "ConnectError: [MASQUÉ]"
    assert run_properties["scanIssues"][0]["capturedAt"] == captured.isoformat()

    exported = render_json_export(audit)
    assert exported["audit"]["scan_issues"][0]["detail"] == "ConnectError: [MASQUÉ]"
    assert datetime.fromisoformat(exported["audit"]["scan_issues"][0]["captured_at"]) == captured
