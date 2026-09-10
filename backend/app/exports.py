from __future__ import annotations

from typing import Any

from .models import AuditResult, Finding, Status


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
PROJECT_URL = "https://github.com/logialog/prestashop-security-auditor"


def render_json_export(audit: AuditResult) -> dict[str, Any]:
    """Return a portable audit document without leaking a local report path."""
    payload = audit.model_dump(mode="json", exclude={"report_path"})
    return {
        "format": "logialog-audit",
        "format_version": "1.0",
        "demo": audit.is_demo,
        "audit": payload,
    }


def _sarif_level(finding: Finding) -> str:
    if finding.status in {Status.ASSET_RESIDUE, Status.NOT_AFFECTED}:
        return "note"
    severity = finding.severity.casefold()
    if severity in {"critical", "critique", "high", "élevée", "elevee"}:
        return "error"
    if severity in {"medium", "moyenne", "modérée", "moderee"}:
        return "warning"
    return "note"


def render_sarif(audit: AuditResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in audit.findings:
        rule_id = f"LOGIALOG/{finding.subject}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.subject,
                "shortDescription": {"text": finding.interpretation},
                "help": {"text": finding.remediation},
                "properties": {
                    "status": finding.status.value,
                    "severity": finding.severity,
                    "cve": finding.cve,
                    "advisory": finding.source,
                },
            },
        )
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": evidence.url},
                },
                "properties": {
                    "capturedAt": evidence.captured_at.isoformat(),
                    "responseSha256": evidence.response_sha256,
                    "confidence": evidence.confidence,
                    "detectionMethod": evidence.detection_method,
                    "evidenceType": evidence.evidence_type,
                },
            }
            for evidence in finding.evidence
        ]
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding),
                "message": {"text": finding.interpretation},
                "locations": locations,
                "properties": {
                    "demo": finding.is_demo,
                    "status": finding.status.value,
                    "businessRisk": finding.business_risk,
                    "accessRequired": finding.access_required,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LOGIALOG PrestaShop Security Auditor",
                        "informationUri": PROJECT_URL,
                        "semanticVersion": "1.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": audit.id},
                "results": results,
                "properties": {
                    "demo": audit.is_demo,
                    "target": audit.target,
                    "completedAt": audit.completed_at.isoformat(),
                    "requestCount": audit.request_count,
                    "reportSha256": audit.report_sha256,
                },
            }
        ],
    }
