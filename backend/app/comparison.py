from __future__ import annotations

from .models import AuditComparison, AuditResult, Finding, FindingChange


def _key(finding: Finding) -> tuple[str, str]:
    return finding.subject.casefold(), finding.cve or ""


def _change(previous: Finding | None, current: Finding | None) -> FindingChange:
    finding = current or previous
    assert finding is not None
    return FindingChange(
        subject=finding.subject,
        cve=finding.cve,
        previous_status=previous.status if previous else None,
        current_status=current.status if current else None,
        previous_version=previous.version if previous else None,
        current_version=current.version if current else None,
    )


def compare_audits(current: AuditResult, previous: AuditResult | None) -> AuditComparison:
    if current.is_demo:
        raise ValueError("Un audit de démonstration ne peut pas être comparé")
    if previous is None:
        return AuditComparison(audit_id=current.id, domain=current.domain, available=False)
    if previous.is_demo or previous.domain.casefold() != current.domain.casefold():
        raise ValueError("La comparaison exige deux audits réels du même domaine")

    current_findings = {_key(item): item for item in current.findings}
    previous_findings = {_key(item): item for item in previous.findings}
    added = [_change(None, current_findings[key]) for key in sorted(current_findings.keys() - previous_findings.keys())]
    resolved = [_change(previous_findings[key], None) for key in sorted(previous_findings.keys() - current_findings.keys())]
    changed: list[FindingChange] = []
    unchanged_count = 0
    for key in sorted(current_findings.keys() & previous_findings.keys()):
        old, new = previous_findings[key], current_findings[key]
        if (old.status, old.version) != (new.status, new.version):
            changed.append(_change(old, new))
        else:
            unchanged_count += 1

    score_delta = None
    if current.score is not None and previous.score is not None:
        score_delta = current.score.value - previous.score.value
    return AuditComparison(
        audit_id=current.id,
        previous_audit_id=previous.id,
        domain=current.domain,
        available=True,
        score_delta=score_delta,
        added=added,
        resolved=resolved,
        changed=changed,
        unchanged_count=unchanged_count,
    )
