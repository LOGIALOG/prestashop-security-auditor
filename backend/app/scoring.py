from .models import Finding, ScoreFactor, ScoreResult, Status

FORMULA = "100 - confirmé (Critical 25, High 15, Medium 8, Low 3) - LIKELY 5 - REQUIRES_ACCESS 2 - HARDENING 1; ASSET_RESIDUE et NOT_AFFECTED: 0. Minimum 0."


def calculate_score(findings: list[Finding]) -> ScoreResult:
    factors: list[ScoreFactor] = []
    total = 100
    for finding in findings:
        points = 0
        if finding.status == Status.CONFIRMED:
            severity = finding.severity.lower()
            points = -25 if "critical" in severity else -15 if "high" in severity else -8 if "medium" in severity else -3
        elif finding.status == Status.LIKELY:
            points = -5
        elif finding.status == Status.REQUIRES_ACCESS:
            points = -2
        elif finding.status == Status.HARDENING:
            points = -1
        factors.append(ScoreFactor(subject=finding.subject, status=finding.status, points=points, reason=f"{finding.status.value}: {points} point(s) selon la formule documentée."))
        total += points
    return ScoreResult(value=max(0, total), formula=FORMULA, factors=factors, previous_comparison=None)
