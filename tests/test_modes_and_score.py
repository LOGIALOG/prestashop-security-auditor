import json
from pathlib import Path

from backend.app.models import AuditResult, Evidence, Finding, Status
from backend.app.scoring import calculate_score

ROOT = Path(__file__).parents[1]


def test_demo_fixture_is_strictly_demo_local():
    fixtures = list(ROOT.glob("**/*fixture*.json")) + list((ROOT / "backend/fixtures").glob("*.json"))
    assert fixtures
    for path in set(fixtures):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["is_demo"] is True
        assert data["target"] == "demo.local"
        AuditResult.model_validate(data)


def test_score_weights_and_no_previous_comparison():
    evidence=Evidence(url="https://shop.test/",evidence_type="test",excerpt="clean",response_sha256="a"*64,confidence="high",detection_method="fixture")
    findings=[
        Finding(subject="critical",status=Status.CONFIRMED,severity="Critical 9.8",interpretation="x",business_risk="x",remediation="x",evidence=[evidence]),
        Finding(subject="access",status=Status.REQUIRES_ACCESS,interpretation="x",business_risk="x",remediation="x",evidence=[evidence]),
        Finding(subject="residue",status=Status.ASSET_RESIDUE,interpretation="x",business_risk="x",remediation="x",evidence=[evidence]),
    ]
    score=calculate_score(findings)
    assert score.value == 73
    assert next(f.points for f in score.factors if f.subject == "residue") == 0
    assert score.previous_comparison is None


def test_no_fabricated_client_result_literals():
    forbidden = ["8.1" + ".4", "8.1" + ".27", "72" + "/100", "2025" + "-0521", "+8" + " pts", "ps_" + "checkout"]
    excluded = {"node_modules", "dist", ".git", ".venv", "__pycache__", ".pytest_cache"}
    files = [p for p in ROOT.rglob("*") if p.is_file() and not excluded.intersection(p.parts)]
    corpus = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in files)
    assert not any(value in corpus for value in forbidden)
