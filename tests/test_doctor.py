import json
from pathlib import Path

from backend.app import cli
from backend.app.doctor import run_doctor


def test_doctor_reports_required_checks_without_network(monkeypatch):
    def reject_network(*_args, **_kwargs):
        raise AssertionError("doctor must not access the network")

    monkeypatch.setattr("httpx.Client", reject_network)
    monkeypatch.setattr("httpx.AsyncClient", reject_network)

    report = run_doctor(Path(__file__).parents[1])

    assert report.ready is True
    assert report.network_access is False
    required = {check.check_id: check.status for check in report.checks if check.required}
    assert required == {
        "python": "PASS",
        "advisory_snapshot": "PASS",
        "advisory_signature": "PASS",
        "repository_safety": "PASS",
    }


def test_doctor_cli_returns_dedicated_failure_code(tmp_path):
    output = tmp_path / "doctor.json"

    code = cli.main(["doctor", "--root", str(tmp_path), "--output", str(output)])

    assert code == cli.EXIT_DOCTOR_FAILED
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["ready"] is False
    assert any(check["status"] == "FAIL" for check in payload["checks"])
