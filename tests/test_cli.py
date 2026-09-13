import json
from pathlib import Path

import httpx
import pytest

from backend.app import cli
from backend.app.advisories import build_advisory_manifest
from backend.app.models import AuditResult, Status
from backend.app.scanner import PassiveScanner


def demo_audit() -> AuditResult:
    fixture = Path(__file__).parents[1] / "backend" / "fixtures" / "demo-audit.json"
    return AuditResult.model_validate(json.loads(fixture.read_text(encoding="utf-8")))


def test_advisory_validation_command(capsys):
    assert cli.main(["advisories", "validate"]) == cli.EXIT_OK
    assert "2 advisory file(s) et manifest" in capsys.readouterr().out


def test_advisory_validation_rejects_unknown_fields(tmp_path, capsys):
    (tmp_path / "invalid.json").write_text('{"module":"x","unexpected":true}', encoding="utf-8")

    assert cli.main(["advisories", "validate", "--directory", str(tmp_path)]) == cli.EXIT_INVALID_ADVISORY
    assert "Erreur:" in capsys.readouterr().err


def test_advisory_validation_rejects_duplicate_record_ids(tmp_path, capsys):
    source = Path(__file__).parents[1] / "advisories" / "ybc_blog.json"
    content = source.read_text(encoding="utf-8")
    (tmp_path / "first.json").write_text(content, encoding="utf-8")
    (tmp_path / "second.json").write_text(content, encoding="utf-8")

    assert cli.main(["advisories", "validate", "--directory", str(tmp_path)]) == cli.EXIT_INVALID_ADVISORY
    assert "record_id dupliqué" in capsys.readouterr().err


def test_export_command_writes_sarif(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "get_audit", lambda _audit_id: demo_audit())
    destination = tmp_path / "audit.sarif"

    assert cli.main(["export", "demo-session", "--format", "sarif", "--output", str(destination)]) == cli.EXIT_OK
    assert json.loads(destination.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_export_command_returns_not_found(monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_audit", lambda _audit_id: None)

    assert cli.main(["export", "missing"]) == cli.EXIT_NOT_FOUND
    assert "Audit introuvable" in capsys.readouterr().err


def test_report_render_command_uses_validated_profile(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "get_audit", lambda _audit_id: demo_audit())
    profile = tmp_path / "profile.json"
    destination = tmp_path / "client-report.html"
    profile.write_text(json.dumps({"schema_version":"1.0","brand_name":"Agence Exemple","report_title":"Rapport de sécurité","primary_color":"#123456","accent_color":"#0faec4"}),encoding="utf-8")

    code = cli.main(["report","render","demo-session","--profile",str(profile),"--output",str(destination)])

    assert code == cli.EXIT_OK
    html = destination.read_text(encoding="utf-8")
    assert "Agence Exemple" in html
    assert "logialog:engine" in html
    assert "SHA-256" in capsys.readouterr().out


def test_scan_requires_explicit_authorization(capsys):
    assert cli.main(["scan", "https://shop.test"]) == cli.EXIT_INVALID_INPUT
    assert "autorisation explicite" in capsys.readouterr().err


def test_scan_returns_policy_exit_code_for_confirmed_findings(monkeypatch, capsys):
    result = demo_audit().model_copy(deep=True)
    result.is_demo = False
    result.target = "https://shop.test"
    result.domain = "shop.test"
    for item in result.findings:
        item.is_demo = False
    result.findings[0].status = Status.CONFIRMED

    captured = {}

    class FakeScanner:
        async def run(self, request):
            captured["request"] = request
            return result

    monkeypatch.setattr(cli, "PassiveScanner", FakeScanner)
    monkeypatch.setattr(cli, "save_report", lambda _audit: ("report.html", "a" * 64))
    monkeypatch.setattr(cli, "save_audit", lambda _audit: None)

    code = cli.main(["scan", "https://shop.test", "--authorized", "--public-page", "https://shop.test/contact", "--max-requests", "1", "--fail-on-confirmed"])

    assert code == cli.EXIT_POLICY_FINDINGS
    assert str(captured["request"].public_pages[0]) == "https://shop.test/contact"
    assert json.loads(capsys.readouterr().out)["audit"]["target"] == "https://shop.test"


def test_scan_returns_runtime_exit_code_on_network_failure(monkeypatch, capsys):
    class FailingScanner:
        async def run(self, _request):
            raise httpx.ConnectError("offline")

    monkeypatch.setattr(cli, "PassiveScanner", FailingScanner)

    assert cli.main(["scan", "https://shop.test", "--authorized", "--max-requests", "1"]) == cli.EXIT_RUNTIME_ERROR
    assert "offline" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("scenario", "expected_exit"),
    [
        ("complete_success", cli.EXIT_OK),
        ("root_404", cli.EXIT_RUNTIME_ERROR),
        ("root_500", cli.EXIT_RUNTIME_ERROR),
        ("timeout", cli.EXIT_RUNTIME_ERROR),
        ("connection_refusal", cli.EXIT_RUNTIME_ERROR),
        ("required_asset_failure", cli.EXIT_RUNTIME_ERROR),
        ("self_redirect", cli.EXIT_RUNTIME_ERROR),
        ("two_node_redirect_loop", cli.EXIT_RUNTIME_ERROR),
        ("optional_failure_then_required_failure", cli.EXIT_RUNTIME_ERROR),
        ("optional_failure_then_required_recovery", cli.EXIT_OK),
    ],
)
def test_scan_exit_code_matrix(monkeypatch, capsys, scenario, expected_exit):
    shared_requests = 0

    async def no_sleep(_delay):
        return None

    def handler(request: httpx.Request):
        nonlocal shared_requests
        if scenario == "timeout" and request.url.path == "/":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        if scenario == "connection_refusal":
            raise httpx.ConnectError("synthetic connection refusal", request=request)
        if scenario == "root_404" and request.url.path == "/":
            return httpx.Response(404)
        if scenario == "root_500" and request.url.path == "/":
            return httpx.Response(500)
        if scenario == "required_asset_failure" and request.url.path == "/required.js":
            return httpx.Response(503)
        if scenario == "self_redirect" and request.url.path == "/":
            return httpx.Response(302, headers={"location": "/"})
        if scenario == "two_node_redirect_loop" and request.url.path == "/":
            return httpx.Response(302, headers={"location": "/loop"})
        if scenario == "two_node_redirect_loop" and request.url.path == "/loop":
            return httpx.Response(302, headers={"location": "/"})
        if scenario.startswith("optional_failure_then_required"):
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    text='<script src="/shared.js"></script>',
                    headers={"content-type": "text/html"},
                )
            if request.url.path == "/required":
                return httpx.Response(302, headers={"location": "/shared.js"})
            if request.url.path == "/shared.js":
                shared_requests += 1
                if scenario == "optional_failure_then_required_recovery" and shared_requests == 2:
                    return httpx.Response(200)
                return httpx.Response(503)
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    scanner = PassiveScanner(httpx.MockTransport(handler))
    monkeypatch.setattr(cli, "PassiveScanner", lambda: scanner)
    monkeypatch.setattr("backend.app.scanner.asyncio.sleep", no_sleep)
    monkeypatch.setattr(cli, "save_report", lambda _audit: ("report.html", "a" * 64))
    monkeypatch.setattr(cli, "save_audit", lambda _audit: None)
    max_requests = "6" if scenario.startswith("optional_failure_then_required") else "3"
    arguments = ["scan", "https://cli-matrix.test", "--authorized", "--max-requests", max_requests]
    if scenario == "required_asset_failure":
        arguments.extend(["--public-page", "https://cli-matrix.test/required.js"])
    if scenario.startswith("optional_failure_then_required"):
        arguments.extend(["--public-page", "https://cli-matrix.test/required"])

    actual_exit = cli.main(arguments)

    assert actual_exit == expected_exit
    assert scanner.methods and set(scanner.methods) == {"GET"}
    capsys.readouterr()


def test_monitor_run_creates_quiet_baseline(monkeypatch, tmp_path):
    result = demo_audit().model_copy(deep=True)
    result.is_demo = False
    result.target = "https://shop.test"
    result.domain = "shop.test"
    for item in result.findings:
        item.is_demo = False

    class FakeScanner:
        async def run(self, _request):
            return result

    config = tmp_path / "monitor.json"
    output = tmp_path / "monitor-result.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "monitor_id": "shop.production",
                "target": "https://shop.test",
                "authorization_confirmed": True,
                "max_requests": 1,
                "delay_seconds": 1,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "PassiveScanner", FakeScanner)
    monkeypatch.setattr(cli, "get_previous_real_audit", lambda _audit: None)
    monkeypatch.setattr(cli, "save_report", lambda _audit: ("report.html", "a" * 64))
    monkeypatch.setattr(cli, "save_audit", lambda _audit: None)

    code = cli.main(["monitor", "run", "--config", str(config), "--output", str(output)])

    assert code == cli.EXIT_OK
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["state"] == "BASELINE"
    assert payload["notification_required"] is False


def test_manifest_command_detects_advisory_tampering(tmp_path, capsys):
    source = Path(__file__).parents[1] / "advisories" / "ybc_blog.json"
    advisory = tmp_path / "ybc_blog.json"
    advisory.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    assert cli.main(["advisories", "manifest", "--directory", str(tmp_path)]) == cli.EXIT_OK
    assert cli.main(["advisories", "validate", "--directory", str(tmp_path)]) == cli.EXIT_OK

    advisory.write_text(advisory.read_text(encoding="utf-8").replace("CWE-89", "CWE-20"), encoding="utf-8")
    assert cli.main(["advisories", "validate", "--directory", str(tmp_path)]) == cli.EXIT_INVALID_ADVISORY
    assert "manifest advisory" in capsys.readouterr().err


def test_source_assess_command_exports_sarif_and_fails_on_affected(tmp_path):
    module = tmp_path / "shop" / "modules" / "ybc_blog"
    advisories = tmp_path / "advisories"
    module.mkdir(parents=True)
    advisories.mkdir()
    (module / "config.xml").write_text("<module><version><![CDATA[3.3.8]]></version></module>", encoding="utf-8")
    source = Path(__file__).parents[1] / "advisories" / "ybc_blog.json"
    (advisories / "ybc_blog.json").write_bytes(source.read_bytes())
    (advisories / "snapshot-manifest.json").write_text(
        json.dumps(build_advisory_manifest(advisories), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    destination = tmp_path / "assessment.sarif"

    code = cli.main(
        [
            "source",
            "assess",
            str(tmp_path / "shop"),
            "--advisories",
            str(advisories),
            "--format",
            "sarif",
            "--output",
            str(destination),
            "--fail-on-affected",
        ]
    )

    assert code == cli.EXIT_POLICY_FINDINGS
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"][0]["level"] == "error"
    assert payload["runs"][0]["results"][0]["ruleId"] == "friendsofpresta-CVE-2023-43979"
