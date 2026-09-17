import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.app import cli, database
from backend.app.advisories import build_advisory_manifest
from backend.app.manifest_signing import sign_manifest
from backend.app.models import AuditResult, ScanIssue, Status
from backend.app.multistore import MultistoreAudit, MultistoreManifest, ShopAudit
from backend.app.multistore import run_multistore as real_run_multistore
from backend.app.report import save_report as write_report
from backend.app.scanner import PassiveScanner


def demo_audit() -> AuditResult:
    fixture = Path(__file__).parents[1] / "backend" / "fixtures" / "demo-audit.json"
    return AuditResult.model_validate(json.loads(fixture.read_text(encoding="utf-8")))


def real_monitor_audit(identifier: str) -> AuditResult:
    result = demo_audit().model_copy(deep=True)
    result.id = identifier
    result.is_demo = False
    result.target = "https://shop.test"
    result.domain = "shop.test"
    for item in result.findings:
        item.is_demo = False
    return result


def multistore_cli_audit(identifier: str, complete: bool = True, confirmed: bool = False) -> AuditResult:
    payload = real_monitor_audit(identifier).model_dump(mode="json")
    payload["findings"] = payload["findings"][:1] if confirmed else []
    if confirmed:
        payload["findings"][0]["status"] = Status.CONFIRMED
    payload["scan_completeness"] = "COMPLETED" if complete else "INCOMPLETE"
    payload["scan_issues"] = [] if complete else [
        ScanIssue(kind="HTTP_STATUS",url="https://shop.test/",required=True,status_code=503).model_dump(mode="json")
    ]
    payload["report_path"] = None
    payload["report_sha256"] = None
    return AuditResult.model_validate(payload)


def multistore_cli_batch(*audits: AuditResult) -> MultistoreAudit:
    now = datetime(2000,1,1,tzinfo=timezone.utc)
    return MultistoreAudit(
        batch_id="synthetic-batch",
        started_at=now,
        completed_at=now,
        shops=[ShopAudit(shop_id=f"shop-{index}",name=f"Synthetic {index}",audit=audit) for index,audit in enumerate(audits,1)],
    )


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


@pytest.mark.asyncio
async def test_multistore_cli_persists_first_incomplete_shop_before_runtime_exit(monkeypatch,tmp_path):
    incomplete=multistore_cli_audit("incomplete-a",complete=False)
    batch=multistore_cli_batch(incomplete)
    reports=[]
    audits=[]
    output=tmp_path/"first-incomplete.json"

    async def run(_manifest):
        return batch

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",lambda audit: reports.append(audit.id) or (f"{audit.id}.html","a"*64))
    monkeypatch.setattr(cli,"save_audit",lambda audit: audits.append(audit.id))

    code=await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=False),object())
    exported=json.loads(output.read_text(encoding="utf-8"))

    assert code==cli.EXIT_RUNTIME_ERROR
    assert reports==[incomplete.id]
    assert audits==[incomplete.id]
    assert exported["shops"][0]["shop_id"]=="shop-1"
    assert exported["shops"][0]["audit"]["id"]==incomplete.id
    assert exported["shops"][0]["audit"]["scan_completeness"]=="INCOMPLETE"
    assert exported["shops"][0]["audit"]["scan_issues"][0]["required"] is True
    assert "report_path" not in str(exported)


@pytest.mark.asyncio
async def test_multistore_cli_incomplete_exit_precedes_confirmed_policy_and_preserves_attempts(monkeypatch,tmp_path):
    completed=multistore_cli_audit("completed-a",confirmed=True)
    incomplete=multistore_cli_audit("incomplete-b",complete=False)
    batch=multistore_cli_batch(completed,incomplete)
    reports=[]
    audits=[]
    output=tmp_path/"later-incomplete.json"

    async def run(_manifest):
        return batch

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",lambda audit: reports.append(audit.id) or (f"{audit.id}.html","a"*64))
    monkeypatch.setattr(cli,"save_audit",lambda audit: audits.append(audit.id))

    code=await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=True),object())
    exported=json.loads(output.read_text(encoding="utf-8"))

    assert code==cli.EXIT_RUNTIME_ERROR
    assert reports==[completed.id,incomplete.id]
    assert audits==[completed.id,incomplete.id]
    assert [shop["shop_id"] for shop in exported["shops"]]==["shop-1","shop-2"]
    assert exported["shops"][1]["audit"]["id"]==incomplete.id
    assert exported["shops"][1]["audit"]["scan_completeness"]=="INCOMPLETE"
    assert exported["shops"][1]["audit"]["scan_issues"][0]["status_code"]==503
    assert "report_path" not in str(exported)


@pytest.mark.asyncio
async def test_multistore_cli_all_completed_persists_once_and_returns_success(monkeypatch,tmp_path):
    first=multistore_cli_audit("completed-a")
    second=multistore_cli_audit("completed-b")
    batch=multistore_cli_batch(first,second)
    reports=[]
    audits=[]
    output=tmp_path/"completed.json"

    async def run(_manifest):
        return batch

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",lambda audit: reports.append(audit.id) or (f"{audit.id}.html","a"*64))
    monkeypatch.setattr(cli,"save_audit",lambda audit: audits.append(audit.id))

    code=await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=False),object())
    exported=json.loads(output.read_text(encoding="utf-8"))

    assert code==cli.EXIT_OK
    assert reports==[first.id,second.id]
    assert audits==[first.id,second.id]
    assert [shop["audit"]["id"] for shop in exported["shops"]]==[first.id,second.id]


@pytest.mark.asyncio
async def test_multistore_cli_completed_confirmed_batch_keeps_policy_exit(monkeypatch,tmp_path):
    confirmed=multistore_cli_audit("confirmed-a",confirmed=True)
    batch=multistore_cli_batch(confirmed)
    output=tmp_path/"confirmed.json"

    async def run(_manifest):
        return batch

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",lambda audit: (f"{audit.id}.html","a"*64))
    monkeypatch.setattr(cli,"save_audit",lambda _audit: None)

    code=await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=True),object())

    assert code==cli.EXIT_POLICY_FINDINGS
    assert output.is_file()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure",["report","audit"])
async def test_multistore_cli_persistence_failure_cannot_return_success(monkeypatch,tmp_path,failure):
    completed=multistore_cli_audit("completed-a")
    batch=multistore_cli_batch(completed)
    output=tmp_path/f"{failure}-failure.json"

    async def run(_manifest):
        return batch

    def save_report(audit):
        if failure=="report":
            raise OSError("synthetic report failure")
        return f"{audit.id}.html","a"*64

    def save_audit(_audit):
        if failure=="audit":
            raise OSError("synthetic audit failure")

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",save_report)
    monkeypatch.setattr(cli,"save_audit",save_audit)

    with pytest.raises(OSError,match=f"synthetic {failure} failure"):
        await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=False),object())
    assert not output.exists()


def test_multistore_cli_scanner_exception_returns_runtime_error_without_output(monkeypatch,tmp_path,capsys):
    output=tmp_path/"scanner-failure.json"

    async def fail(_manifest):
        raise OSError("synthetic scanner failure")

    monkeypatch.setattr(cli,"load_multistore_manifest",lambda _path: object())
    monkeypatch.setattr(cli,"run_multistore",fail)

    code=cli.main(["multistore","scan","--manifest",str(tmp_path/"manifest.json"),"--output",str(output)])

    assert code==cli.EXIT_RUNTIME_ERROR
    assert "synthetic scanner failure" in capsys.readouterr().err
    assert not output.exists()


def flaky_multistore_manifest(*shop_ids: str) -> MultistoreManifest:
    return MultistoreManifest.model_validate({
        "schema_version":"1.0",
        "authorization_confirmed":True,
        "delay_seconds":1,
        "shops":[
            {"shop_id":shop_id,"name":f"Synthetic {shop_id}","target":f"https://{shop_id}.example","max_requests":2}
            for shop_id in shop_ids
        ],
    })


@pytest.mark.asyncio
async def test_multistore_cli_scanner_failure_preserves_completed_before_runtime_exit(monkeypatch,tmp_path,capsys):
    manifest=flaky_multistore_manifest("a","b","c")
    requests=[]
    produced=[]
    reports=[]
    audits=[]
    output=tmp_path/"later-scanner-failure.json"

    class FlakyScanner:
        async def run(self, request):
            requests.append(request.target.host)
            if request.target.host == "b.example":
                raise OSError("synthetic scanner failure on B")
            audit=multistore_cli_audit(request.target.host)
            produced.append(audit)
            return audit

    async def run(manifest_arg):
        return await real_run_multistore(manifest_arg,FlakyScanner)

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",lambda audit: reports.append(audit.id) or (f"{audit.id}.html","a"*64))
    monkeypatch.setattr(cli,"save_audit",lambda audit: audits.append(audit.id))

    code=await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=False),manifest)

    assert code==cli.EXIT_RUNTIME_ERROR
    assert requests==["a.example","b.example"]
    assert reports==[produced[0].id]
    assert audits==[produced[0].id]
    assert "synthetic scanner failure on B" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.asyncio
async def test_multistore_cli_first_shop_scanner_failure_saves_nothing(monkeypatch,tmp_path,capsys):
    manifest=flaky_multistore_manifest("a","b")
    requests=[]
    reports=[]
    audits=[]
    output=tmp_path/"first-scanner-failure.json"

    class FailingScanner:
        async def run(self, request):
            requests.append(request.target.host)
            raise OSError("synthetic scanner failure")

    async def run(manifest_arg):
        return await real_run_multistore(manifest_arg,FailingScanner)

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",lambda audit: reports.append(audit.id) or (f"{audit.id}.html","a"*64))
    monkeypatch.setattr(cli,"save_audit",lambda audit: audits.append(audit.id))

    code=await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=False),manifest)

    assert code==cli.EXIT_RUNTIME_ERROR
    assert requests==["a.example"]
    assert reports==[]
    assert audits==[]
    assert "synthetic scanner failure" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.asyncio
async def test_multistore_cli_multiple_completed_preserved_before_scanner_failure(monkeypatch,tmp_path,capsys):
    manifest=flaky_multistore_manifest("a","b","c","d")
    requests=[]
    produced=[]
    reports=[]
    audits=[]
    output=tmp_path/"multi-scanner-failure.json"

    class FlakyScanner:
        async def run(self, request):
            requests.append(request.target.host)
            if request.target.host == "c.example":
                raise OSError("synthetic scanner failure on C")
            audit=multistore_cli_audit(request.target.host)
            produced.append(audit)
            return audit

    async def run(manifest_arg):
        return await real_run_multistore(manifest_arg,FlakyScanner)

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",lambda audit: reports.append(audit.id) or (f"{audit.id}.html","a"*64))
    monkeypatch.setattr(cli,"save_audit",lambda audit: audits.append(audit.id))

    code=await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=False),manifest)
    capsys.readouterr()

    assert code==cli.EXIT_RUNTIME_ERROR
    assert requests==["a.example","b.example","c.example"]
    assert reports==[audit.id for audit in produced]
    assert audits==[audit.id for audit in produced]
    assert len(reports)==2
    assert not output.exists()


@pytest.mark.asyncio
async def test_multistore_cli_scanner_failure_over_confirmed_returns_runtime_error(monkeypatch,tmp_path,capsys):
    manifest=flaky_multistore_manifest("a","b")
    requests=[]
    produced=[]
    reports=[]
    audits=[]
    output=tmp_path/"confirmed-scanner-failure.json"

    class FlakyScanner:
        async def run(self, request):
            requests.append(request.target.host)
            if request.target.host == "b.example":
                raise OSError("synthetic scanner failure on B")
            audit=multistore_cli_audit(request.target.host,confirmed=True)
            produced.append(audit)
            return audit

    async def run(manifest_arg):
        return await real_run_multistore(manifest_arg,FlakyScanner)

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",lambda audit: reports.append(audit.id) or (f"{audit.id}.html","a"*64))
    monkeypatch.setattr(cli,"save_audit",lambda audit: audits.append(audit.id))

    code=await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=True),manifest)
    capsys.readouterr()

    assert code==cli.EXIT_RUNTIME_ERROR
    assert code!=cli.EXIT_POLICY_FINDINGS
    assert requests==["a.example","b.example"]
    assert reports==[produced[0].id]
    assert audits==[produced[0].id]
    assert not output.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure",["report","audit"])
async def test_multistore_cli_partial_persistence_failure_cannot_return_success(monkeypatch,tmp_path,failure):
    manifest=flaky_multistore_manifest("a","b")
    output=tmp_path/f"partial-{failure}-failure.json"

    class FlakyScanner:
        async def run(self, request):
            if request.target.host == "b.example":
                raise OSError("synthetic scanner failure on B")
            return multistore_cli_audit(request.target.host)

    async def run(manifest_arg):
        return await real_run_multistore(manifest_arg,FlakyScanner)

    def save_report(audit):
        if failure=="report":
            raise OSError("synthetic partial report failure")
        return f"{audit.id}.html","a"*64

    def save_audit(_audit):
        if failure=="audit":
            raise OSError("synthetic partial audit failure")

    monkeypatch.setattr(cli,"run_multistore",run)
    monkeypatch.setattr(cli,"save_report",save_report)
    monkeypatch.setattr(cli,"save_audit",save_audit)

    with pytest.raises(OSError,match=f"synthetic partial {failure} failure"):
        await cli._scan_multistore(SimpleNamespace(output=output,fail_on_confirmed=False),manifest)
    assert not output.exists()


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
        ("optional_failure_then_required_no_budget", cli.EXIT_RUNTIME_ERROR),
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
    if scenario == "optional_failure_then_required_no_budget":
        max_requests = "4"
    else:
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
    result = real_monitor_audit("baseline")

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
    assert payload["schema_version"] == "1.1"
    assert payload["state"] == "BASELINE"
    assert payload["notification_required"] is False
    assert payload["scan_completeness"] == "COMPLETED"
    assert payload["scan_issues"] == []
    assert payload["comparison"] is not None


def test_monitor_incomplete_scan_persists_report_and_structured_evidence(monkeypatch, tmp_path):
    config = tmp_path / "monitor.json"
    output = tmp_path / "monitor-result.json"
    report = tmp_path / "monitor-report.html"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "monitor_id": "shop.production",
                "target": "https://monitor-incomplete.test",
                "authorization_confirmed": True,
                "max_requests": 1,
                "delay_seconds": 1,
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request):
        return httpx.Response(503, request=request)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Incomplete monitor scans must not be compared or evaluated")

    scanner = PassiveScanner(httpx.MockTransport(handler))
    monkeypatch.setattr(cli, "PassiveScanner", lambda: scanner)
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "audits.sqlite3")
    monkeypatch.setattr(cli, "save_report", lambda audit: write_report(audit, destination=report))
    monkeypatch.setattr(cli, "get_previous_real_audit", forbidden)
    monkeypatch.setattr(cli, "compare_audits", forbidden)
    monkeypatch.setattr(cli, "evaluate_monitor", forbidden)

    code = cli.main(["monitor", "run", "--config", str(config), "--output", str(output)])

    assert code == cli.EXIT_RUNTIME_ERROR
    assert report.is_file()
    assert output.is_file()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.1"
    assert payload["state"] == "INCOMPLETE"
    assert payload["notification_required"] is False
    assert payload["comparison"] is None
    assert payload["scan_completeness"] == "INCOMPLETE"
    assert payload["scan_issues"] == [
        {
            "kind": "HTTP_STATUS",
            "url": "https://monitor-incomplete.test/",
            "required": True,
            "check_id": None,
            "status_code": 503,
            "detail": None,
            "captured_at": None,
        }
    ]
    persisted = database.get_audit(payload["audit_id"])
    assert persisted is not None
    assert persisted.id == payload["audit_id"]
    assert persisted.scan_completeness == "INCOMPLETE"
    assert persisted.scan_issues[0].status_code == 503
    assert persisted.report_path == str(report)
    assert persisted.report_sha256 is not None and len(persisted.report_sha256) == 64


def test_monitor_completed_unchanged_run_remains_successful(monkeypatch, tmp_path):
    current = real_monitor_audit("current-unchanged")
    previous = current.model_copy(deep=True, update={"id": "previous-unchanged"})
    config = tmp_path / "monitor.json"
    output = tmp_path / "monitor-result.json"
    config.write_text(json.dumps({"schema_version":"1.0","monitor_id":"shop.production","target":"https://shop.test","authorization_confirmed":True,"max_requests":1,"delay_seconds":1}),encoding="utf-8")

    class FakeScanner:
        async def run(self, _request):
            return current

    monkeypatch.setattr(cli, "PassiveScanner", FakeScanner)
    monkeypatch.setattr(cli, "get_previous_real_audit", lambda _audit: previous)
    monkeypatch.setattr(cli, "save_report", lambda _audit: ("report.html", "a" * 64))
    monkeypatch.setattr(cli, "save_audit", lambda _audit: None)

    code = cli.main(["monitor", "run", "--config", str(config), "--output", str(output)])

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert code == cli.EXIT_OK
    assert payload["state"] == "UNCHANGED"
    assert payload["notification_required"] is False
    assert payload["scan_completeness"] == "COMPLETED"


def test_monitor_completed_meaningful_change_keeps_notification_exit(monkeypatch, tmp_path):
    current = real_monitor_audit("current-changed")
    previous = current.model_copy(deep=True, update={"id": "previous-changed", "findings": []})
    config = tmp_path / "monitor.json"
    output = tmp_path / "monitor-result.json"
    config.write_text(json.dumps({"schema_version":"1.0","monitor_id":"shop.production","target":"https://shop.test","authorization_confirmed":True,"max_requests":1,"delay_seconds":1}),encoding="utf-8")

    class FakeScanner:
        async def run(self, _request):
            return current

    monkeypatch.setattr(cli, "PassiveScanner", FakeScanner)
    monkeypatch.setattr(cli, "get_previous_real_audit", lambda _audit: previous)
    monkeypatch.setattr(cli, "save_report", lambda _audit: ("report.html", "a" * 64))
    monkeypatch.setattr(cli, "save_audit", lambda _audit: None)

    code = cli.main(["monitor", "run", "--config", str(config), "--output", str(output)])

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert code == cli.EXIT_MEANINGFUL_CHANGE
    assert payload["state"] == "CHANGED"
    assert payload["notification_required"] is True
    assert payload["scan_completeness"] == "COMPLETED"


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
    manifest_path = advisories / "snapshot-manifest.json"
    manifest_path.write_text(
        json.dumps(build_advisory_manifest(advisories), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "snapshot-private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path = tmp_path / "snapshot-public.pem"
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    envelope = sign_manifest(manifest_path, private_path)
    (advisories / "snapshot-manifest.sig.json").write_text(
        json.dumps(envelope.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
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
            "--public-key",
            str(public_path),
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
