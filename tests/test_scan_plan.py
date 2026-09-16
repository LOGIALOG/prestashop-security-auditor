import asyncio
import json

from backend.app import cli
from backend.app.models import AuditRequest
from backend.app.scan_plan import build_scan_plan


def test_scan_plan_is_deterministic_and_network_free(monkeypatch):
    def reject_network(*_args, **_kwargs):
        raise AssertionError("scan planning must not access the network")

    monkeypatch.setattr("httpx.Client", reject_network)
    monkeypatch.setattr("httpx.AsyncClient", reject_network)
    request = AuditRequest(
        target="https://shop.test/store",
        authorization_confirmed=True,
        public_pages=["https://shop.test/contact"],
        max_requests=7,
        delay_seconds=2,
    )

    payload = build_scan_plan(request).model_dump(mode="json")

    assert payload["target_origin"] == "https://shop.test"
    assert payload["fixed_requests"] == [
        "https://shop.test/store/",
        "https://shop.test/contact",
        "https://shop.test/store/robots.txt",
    ]
    assert payload["required_requests"] == ["https://shop.test/store/", "https://shop.test/contact"]
    assert payload["optional_requests"] == ["https://shop.test/store/robots.txt"]
    assert payload["maximum_requests"] == 7
    assert payload["network_access"] is False
    assert payload["methods"] == ["GET"]


def test_scan_plan_rejects_cross_origin_public_pages():
    request = AuditRequest(
        target="https://shop.test",
        authorization_confirmed=True,
        public_pages=["https://outside.test/contact"],
    )

    try:
        build_scan_plan(request)
    except ValueError as exc:
        assert "domaine autorisé" in str(exc)
    else:
        raise AssertionError("cross-origin page should be rejected")


def test_real_scanner_rejects_cross_origin_before_dns(monkeypatch):
    from backend.app.scanner import PassiveScanner

    def reject_dns(*_args, **_kwargs):
        raise AssertionError("DNS must not run before scope validation")

    monkeypatch.setattr("backend.app.scanner.reject_private_target", reject_dns)
    request = AuditRequest(
        target="https://shop.test",
        authorization_confirmed=True,
        public_pages=["https://outside.test/contact"],
    )

    try:
        asyncio.run(PassiveScanner().run(request))
    except ValueError as exc:
        assert "domaine autorisé" in str(exc)
    else:
        raise AssertionError("cross-origin page should be rejected")


def test_plan_cli_requires_authorization_and_writes_contract(tmp_path, capsys):
    assert cli.main(["plan", "https://shop.test"]) == cli.EXIT_INVALID_INPUT
    assert "autorisation explicite" in capsys.readouterr().err
    output = tmp_path / "plan.json"

    code = cli.main(
        [
            "plan",
            "https://shop.test",
            "--authorized",
            "--public-page",
            "https://shop.test/contact",
            "--max-requests",
            "5",
            "--output",
            str(output),
        ]
    )

    assert code == cli.EXIT_OK
    assert json.loads(output.read_text(encoding="utf-8"))["format"] == "logialog-scan-plan"
