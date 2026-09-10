import json
from pathlib import Path

import pytest

from backend.app.advisories import correlate
from backend.app.extractors import extract_html
from backend.app.models import Status
from backend.app.redaction import redact_text, redact_url

FIXTURES = Path(__file__).parent / "fixtures"


def test_detects_module_paths_route_ps_version_and_module_version():
    body = (FIXTURES / "modules.html").read_text()
    items = extract_html("https://shop.test/", body)
    names = {item.name for item in items}
    assert {"ybc_blog", "newsletterpro", "blockwishlist", "prestashop"} <= names
    assert next(i for i in items if i.name == "prestashop").version == "8.2.7"
    assert next(i for i in items if i.name == "ybc_blog").version == "3.3.8"


def test_active_module_and_css_residue_are_distinct():
    active = extract_html("https://shop.test/", '<img src="/modules/ybc_blog/a.png">')
    residue = extract_html("https://shop.test/app.css", '.x{background:url(/modules/productcomments/a.png)}', "text/css")
    assert active[0].kind == "active_module"
    assert residue[0].kind == "asset_module"
    assert correlate(residue)[0].status == Status.ASSET_RESIDUE


def test_compiled_asset_identifier_is_residue():
    body = (FIXTURES / "bundle.css").read_text()
    findings = correlate(extract_html("https://shop.test/app.css", body, "text/css"))
    assert {f.subject for f in findings} == {"productcomments", "codfee", "smartblog", "leopartsfilter"}
    assert all(f.status == Status.ASSET_RESIDUE for f in findings)


def test_redaction_masks_sensitive_values():
    text = redact_text("token=secret123 test@example.com +212 612 345 678 Cookie: PHPSESSID=abc")
    assert "secret123" not in text and "test@example.com" not in text and "612 345" not in text and "PHPSESSID=abc" not in text
    assert "abc" not in redact_url("https://shop.test/a?token=abc")


def test_vulnerable_version_matches_confirmed():
    items = extract_html("https://shop.test/", '<!-- version: 3.3.8 --><img src="/modules/ybc_blog/a.png">')
    finding = correlate(items)[0]
    assert finding.status == Status.CONFIRMED
    assert finding.cve == "CVE-2023-43979"


def test_unknown_active_version_requires_access():
    finding = correlate(extract_html("https://shop.test/", '<img src="/modules/ybc_blog/a.png">'))[0]
    assert finding.status == Status.REQUIRES_ACCESS
    assert finding.severity == "À vérifier"
    assert "ne prouve pas" in finding.interpretation


def test_ps_fingerprint_is_probable_not_confirmed():
    finding = correlate(extract_html("https://shop.test/", '<body class="ps_827">'))[0]
    assert finding.status == Status.REQUIRES_ACCESS
    assert finding.version == "8.2.7"
    assert finding.evidence[0].confidence == "medium"


def test_newsletter_bundle_version_requires_server_access():
    body = 'newsletterpro version: 4.0.1'
    finding = correlate(extract_html("https://shop.test/app.js", body, "application/javascript"))[0]
    assert finding.status == Status.REQUIRES_ACCESS
    assert finding.version == "4.0.1"
    assert finding.evidence[0].confidence == "medium"


@pytest.mark.parametrize("case", json.loads((FIXTURES / "extractor-cases.json").read_text(encoding="utf-8")), ids=lambda case: case["name"])
def test_extractor_positive_and_negative_corpus(case):
    items = extract_html("https://shop.test/asset.css" if case["content_type"] == "text/css" else "https://shop.test/", case["body"], case["content_type"])
    observed = {(item.name, item.evidence.detection_method) for item in items}
    assert observed == {tuple(expected) for expected in case["expected"]}


def test_version_is_not_attributed_across_another_module_signal():
    body = '<img src="/modules/ybc_blog/logo.png"><div data-module-name="blockwishlist"></div><!-- blockwishlist version: 2.1.0 -->'
    items = extract_html("https://shop.test/", body)
    assert next(item for item in items if item.name == "ybc_blog").version is None
    assert next(item for item in items if item.name == "blockwishlist").version == "2.1.0"
