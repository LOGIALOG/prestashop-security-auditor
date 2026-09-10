from datetime import datetime, timezone
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.app.models import AuditResult, Evidence, Finding, Status
from backend.app.report import render_report
from backend.app.report_profile import ReportProfile


def test_report_displays_requires_access_and_disclaimer():
    now=datetime.now(timezone.utc)
    evidence=Evidence(url="https://shop.test/",evidence_type="active_module",excerpt="/modules/ybc_blog/",response_sha256="a"*64,confidence="high",detection_method="module_path")
    audit=AuditResult(is_demo=False,target="https://shop.test",id="x",domain="shop.test",started_at=now,completed_at=now,request_count=2,scope=[],headers={},cookies=[],findings=[Finding(subject="ybc_blog",status=Status.REQUIRES_ACCESS,interpretation="Version inconnue",business_risk="À vérifier",remediation="Confirmer",evidence=[evidence])])
    html,digest=render_report(audit)
    assert "REQUIRES_ACCESS" in html
    assert "ne constitue pas une preuve" in html
    assert len(digest)==64


def test_demo_report_contains_watermark():
    data=json.loads((Path(__file__).parents[1]/"backend/fixtures/demo-audit.json").read_text(encoding="utf-8"))
    html,_=render_report(AuditResult.model_validate(data))
    assert "DONNÉES FICTIVES — MODE DÉMONSTRATION" in html
    assert "demo.local" in html
    assert "data:image/png;base64," in html
    assert "class='logo default-logo'" in html
    assert "<link rel='icon' type='image/png' href='data:image/png;base64," in html
    assert "--primary:#0b6ffb" in html
    assert "--accent:#45b800" in html


def test_white_label_profile_keeps_logialog_provenance_in_metadata():
    data=json.loads((Path(__file__).parents[1]/"backend/fixtures/demo-audit.json").read_text(encoding="utf-8"))
    profile=ReportProfile(brand_name="Agence Exemple",report_title="Rapport de sécurité",primary_color="#123456",accent_color="#abcdef",contact_url="https://agency.example/contact")
    html,_=render_report(AuditResult.model_validate(data),profile)
    assert "Agence Exemple" in html
    assert "--primary:#123456" in html
    assert "name='generator' content='LOGIALOG PrestaShop Security Auditor 1.4.0'" in html
    assert "name='logialog:report-profile-schema' content='1.0'" in html
    assert "DONNÉES FICTIVES — MODE DÉMONSTRATION" in html


def test_report_profile_rejects_html_and_css_injection():
    with pytest.raises(ValidationError):
        ReportProfile(brand_name="<script>alert(1)</script>")
    with pytest.raises(ValidationError):
        ReportProfile(primary_color="red;display:none")
    with pytest.raises(ValidationError):
        ReportProfile(logo_data_uri="data:image/svg+xml;base64,PHN2Zz4=")
    with pytest.raises(ValidationError):
        ReportProfile.model_validate({"brand_name":"Agency","unknown":"value"})


def test_real_finding_without_evidence_is_refused():
    with pytest.raises(ValidationError, match="preuve"):
        Finding(subject="x",status=Status.REQUIRES_ACCESS,interpretation="x",business_risk="x",remediation="x")
