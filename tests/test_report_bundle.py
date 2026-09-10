import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.app.models import AuditResult
from backend.app.report_bundle import BUNDLE_FILES, MANIFEST_PATH, SIGNATURE_PATH, create_signed_bundle, verify_signed_bundle
from backend.app.report_profile import ReportProfile


def demo_audit() -> AuditResult:
    fixture = Path(__file__).parents[1] / "backend" / "fixtures" / "demo-audit.json"
    return AuditResult.model_validate(json.loads(fixture.read_text(encoding="utf-8")))


def write_keys(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    return private_path,public_path


def test_signed_bundle_round_trip_is_portable_and_deterministic(tmp_path):
    private,public = write_keys(tmp_path)
    first,second = tmp_path/"first.zip",tmp_path/"second.zip"
    profile = ReportProfile(brand_name="Agency Example",report_title="Security report")

    manifest = create_signed_bundle(demo_audit(),first,private,profile=profile)
    create_signed_bundle(demo_audit(),second,private,profile=profile)
    verified = verify_signed_bundle(first,public)

    assert first.read_bytes() == second.read_bytes()
    assert verified.audit_id == "demo-session"
    assert verified.file_count == 4
    assert manifest.report_profile_schema == "1.0"
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == [*BUNDLE_FILES,MANIFEST_PATH,SIGNATURE_PATH]
        audit = json.loads(archive.read("audit.json"))
        report = archive.read("report.html").decode()
    assert "report_path" not in audit["audit"]
    assert "Agency Example" in report
    assert "DONNÉES FICTIVES — MODE DÉMONSTRATION" in report
    assert "logialog:engine" in report


def test_bundle_verification_rejects_tampered_content(tmp_path):
    private,public = write_keys(tmp_path)
    source,tampered = tmp_path/"source.zip",tmp_path/"tampered.zip"
    create_signed_bundle(demo_audit(),source,private)
    with zipfile.ZipFile(source) as original,zipfile.ZipFile(tampered,"w") as changed:
        for info in original.infolist():
            payload = original.read(info.filename)
            if info.filename == "audit.json":
                payload = payload.replace(b"demo.local",b"evil.test ")
            changed.writestr(info,payload)

    with pytest.raises(ValueError,match="Intégrité invalide"):
        verify_signed_bundle(tampered,public)


def test_bundle_creation_refuses_overwrite(tmp_path):
    private,_ = write_keys(tmp_path)
    destination = tmp_path/"bundle.zip"
    create_signed_bundle(demo_audit(),destination,private)
    with pytest.raises(ValueError,match="existe déjà"):
        create_signed_bundle(demo_audit(),destination,private)


def test_bundle_verification_rejects_non_zip_input(tmp_path):
    _,public=write_keys(tmp_path)
    invalid=tmp_path/"invalid.zip"
    invalid.write_bytes(b"not a zip")
    with pytest.raises(ValueError,match="ZIP illisible"):
        verify_signed_bundle(invalid,public)
