import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from backend.app.advisories import advisory_snapshot_identity
from backend.app.manifest_signing import verify_manifest_signature
from backend.app.models import AuditResult

ROOT = Path(__file__).resolve().parents[1]
ADVISORIES = ROOT / "advisories"
PUBLIC_KEY = ROOT / "keys" / "logialog-ed25519-public.pem"
MANIFEST = "snapshot-manifest.json"
SIGNATURE = "snapshot-manifest.sig.json"


def copy_advisories(tmp_path: Path) -> Path:
    destination = tmp_path / "advisories"
    shutil.copytree(ADVISORIES, destination)
    return destination


def test_advisory_snapshot_identity_matches_signed_manifest():
    identity = advisory_snapshot_identity()
    envelope = verify_manifest_signature(ADVISORIES / MANIFEST, ADVISORIES / SIGNATURE, PUBLIC_KEY)
    manifest = json.loads((ADVISORIES / MANIFEST).read_text(encoding="utf-8"))

    assert len(identity.snapshot_sha256) == 64
    assert identity.snapshot_sha256 == envelope.manifest_sha256
    assert identity.key_id == envelope.key_id
    assert identity.record_count == manifest["record_count"]
    assert identity.snapshot_date == date.fromisoformat(manifest["snapshot_date"])


def test_advisory_snapshot_identity_rejects_modified_manifest(tmp_path):
    destination = copy_advisories(tmp_path)
    manifest_path = destination / MANIFEST
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["record_count"] = payload["record_count"] + 1
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        advisory_snapshot_identity(destination)


def test_advisory_snapshot_identity_rejects_invalid_signature(tmp_path):
    destination = copy_advisories(tmp_path)
    signature_path = destination / SIGNATURE
    payload = json.loads(signature_path.read_text(encoding="utf-8"))
    payload["signature"] = "AAAA" + payload["signature"][4:]
    signature_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        advisory_snapshot_identity(destination)


def test_advisory_snapshot_identity_rejects_missing_signature(tmp_path):
    destination = copy_advisories(tmp_path)
    (destination / SIGNATURE).unlink()

    with pytest.raises(ValueError):
        advisory_snapshot_identity(destination)


def test_demo_fixture_remains_valid_without_snapshot_fields():
    fixture = json.loads((ROOT / "backend" / "fixtures" / "demo-audit.json").read_text(encoding="utf-8"))

    result = AuditResult.model_validate(fixture)

    assert result.advisory_snapshot_sha256 is None
    assert result.advisory_snapshot_date is None
    assert all(finding.advisory_snapshot_sha256 is None for finding in result.findings)
