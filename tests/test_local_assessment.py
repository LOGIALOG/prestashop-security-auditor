import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.app.advisories import build_advisory_manifest
from backend.app.local_assessment import assess_local_source, render_assessment_cyclonedx, render_assessment_sarif
from backend.app.manifest_signing import sign_manifest


ROOT = Path(__file__).parents[1]


def advisory_snapshot(destination: Path) -> tuple[Path, Path]:
    destination.mkdir()
    for name in ("ybc_blog.json", "prestashop-core-8.2.8.json"):
        (destination / name).write_bytes((ROOT / "advisories" / name).read_bytes())
    manifest = build_advisory_manifest(destination)
    manifest_path = destination / "snapshot-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    private_key = Ed25519PrivateKey.generate()
    private_path = destination / "signing-private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path = destination / "signing-public.pem"
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    envelope = sign_manifest(manifest_path, private_path)
    (destination / "snapshot-manifest.sig.json").write_text(
        json.dumps(envelope.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return destination, public_path


def source_tree(destination: Path, module_version: str | None = "3.3.8") -> Path:
    core = destination / "config"
    module = destination / "modules" / "ybc_blog"
    core.mkdir(parents=True)
    module.mkdir(parents=True)
    (core / "settings.inc.php").write_text("<?php define('_PS_VERSION_', '8.2.7');", encoding="utf-8")
    if module_version is not None:
        (module / "config.xml").write_text(f"<module><version><![CDATA[{module_version}]]></version></module>", encoding="utf-8")
    return destination


def test_local_assessment_correlates_trusted_versions_without_executing_code(tmp_path):
    advisories, public_key = advisory_snapshot(tmp_path / "advisories")
    assessment = assess_local_source(source_tree(tmp_path / "shop"), advisories, public_key)

    assert assessment.network_access is False
    assert assessment.executed_source_code is False
    assert assessment.affected_count == 1
    match = assessment.advisory_matches[0]
    assert match.status == "AFFECTED"
    assert match.cve == "CVE-2023-43979"
    assert match.evidence_path == "modules/ybc_blog/config.xml"
    assert len(match.evidence_sha256) == 64
    assert assessment.core_maintenance[0].status == "UPDATE_RECOMMENDED"
    assert len(assessment.advisory_snapshot_sha256) == 64
    assert str(tmp_path) not in assessment.model_dump_json()


def test_local_assessment_exports_sarif_and_cyclonedx_provenance(tmp_path):
    advisories, public_key = advisory_snapshot(tmp_path / "advisories")
    assessment = assess_local_source(source_tree(tmp_path / "shop"), advisories, public_key)

    sarif = render_assessment_sarif(assessment)
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "modules/ybc_blog/config.xml"
    assert len(result["properties"]["evidenceSha256"]) == 64
    bom = render_assessment_cyclonedx(assessment)
    vulnerability = bom["vulnerabilities"][0]
    assert vulnerability["id"] == "CVE-2023-43979"
    assert vulnerability["analysis"]["state"] == "in_triage"
    assert vulnerability["affects"][0]["ref"] == bom["components"][1]["bom-ref"]


def test_local_assessment_distinguishes_fixed_and_unknown_versions(tmp_path):
    fixed_advisories, fixed_key = advisory_snapshot(tmp_path / "fixed-advisories")
    unknown_advisories, unknown_key = advisory_snapshot(tmp_path / "unknown-advisories")
    fixed = assess_local_source(source_tree(tmp_path / "fixed", "4.4.0"), fixed_advisories, fixed_key)
    unknown = assess_local_source(source_tree(tmp_path / "unknown", None), unknown_advisories, unknown_key)

    assert fixed.advisory_matches[0].status == "NOT_AFFECTED"
    assert unknown.advisory_matches[0].status == "INDETERMINATE"
    assert unknown.affected_count == 0


def test_local_assessment_rejects_tampered_advisory_snapshot(tmp_path):
    advisories, public_key = advisory_snapshot(tmp_path / "advisories")
    advisory = advisories / "ybc_blog.json"
    advisory.write_text(advisory.read_text(encoding="utf-8").replace("lecture ou altération", "lecture et altération"), encoding="utf-8")

    with pytest.raises(ValueError, match="manifest advisory"):
        assess_local_source(source_tree(tmp_path / "shop"), advisories, public_key)


def test_local_assessment_rejects_unsigned_advisory_snapshot(tmp_path):
    advisories, public_key = advisory_snapshot(tmp_path / "advisories")
    (advisories / "snapshot-manifest.sig.json").unlink()

    with pytest.raises(ValueError):
        assess_local_source(source_tree(tmp_path / "shop"), advisories, public_key)
