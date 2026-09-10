from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .exports import render_json_export, render_sarif
from .manifest_signing import ManifestSignature, sign_payload, verify_payload_signature
from .models import AuditResult
from .report import DEMO_WATERMARK, ENGINE_NAME, ENGINE_VERSION, render_report
from .report_profile import ReportProfile

ROOT = Path(__file__).resolve().parents[2]
BUNDLE_FILES = ("advisory-snapshot.json", "audit.json", "audit.sarif", "report.html")
MANIFEST_PATH = "bundle-manifest.json"
SIGNATURE_PATH = "bundle-manifest.sig.json"
MAX_BUNDLE_BYTES = 25 * 1024 * 1024


class BundleFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0, le=MAX_BUNDLE_BYTES)

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if value not in BUNDLE_FILES or path.is_absolute() or ".." in path.parts:
            raise ValueError("Chemin de bundle interdit")
        return value


class BundleManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    audit_id: str
    demo: bool
    created_at: datetime
    engine: Literal[ENGINE_NAME] = ENGINE_NAME
    engine_version: Literal[ENGINE_VERSION] = ENGINE_VERSION
    report_profile_schema: Literal["1.0"] = "1.0"
    report_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: list[BundleFile]

    @model_validator(mode="after")
    def complete_file_set(self) -> "BundleManifest":
        paths = [item.path for item in self.files]
        if paths != list(BUNDLE_FILES):
            raise ValueError("Le manifest doit contenir exactement les fichiers attendus dans l’ordre canonique")
        if sum(item.size for item in self.files) > MAX_BUNDLE_BYTES:
            raise ValueError("Le contenu du bundle dépasse 25 Mio")
        return self


class BundleVerification(BaseModel):
    schema_version: Literal[1] = 1
    audit_id: str
    demo: bool
    key_id: str
    file_count: int
    manifest_sha256: str


def _json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _zip_timestamp(value: datetime) -> tuple[int, int, int, int, int, int]:
    utc = value.astimezone(timezone.utc)
    year = min(2107, max(1980, utc.year))
    return year, utc.month, utc.day, utc.hour, utc.minute, utc.second - utc.second % 2


def _write_entry(archive: zipfile.ZipFile, path: str, content: bytes, timestamp: tuple[int, int, int, int, int, int]) -> None:
    info = zipfile.ZipInfo(path, timestamp)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    info.flag_bits |= 0x800
    archive.writestr(info, content)


def create_signed_bundle(
    audit: AuditResult,
    destination: Path,
    private_key: Path,
    password: bytes | None = None,
    profile: ReportProfile | None = None,
) -> BundleManifest:
    if destination.exists():
        raise ValueError(f"Le bundle existe déjà: {destination}")
    profile = profile or ReportProfile()
    report_html, report_digest = render_report(audit, profile)
    bundle_audit = audit.model_copy(deep=True)
    bundle_audit.report_path = None
    bundle_audit.report_sha256 = report_digest
    advisory_manifest = (ROOT / "advisories" / "snapshot-manifest.json").read_bytes()
    files = {
        "advisory-snapshot.json": advisory_manifest,
        "audit.json": _json_bytes(render_json_export(bundle_audit)),
        "audit.sarif": _json_bytes(render_sarif(bundle_audit)),
        "report.html": report_html.encode("utf-8"),
    }
    manifest = BundleManifest(
        audit_id=audit.id,
        demo=audit.is_demo,
        created_at=audit.completed_at,
        report_profile_schema=profile.schema_version,
        report_canonical_sha256=report_digest,
        files=[BundleFile(path=path,sha256=hashlib.sha256(files[path]).hexdigest(),size=len(files[path])) for path in BUNDLE_FILES],
    )
    manifest_bytes = _json_bytes(manifest.model_dump(mode="json"))
    signature = sign_payload(manifest_bytes, private_key, password)
    signature_bytes = _json_bytes(signature.model_dump(mode="json"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    timestamp = _zip_timestamp(audit.completed_at)
    with zipfile.ZipFile(destination, "x") as archive:
        for path in BUNDLE_FILES:
            _write_entry(archive, path, files[path], timestamp)
        _write_entry(archive, MANIFEST_PATH, manifest_bytes, timestamp)
        _write_entry(archive, SIGNATURE_PATH, signature_bytes, timestamp)
    return manifest


def verify_signed_bundle(bundle: Path, public_key: Path) -> BundleVerification:
    if not bundle.is_file():
        raise ValueError(f"Bundle introuvable: {bundle}")
    try:
        with zipfile.ZipFile(bundle) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            expected = [*BUNDLE_FILES, MANIFEST_PATH, SIGNATURE_PATH]
            if names != expected or len(names) != len(set(names)):
                raise ValueError("Structure ou ordre du bundle invalide")
            if any(info.flag_bits & 0x1 for info in infos):
                raise ValueError("Les entrées ZIP chiffrées ne sont pas acceptées")
            if sum(info.file_size for info in infos) > MAX_BUNDLE_BYTES:
                raise ValueError("Le bundle dépasse 25 Mio décompressés")
            if archive.testzip() is not None:
                raise ValueError("Le bundle ZIP est corrompu")
            content = {name: archive.read(name) for name in names}
    except (zipfile.BadZipFile,RuntimeError,KeyError) as exc:
        raise ValueError("Bundle ZIP illisible") from exc
    manifest_bytes = content[MANIFEST_PATH]
    manifest = BundleManifest.model_validate_json(manifest_bytes)
    signature = ManifestSignature.model_validate_json(content[SIGNATURE_PATH])
    verified = verify_payload_signature(manifest_bytes, signature, public_key)
    for item in manifest.files:
        payload = content[item.path]
        if len(payload) != item.size or hashlib.sha256(payload).hexdigest() != item.sha256:
            raise ValueError(f"Intégrité invalide pour {item.path}")
    audit_export = json.loads(content["audit.json"])
    if audit_export.get("format") != "logialog-audit" or audit_export.get("audit",{}).get("id") != manifest.audit_id:
        raise ValueError("L’audit JSON ne correspond pas au manifest")
    if bool(audit_export.get("demo")) != manifest.demo:
        raise ValueError("Le mode démo de l’audit ne correspond pas au manifest")
    report = content["report.html"].decode("utf-8")
    if f"name='generator' content='{ENGINE_NAME} {ENGINE_VERSION}'" not in report:
        raise ValueError("La provenance LOGIALOG du rapport est absente")
    if manifest.demo and DEMO_WATERMARK not in report:
        raise ValueError("Le watermark permanent de démonstration est absent")
    return BundleVerification(
        audit_id=manifest.audit_id,
        demo=manifest.demo,
        key_id=verified.key_id,
        file_count=len(manifest.files),
        manifest_sha256=verified.manifest_sha256,
    )
