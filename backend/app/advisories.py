from __future__ import annotations

import json
import hashlib
import re
from datetime import date
from pathlib import Path
from typing import Literal

from packaging.version import Version
from pydantic import BaseModel, ConfigDict, HttpUrl, TypeAdapter, field_validator

from .extractors import Extracted
from .models import Finding, Status

ROOT = Path(__file__).resolve().parents[2]


class ModuleAdvisory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    record_id: str
    module: str
    cve: str
    type: str
    cwe: str
    cvss: str
    affected_max: str
    fixed_version: str
    authentication_required: bool
    business_risk: str
    source: HttpUrl
    source_authority: str
    published: date
    retrieved_at: date

    @field_validator("cve")
    @classmethod
    def valid_cve(cls, value: str) -> str:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
            raise ValueError("Identifiant CVE invalide")
        return value


class CoreSecurityRelease(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    record_id: str
    product: Literal["PrestaShop Core"]
    release: str
    published: date
    retrieved_at: date
    summary: str
    source: HttpUrl
    source_authority: str


AdvisoryDocument = ModuleAdvisory | CoreSecurityRelease
ADVISORY_ADAPTER = TypeAdapter(AdvisoryDocument)
MANIFEST_NAME = "snapshot-manifest.json"


def advisory_paths(directory: Path) -> list[Path]:
    return [path for path in sorted(directory.glob("*.json")) if path.name != MANIFEST_NAME]


def validate_advisory_files(directory: Path | None = None) -> list[Path]:
    base = directory or ROOT / "advisories"
    paths = advisory_paths(base)
    if not paths:
        raise ValueError(f"Aucun advisory JSON trouvé dans {base}")
    record_ids: set[str] = set()
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        document = ADVISORY_ADAPTER.validate_python(payload)
        if document.record_id in record_ids:
            raise ValueError(f"{path.name}: record_id dupliqué: {document.record_id}")
        record_ids.add(document.record_id)
        if isinstance(payload, dict) and payload.get("module"):
            Version(payload["affected_max"])
            Version(payload["fixed_version"])
            if Version(payload["affected_max"]) >= Version(payload["fixed_version"]):
                raise ValueError(f"{path.name}: fixed_version doit être supérieure à affected_max")
    return paths


def build_advisory_manifest(directory: Path | None = None) -> dict:
    base = directory or ROOT / "advisories"
    paths = validate_advisory_files(base)
    records = []
    retrieved_dates: list[str] = []
    for path in paths:
        raw = path.read_bytes()
        payload = json.loads(raw)
        retrieved_dates.append(payload["retrieved_at"])
        records.append(
            {
                "file": path.name,
                "record_id": payload["record_id"],
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return {
        "manifest_version": 1,
        "advisory_schema_version": 1,
        "snapshot_date": max(retrieved_dates),
        "record_count": len(records),
        "records": records,
    }


def validate_advisory_manifest(directory: Path | None = None) -> Path:
    base = directory or ROOT / "advisories"
    manifest_path = base / MANIFEST_NAME
    if not manifest_path.exists():
        raise ValueError(f"Manifest absent: {manifest_path}")
    expected = build_advisory_manifest(base)
    actual = json.loads(manifest_path.read_text(encoding="utf-8"))
    if actual != expected:
        raise ValueError("Le manifest advisory ne correspond pas aux fichiers courants")
    return manifest_path


def load_advisories(directory: Path | None = None) -> list[dict]:
    paths = validate_advisory_files(directory)
    return [json.loads(path.read_text(encoding="utf-8")) for path in paths]


def correlate(extracted: list[Extracted]) -> list[Finding]:
    advisories = {item["module"]: item for item in load_advisories() if item.get("module")}
    grouped: dict[str, list[Extracted]] = {}
    for item in extracted:
        grouped.setdefault(item.name, []).append(item)
    findings: list[Finding] = []
    for name, traces in grouped.items():
        versions = [t.version for t in traces if t.version]
        evidence = [t.evidence for t in traces]
        only_assets = all(t.kind == "asset_module" for t in traces)
        advisory = advisories.get(name)
        if only_assets and name == "newsletterpro" and versions:
            findings.append(Finding(subject=name, status=Status.REQUIRES_ACCESS, severity="À vérifier", version=versions[0], interpretation=f"NewsletterPro {versions[0]} détecté dans un bundle frontend. Cette valeur ne confirme pas la version PHP installée et aucune vulnérabilité n'est confirmée.", business_risk="Provenance et version serveur inconnues.", remediation="Comparer les fichiers du module avec une archive officielle.", access_required="Accès serveur ou Back Office", evidence=evidence))
        elif only_assets:
            findings.append(Finding(subject=name, status=Status.ASSET_RESIDUE, interpretation="Nom trouvé uniquement dans un asset CSS/JS compilé; présence active non démontrée.", business_risk="Aucun risque précis confirmé.", remediation="Vérifier les fichiers déployés et la liste réelle des modules.", evidence=evidence))
        elif advisory and versions:
            version = versions[0]
            affected = Version(version) <= Version(advisory["affected_max"])
            fixed = Version(version) >= Version(advisory["fixed_version"])
            status = Status.CONFIRMED if affected else Status.NOT_AFFECTED if fixed else Status.REQUIRES_ACCESS
            interpretation = (f"Version fiable {version} comprise dans la plage affectée documentée." if affected else f"Non affecté par {advisory['cve']} selon la version détectée. Cela ne garantit pas l’absence d’autres vulnérabilités." if fixed else f"Version {version} hors de la plage affectée publiée mais antérieure à la version corrigée; vérification manuelle requise.")
            findings.append(Finding(subject=name, status=status, severity="Critical 9.8" if affected else "À vérifier" if status == Status.REQUIRES_ACCESS else "Information", version=version, cve=advisory["cve"], interpretation=interpretation, business_risk=advisory["business_risk"], remediation=f"Mettre à jour vers {advisory['fixed_version']} ou une version ultérieure officielle.", source=advisory["source"], access_required="Accès serveur ou Back Office" if status == Status.REQUIRES_ACCESS else None, evidence=evidence))
        elif advisory:
            findings.append(Finding(subject=name, status=Status.REQUIRES_ACCESS, severity="À vérifier", cve=advisory["cve"], interpretation="Le module ybc_blog est publiquement détectable. Sa version installée n’a pas pu être confirmée. La présence du module ne prouve pas que CVE-2023-43979 est exploitable.", business_risk=advisory["business_risk"], remediation="Confirmer la version depuis le serveur ou le Back Office avant décision.", source=advisory["source"], access_required="Accès serveur ou Back Office", evidence=evidence))
        elif name == "prestashop" and versions:
            findings.append(Finding(subject=name, status=Status.REQUIRES_ACCESS, version=versions[0], interpretation=f"PrestaShop {versions[0]} probable — confiance moyenne — confirmation par accès serveur ou Back Office requise.", business_risk="La maintenance de sécurité du cœur doit être confirmée.", remediation="Comparer la version réelle à la dernière version de sécurité compatible.", access_required="Accès serveur ou Back Office", evidence=evidence))
        else:
            findings.append(Finding(subject=name, status=Status.REQUIRES_ACCESS, interpretation="Version ancienne ou provenance non vérifiée — revue manuelle du code requise — aucune vulnérabilité précise confirmée par cet outil.", business_risk="Risque indéterminé sans revue de provenance et de version.", remediation="Vérifier la provenance, la version et le code du module.", access_required="Accès serveur ou Back Office", evidence=evidence))
    return findings
