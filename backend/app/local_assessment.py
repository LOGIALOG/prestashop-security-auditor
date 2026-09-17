from __future__ import annotations

from pathlib import Path
from typing import Literal

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field

from .advisories import CoreSecurityRelease, ModuleAdvisory, advisory_snapshot_identity, load_advisories
from .source_scan import LocalComponent, LocalSourceInventory, component_bom_ref, render_cyclonedx, scan_local_source


class LocalAdvisoryMatch(BaseModel):
    component_ref: str
    component_name: str
    component_kind: str
    detected_version: str | None = None
    evidence_path: str | None = None
    evidence_sha256: str | None = None
    detection_method: str
    advisory_record_id: str
    cve: str
    cvss: str
    affected_max: str
    fixed_version: str
    source: str
    source_authority: str
    status: Literal["AFFECTED", "NOT_AFFECTED", "INDETERMINATE"]
    interpretation: str


class LocalCoreMaintenance(BaseModel):
    component_ref: str
    detected_version: str | None = None
    evidence_path: str | None = None
    evidence_sha256: str | None = None
    advisory_record_id: str
    security_release: str
    source: str
    source_authority: str
    status: Literal["UPDATE_RECOMMENDED", "CURRENT_OR_NEWER", "INDETERMINATE"]
    interpretation: str


class LocalSourceAssessment(BaseModel):
    format: Literal["logialog-local-assessment"] = "logialog-local-assessment"
    format_version: Literal["1.0"] = "1.0"
    inventory: LocalSourceInventory
    advisory_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    advisory_matches: list[LocalAdvisoryMatch] = Field(default_factory=list)
    core_maintenance: list[LocalCoreMaintenance] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    network_access: Literal[False] = False
    executed_source_code: Literal[False] = False

    @property
    def affected_count(self) -> int:
        return sum(match.status == "AFFECTED" for match in self.advisory_matches)


def _module_match(component: LocalComponent, advisory: ModuleAdvisory) -> LocalAdvisoryMatch:
    status: Literal["AFFECTED", "NOT_AFFECTED", "INDETERMINATE"] = "INDETERMINATE"
    if component.version is None:
        interpretation = "Module présent, mais version locale non détectée; aucune conclusion de vulnérabilité n’est possible."
    elif component.evidence_sha256 is None:
        interpretation = "Version détectée sans hash complet du fichier de preuve; validation manuelle requise."
    else:
        try:
            detected = Version(component.version)
            affected_max = Version(advisory.affected_max)
            fixed = Version(advisory.fixed_version)
            if detected <= affected_max:
                status = "AFFECTED"
                interpretation = f"La version locale {component.version} est comprise dans la plage affectée publiée, jusqu’à {advisory.affected_max}."
            elif detected >= fixed:
                status = "NOT_AFFECTED"
                interpretation = f"La version locale {component.version} atteint ou dépasse la version corrigée publiée {advisory.fixed_version}."
            else:
                interpretation = f"La version locale {component.version} se situe entre la borne affectée et la version corrigée publiées; revue manuelle requise."
        except InvalidVersion:
            interpretation = f"La version locale {component.version!r} n’est pas normalisable; revue manuelle requise."
    return LocalAdvisoryMatch(
        component_ref=component_bom_ref(component),
        component_name=component.name,
        component_kind=component.kind,
        detected_version=component.version,
        evidence_path=component.evidence_path,
        evidence_sha256=component.evidence_sha256,
        detection_method=component.detection_method,
        advisory_record_id=advisory.record_id,
        cve=advisory.cve,
        cvss=advisory.cvss,
        affected_max=advisory.affected_max,
        fixed_version=advisory.fixed_version,
        source=str(advisory.source),
        source_authority=advisory.source_authority,
        status=status,
        interpretation=interpretation,
    )


def _core_maintenance(component: LocalComponent | None, advisory: CoreSecurityRelease) -> LocalCoreMaintenance:
    if component is None or component.version is None:
        status = "INDETERMINATE"
        interpretation = "Version locale du cœur non détectée; la release de sécurité doit être vérifiée manuellement."
    elif component.evidence_sha256 is None:
        status = "INDETERMINATE"
        interpretation = "Version du cœur détectée sans hash complet du fichier de preuve; validation manuelle requise."
    else:
        try:
            if Version(component.version) < Version(advisory.release):
                status = "UPDATE_RECOMMENDED"
                interpretation = f"Le cœur local {component.version} précède la release de sécurité {advisory.release}; planifier une mise à niveau compatible."
            else:
                status = "CURRENT_OR_NEWER"
                interpretation = f"Le cœur local {component.version} atteint ou dépasse la release de sécurité {advisory.release}."
        except InvalidVersion:
            status = "INDETERMINATE"
            interpretation = f"La version locale {component.version!r} n’est pas normalisable; revue manuelle requise."
    return LocalCoreMaintenance(
        component_ref=component_bom_ref(component) if component else "urn:logialog:component:prestashop-core:unknown",
        detected_version=component.version if component else None,
        evidence_path=component.evidence_path if component else None,
        evidence_sha256=component.evidence_sha256 if component else None,
        advisory_record_id=advisory.record_id,
        security_release=advisory.release,
        source=str(advisory.source),
        source_authority=advisory.source_authority,
        status=status,
        interpretation=interpretation,
    )


def assess_local_source(source: Path, advisory_directory: Path | None = None, public_key: Path | None = None) -> LocalSourceAssessment:
    inventory = scan_local_source(source)
    identity = advisory_snapshot_identity(advisory_directory, public_key)
    documents = load_advisories(advisory_directory)
    modules = {component.name.casefold(): component for component in inventory.components if component.kind == "prestashop-module"}
    core = next((component for component in inventory.components if component.kind == "prestashop-core"), None)
    matches: list[LocalAdvisoryMatch] = []
    maintenance: list[LocalCoreMaintenance] = []
    for payload in documents:
        if "module" in payload:
            advisory = ModuleAdvisory.model_validate(payload)
            component = modules.get(advisory.module.casefold())
            if component:
                matches.append(_module_match(component, advisory))
        else:
            maintenance.append(_core_maintenance(core, CoreSecurityRelease.model_validate(payload)))
    warnings = list(inventory.warnings)
    warnings.extend(match.interpretation for match in matches if match.status == "INDETERMINATE")
    return LocalSourceAssessment(
        inventory=inventory,
        advisory_snapshot_sha256=identity.snapshot_sha256,
        advisory_matches=matches,
        core_maintenance=maintenance,
        warnings=warnings,
    )


def render_assessment_cyclonedx(assessment: LocalSourceAssessment) -> dict:
    bom = render_cyclonedx(assessment.inventory)
    vulnerabilities = []
    for match in assessment.advisory_matches:
        severity = match.cvss.split()[-1].casefold() if match.cvss else "unknown"
        score_text = match.cvss.split()[0] if match.cvss else ""
        rating: dict[str, object] = {"severity": severity, "method": "CVSSv3"}
        try:
            rating["score"] = float(score_text)
        except ValueError:
            pass
        properties = [
            {"name": "logialog:local-status", "value": match.status},
            {"name": "logialog:advisory-record-id", "value": match.advisory_record_id},
            {"name": "logialog:detection-method", "value": match.detection_method},
        ]
        if match.evidence_path:
            properties.append({"name": "logialog:evidence-path", "value": match.evidence_path})
        if match.evidence_sha256:
            properties.append({"name": "logialog:evidence-sha256", "value": match.evidence_sha256})
        vulnerabilities.append(
            {
                "id": match.cve,
                "source": {"name": match.source_authority, "url": match.source},
                "ratings": [rating],
                "analysis": {"state": "not_affected" if match.status == "NOT_AFFECTED" else "in_triage", "detail": match.interpretation},
                "affects": [{"ref": match.component_ref}],
                "properties": properties,
            }
        )
    bom["vulnerabilities"] = vulnerabilities
    bom["metadata"]["properties"] = [{"name": "logialog:advisory-snapshot-sha256", "value": assessment.advisory_snapshot_sha256}]
    return bom


def render_assessment_sarif(assessment: LocalSourceAssessment) -> dict:
    rules = []
    results = []
    for match in assessment.advisory_matches:
        rules.append({"id": match.advisory_record_id, "name": match.cve, "helpUri": match.source, "shortDescription": {"text": f"{match.component_name}: {match.cve}"}})
        level = "error" if match.status == "AFFECTED" else "none" if match.status == "NOT_AFFECTED" else "warning"
        location = match.evidence_path or match.component_name
        results.append(
            {
                "ruleId": match.advisory_record_id,
                "level": level,
                "message": {"text": match.interpretation},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": location}}}],
                "properties": {
                    "localStatus": match.status,
                    "detectedVersion": match.detected_version,
                    "evidenceSha256": match.evidence_sha256,
                    "detectionMethod": match.detection_method,
                    "advisorySnapshotSha256": assessment.advisory_snapshot_sha256,
                    "networkAccess": False,
                    "executedSourceCode": False,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "LOGIALOG PrestaShop Security Auditor", "informationUri": "https://github.com/LOGIALOG/prestashop-security-auditor", "rules": rules}}, "results": results, "properties": {"advisorySnapshotSha256": assessment.advisory_snapshot_sha256, "localOnly": True}}],
    }
