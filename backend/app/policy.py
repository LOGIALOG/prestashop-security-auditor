from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import AuditResult, Status

CONFIDENCE_RANK = {"low":0,"medium":1,"high":2}


class StatusLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed: int | None = Field(default=None,ge=0)
    likely: int | None = Field(default=None,ge=0)
    requires_access: int | None = Field(default=None,ge=0)
    asset_residue: int | None = Field(default=None,ge=0)
    not_affected: int | None = Field(default=None,ge=0)
    hardening: int | None = Field(default=None,ge=0)


class PolicyPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    policy_id: str = Field(min_length=3,max_length=64,pattern=r"^[a-z0-9][a-z0-9._-]+$")
    title: str = Field(min_length=1,max_length=120)
    allow_demo: bool = False
    minimum_score: int | None = Field(default=None,ge=0,le=100)
    fail_on_statuses: list[Status] = Field(default_factory=lambda:[Status.CONFIRMED])
    maximum_counts: StatusLimits = Field(default_factory=StatusLimits)
    minimum_evidence_confidence: Literal["low","medium","high"] = "low"
    require_report_hash: bool = True

    @field_validator("title")
    @classmethod
    def safe_title(cls,value:str)->str:
        value=value.strip()
        if not value or any(character in value for character in "<>\r\n"):
            raise ValueError("Titre de policy invalide")
        return value

    @field_validator("fail_on_statuses")
    @classmethod
    def unique_statuses(cls,value:list[Status])->list[Status]:
        if len(value)!=len(set(value)):
            raise ValueError("fail_on_statuses contient un statut dupliqué")
        return value


class PolicyViolation(BaseModel):
    rule: str
    message: str
    subjects: list[str] = Field(default_factory=list)


class PolicyEvaluation(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    policy_id: str
    audit_id: str
    decision: Literal["PASS","FAIL","UNKNOWN"]
    score: int | None
    counts: dict[str,int]
    violations: list[PolicyViolation]


def load_policy_pack(path:Path)->PolicyPack:
    if not path.is_file():
        raise ValueError(f"Policy pack introuvable: {path}")
    return PolicyPack.model_validate_json(path.read_text(encoding="utf-8"))


def evaluate_policy(audit:AuditResult,policy:PolicyPack)->PolicyEvaluation:
    counts=Counter(finding.status for finding in audit.findings)
    violations:list[PolicyViolation]=[]
    if audit.scan_completeness != "COMPLETED":
        violations.append(PolicyViolation(rule="scan_incomplete",message="La couverture du scan est incomplète; la policy ne peut pas conclure PASS."))
    if audit.is_demo and not policy.allow_demo:
        violations.append(PolicyViolation(rule="demo_not_allowed",message="Les données de démonstration ne satisfont pas cette policy."))
    score=audit.score.value if audit.score else None
    if policy.minimum_score is not None and (score is None or score<policy.minimum_score):
        violations.append(PolicyViolation(rule="minimum_score",message=f"Score {score if score is not None else 'absent'} inférieur au minimum {policy.minimum_score}."))
    for status in policy.fail_on_statuses:
        subjects=sorted(finding.subject for finding in audit.findings if finding.status==status)
        if subjects:
            violations.append(PolicyViolation(rule=f"forbidden_status:{status.value}",message=f"{len(subjects)} finding(s) avec le statut interdit {status.value}.",subjects=subjects))
    limit_values=policy.maximum_counts.model_dump()
    for field,limit in limit_values.items():
        if limit is None:
            continue
        status=Status(field.upper())
        actual=counts[status]
        if actual>limit:
            subjects=sorted(finding.subject for finding in audit.findings if finding.status==status)
            violations.append(PolicyViolation(rule=f"maximum_count:{status.value}",message=f"{actual} finding(s) {status.value}; maximum autorisé {limit}.",subjects=subjects))
    required_rank=CONFIDENCE_RANK[policy.minimum_evidence_confidence]
    weak=sorted({finding.subject for finding in audit.findings for evidence in finding.evidence if CONFIDENCE_RANK[evidence.confidence]<required_rank})
    if weak:
        violations.append(PolicyViolation(rule="minimum_evidence_confidence",message=f"Des preuves sont sous le niveau {policy.minimum_evidence_confidence}.",subjects=weak))
    if policy.require_report_hash and not audit.report_sha256:
        violations.append(PolicyViolation(rule="report_hash_required",message="Le SHA-256 canonique du rapport est absent."))
    decision = "UNKNOWN" if audit.scan_completeness != "COMPLETED" else "FAIL" if violations else "PASS"
    return PolicyEvaluation(policy_id=policy.policy_id,audit_id=audit.id,decision=decision,score=score,counts={status.value:counts[status] for status in Status},violations=violations)
