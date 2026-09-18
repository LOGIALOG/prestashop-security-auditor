from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

SECURITY_HEADERS = ["content-security-policy", "strict-transport-security", "permissions-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "server", "cf-ray", "cf-cache-status", "x-litespeed-cache"]
REQUIRED_HEADERS = set(SECURITY_HEADERS[:6])


class Status(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    REQUIRES_ACCESS = "REQUIRES_ACCESS"
    ASSET_RESIDUE = "ASSET_RESIDUE"
    NOT_AFFECTED = "NOT_AFFECTED"
    HARDENING = "HARDENING"


class ScanIssue(BaseModel):
    kind: Literal[
        "HTTP_STATUS",
        "TRANSPORT_ERROR",
        "EXTRACTOR_ERROR",
        "BUDGET_EXHAUSTED",
        "CHECK_NOT_TESTED",
        "REDIRECT_LOOP",
    ]
    url: str
    required: bool = True
    check_id: str | None = None
    status_code: int | None = Field(default=None, ge=300, le=599)
    detail: str | None = Field(default=None, max_length=200)
    captured_at: datetime | None = None

    @model_validator(mode="after")
    def issue_consistency(self) -> "ScanIssue":
        if (self.kind == "HTTP_STATUS") != (self.status_code is not None):
            raise ValueError("HTTP_STATUS exige un code HTTP; les autres incidents l'interdisent")
        if self.kind == "CHECK_NOT_TESTED" and not self.check_id:
            raise ValueError("CHECK_NOT_TESTED exige un identifiant de contrôle")
        return self


class Evidence(BaseModel):
    url: str
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_type: str
    excerpt: str
    response_sha256: str
    observation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    confidence: Literal["high", "medium", "low"]
    detection_method: str


class HttpMetadataObservation(BaseModel):
    url: str
    captured_at: datetime
    method: Literal["GET"] = "GET"
    observed: bool
    absent_headers: list[str] = Field(default_factory=list)
    headers_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    cookies_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def observation_state_consistent(self) -> "HttpMetadataObservation":
        if self.observed:
            if self.headers_sha256 is None or self.cookies_sha256 is None:
                raise ValueError("Une observation HTTP observée exige les digests d’en-têtes et de cookies")
        elif self.headers_sha256 is not None or self.cookies_sha256 is not None or self.absent_headers:
            raise ValueError("Une observation HTTP non observée ne peut porter ni digest ni absence")
        if any(name != name.lower() for name in self.absent_headers):
            raise ValueError("absent_headers doit contenir des noms en minuscules")
        if len(set(self.absent_headers)) != len(self.absent_headers):
            raise ValueError("absent_headers ne doit pas contenir de doublons")
        if any(name not in SECURITY_HEADERS for name in self.absent_headers):
            raise ValueError("absent_headers contient un en-tête non suivi")
        return self


class Finding(BaseModel):
    is_demo: bool = False
    subject: str
    status: Status
    severity: str = "Information"
    version: str | None = None
    cve: str | None = None
    interpretation: str
    business_risk: str
    remediation: str
    source: str | None = None
    access_required: str | None = None
    advisory_snapshot_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    evidence: list[Evidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def real_findings_require_evidence(self) -> "Finding":
        if not self.is_demo and not self.evidence:
            raise ValueError("Un finding réel doit contenir au moins une preuve enregistrée")
        return self


class AuditRequest(BaseModel):
    target: HttpUrl
    authorization_confirmed: bool
    public_pages: list[HttpUrl] = Field(default_factory=list)
    max_requests: int = Field(default=20, ge=1, le=20)
    delay_seconds: float = Field(default=1.0, ge=1.0, le=10.0)

    @field_validator("authorization_confirmed")
    @classmethod
    def authorization_required(cls, value: bool) -> bool:
        if not value:
            raise ValueError("Une autorisation explicite est obligatoire")
        return value


class AuditResult(BaseModel):
    is_demo: bool = False
    target: str
    id: str
    domain: str
    started_at: datetime
    completed_at: datetime
    request_count: int
    scope: list[str]
    findings: list[Finding]
    headers: dict[str, str]
    cookies: list[dict[str, str | bool]]
    scan_completeness: Literal["COMPLETED", "INCOMPLETE"]
    scan_issues: list[ScanIssue]
    report_path: str | None = None
    report_sha256: str | None = None
    advisory_snapshot_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    advisory_snapshot_date: date | None = None
    http_observation: "HttpMetadataObservation | None" = None
    score: "ScoreResult | None" = None

    @model_validator(mode="before")
    @classmethod
    def legacy_completeness_fails_closed(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        has_completeness = "scan_completeness" in data
        has_issues = "scan_issues" in data
        if has_completeness != has_issues:
            raise ValueError("scan_completeness et scan_issues doivent être fournis ensemble")
        if has_completeness:
            return data
        legacy = dict(data)
        legacy["scan_completeness"] = "INCOMPLETE"
        legacy["scan_issues"] = [
            {
                "kind": "CHECK_NOT_TESTED",
                "url": str(legacy.get("target", "")),
                "required": True,
                "check_id": "coverage:legacy-record",
            }
        ]
        return legacy

    @model_validator(mode="after")
    def mode_consistency(self) -> "AuditResult":
        if self.is_demo and self.target != "demo.local":
            raise ValueError("Les données de démonstration doivent cibler demo.local")
        if any(f.is_demo != self.is_demo for f in self.findings):
            raise ValueError("Le mode des findings doit correspondre au mode de l'audit")
        required_issues = [issue for issue in self.scan_issues if issue.required]
        if self.scan_completeness == "COMPLETED" and required_issues:
            raise ValueError("Un audit complet ne peut pas contenir d'incident obligatoire")
        if self.scan_completeness == "INCOMPLETE" and not required_issues:
            raise ValueError("Un audit incomplet doit enregistrer au moins un incident obligatoire")
        return self


class ScoreFactor(BaseModel):
    subject: str
    status: Status
    points: int
    reason: str


class ScoreResult(BaseModel):
    value: int = Field(ge=0, le=100)
    formula: str
    factors: list[ScoreFactor]
    previous_comparison: int | None = None


class FindingChange(BaseModel):
    subject: str
    cve: str | None = None
    previous_status: Status | None = None
    current_status: Status | None = None
    previous_version: str | None = None
    current_version: str | None = None


class AuditComparison(BaseModel):
    audit_id: str
    previous_audit_id: str | None = None
    domain: str
    available: bool
    score_delta: int | None = None
    added: list[FindingChange] = Field(default_factory=list)
    resolved: list[FindingChange] = Field(default_factory=list)
    changed: list[FindingChange] = Field(default_factory=list)
    unchanged_count: int = 0


AuditResult.model_rebuild()
