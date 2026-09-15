from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from .models import AuditComparison, AuditRequest, AuditResult, ScanIssue, Status


class MonitorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    monitor_id: str = Field(min_length=3,max_length=64,pattern=r"^[a-z0-9][a-z0-9._-]+$")
    target: HttpUrl
    authorization_confirmed: bool
    public_pages: list[HttpUrl] = Field(default_factory=list,max_length=10)
    max_requests: int = Field(default=20,ge=1,le=20)
    delay_seconds: float = Field(default=1.0,ge=1.0,le=10.0)
    notify_on_added_statuses: list[Status] = Field(default_factory=lambda:[Status.CONFIRMED,Status.LIKELY,Status.REQUIRES_ACCESS])
    notify_on_resolved: bool = True
    notify_on_status_change: bool = True
    minimum_score_drop: int = Field(default=1,ge=1,le=100)

    @field_validator("authorization_confirmed")
    @classmethod
    def authorization_required(cls,value:bool)->bool:
        if not value:
            raise ValueError("Une autorisation explicite est obligatoire pour le monitoring")
        return value

    @field_validator("notify_on_added_statuses")
    @classmethod
    def unique_statuses(cls,value:list[Status])->list[Status]:
        if len(value)!=len(set(value)):
            raise ValueError("notify_on_added_statuses contient un statut dupliqué")
        return value

    @model_validator(mode="after")
    def pages_stay_on_target_origin(self)->"MonitorConfig":
        from .scanner import normalized_origin
        origin=normalized_origin(str(self.target))
        if any(normalized_origin(str(page))!=origin for page in self.public_pages):
            raise ValueError("Chaque page surveillée doit rester sur l’origine exacte de la cible")
        return self

    def audit_request(self)->AuditRequest:
        return AuditRequest(target=self.target,authorization_confirmed=self.authorization_confirmed,public_pages=self.public_pages,max_requests=self.max_requests,delay_seconds=self.delay_seconds)


class MonitorResult(BaseModel):
    schema_version: Literal["1.1"] = "1.1"
    monitor_id: str
    audit_id: str
    state: Literal["BASELINE","UNCHANGED","CHANGED","INCOMPLETE"]
    notification_required: bool
    reasons: list[str]
    comparison: AuditComparison | None
    scan_completeness: Literal["COMPLETED","INCOMPLETE"]
    scan_issues: list[ScanIssue]

    @model_validator(mode="after")
    def state_matches_scan_completeness(self)->"MonitorResult":
        required_issues=any(issue.required for issue in self.scan_issues)
        if self.state=="INCOMPLETE":
            if self.scan_completeness!="INCOMPLETE" or self.comparison is not None or self.notification_required or not required_issues:
                raise ValueError("Un résultat de monitoring incomplet exige une couverture incomplète sans comparaison ni notification")
        elif self.scan_completeness!="COMPLETED" or self.comparison is None or required_issues:
            raise ValueError("Un résultat de monitoring normal exige un audit complet et une comparaison")
        return self


def load_monitor_config(path:Path)->MonitorConfig:
    if not path.is_file():
        raise ValueError(f"Configuration de monitoring introuvable: {path}")
    return MonitorConfig.model_validate_json(path.read_text(encoding="utf-8"))


def evaluate_monitor(config:MonitorConfig,audit:AuditResult,comparison:AuditComparison)->MonitorResult:
    if not comparison.available:
        return MonitorResult(monitor_id=config.monitor_id,audit_id=audit.id,state="BASELINE",notification_required=False,reasons=[],comparison=comparison,scan_completeness=audit.scan_completeness,scan_issues=audit.scan_issues)
    reasons:list[str]=[]
    watched=set(config.notify_on_added_statuses)
    added=[item.subject for item in comparison.added if item.current_status in watched]
    if added:
        reasons.append(f"Nouveaux findings surveillés: {', '.join(sorted(added))}")
    if config.notify_on_resolved and comparison.resolved:
        reasons.append(f"Findings résolus: {', '.join(sorted(item.subject for item in comparison.resolved))}")
    if config.notify_on_status_change and comparison.changed:
        reasons.append(f"Statuts ou versions modifiés: {', '.join(sorted(item.subject for item in comparison.changed))}")
    if comparison.score_delta is not None and comparison.score_delta<=-config.minimum_score_drop:
        reasons.append(f"Baisse du score: {comparison.score_delta}")
    return MonitorResult(monitor_id=config.monitor_id,audit_id=audit.id,state="CHANGED" if reasons else "UNCHANGED",notification_required=bool(reasons),reasons=reasons,comparison=comparison,scan_completeness=audit.scan_completeness,scan_issues=audit.scan_issues)


def incomplete_monitor_result(config:MonitorConfig,audit:AuditResult)->MonitorResult:
    if audit.scan_completeness!="INCOMPLETE":
        raise ValueError("Seul un audit incomplet peut produire un résultat de monitoring incomplet")
    return MonitorResult(monitor_id=config.monitor_id,audit_id=audit.id,state="INCOMPLETE",notification_required=False,reasons=[],comparison=None,scan_completeness=audit.scan_completeness,scan_issues=audit.scan_issues)
