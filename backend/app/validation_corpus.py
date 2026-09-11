from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


FingerprintOutcome = Literal[
    "TP",
    "FP",
    "FN",
    "CORRECT_ABSTENTION",
    "INDETERMINATE",
    "GROUND_TRUTH_CONFLICT",
]
AdvisoryOutcome = Literal["CORRECT", "INCORRECT", "UNKNOWN", "NOT_APPLICABLE"]
AdvisoryClassification = Literal["AFFECTED", "FIXED", "UNKNOWN", "NOT_APPLICABLE"]
ConfidenceTier = Literal["HIGH", "MEDIUM", "LOW"]

FORBIDDEN_KEY_PARTS = {
    "address",
    "client",
    "cookie",
    "credential",
    "customer",
    "database",
    "domain",
    "email",
    "host",
    "ip",
    "order",
    "password",
    "path",
    "phone",
    "secret",
    "session",
    "token",
    "url",
    "uri",
}
PRIVACY_ASSERTION_KEYS = {"real_client_data", "real_domains"}
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{1,31}:(?://|[^\s])", re.IGNORECASE),
    re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b"),
    re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63}\b", re.IGNORECASE),
    re.compile(r"[a-z]:[\\/]", re.IGNORECASE),
    re.compile(r"\\\\[^\\/\s]+\\[^\\\s]+"),
    re.compile(r"(?<![a-z0-9])/(?:app|data|etc|home|mnt|opt|private|root|run|srv|tmp|usr|var|workspace)(?:/|\b)", re.IGNORECASE),
    re.compile(r"(?:api[_-]?key|credential|password|secret|session|token)\s*[:=]", re.IGNORECASE),
)
IPV6_CANDIDATE_PATTERN = re.compile(r"(?<![0-9a-f:])\[?[0-9a-f:]*:[0-9a-f:]+\]?(?![0-9a-f:])", re.IGNORECASE)


def _contains_ipv6_address(value: str) -> bool:
    for match in IPV6_CANDIDATE_PATTERN.finditer(value):
        candidate = match.group(0).strip("[]")
        if candidate.count(":") < 2:
            continue
        try:
            if isinstance(ipaddress.ip_address(candidate), ipaddress.IPv6Address):
                return True
        except ValueError:
            continue
    return False


def _assert_privacy_safe(value: object, location: str = "record") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_parts = {part for part in re.split(r"[^a-z0-9]+", str(key).casefold()) if part}
            forbidden = [] if key in PRIVACY_ASSERTION_KEYS else sorted(key_parts & FORBIDDEN_KEY_PARTS)
            if forbidden:
                raise ValueError(f"Forbidden privacy field at {location}.{key}: {forbidden[0]}")
            _assert_privacy_safe(nested, f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_privacy_safe(nested, f"{location}[{index}]")
    elif isinstance(value, str):
        if _contains_ipv6_address(value):
            raise ValueError(f"Forbidden privacy value at {location}")
        for pattern in FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(value):
                raise ValueError(f"Forbidden privacy value at {location}")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CorpusScope(StrictModel):
    page_category: Literal["HOME", "ROBOTS", "PUBLIC_PAGE"]
    request_budget: int = Field(ge=1, le=20)
    requests_sent: int = Field(ge=0, le=20)
    network_access: Literal[False]

    @model_validator(mode="after")
    def requests_stay_within_budget(self) -> "CorpusScope":
        if self.requests_sent > self.request_budget:
            raise ValueError("requests_sent cannot exceed request_budget")
        return self


class CorpusStrata(StrictModel):
    core_family: Literal["PS_1_7", "PS_8", "PS_9"]
    hosting: Literal["SHARED", "VPS_DEDICATED", "MANAGED", "CONTAINERIZED"]
    edge_layer: Literal["NONE", "CDN_ONLY", "WAF_ONLY", "CDN_WAF"]
    module_provenance: Literal["OFFICIAL_VENDOR", "COMMUNITY", "CUSTOM_PRIVATE"]
    version_exposure: Literal["EXACT", "PARTIAL", "ABSENT", "CONFLICTING_SPOOFED"]
    asset_condition: Literal["CURRENT", "STALE_CACHE", "RENAMED", "MINIFIED_BUNDLED", "REMOVED"]


class CorpusDetector(StrictModel):
    extractor_id: str = Field(pattern=r"^synthetic-extractor-[a-z0-9-]+$")
    extractor_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    detection_method: Literal["MODULE_PATH", "ASSET_VERSION", "NO_SIGNAL", "CONFLICTING_SIGNALS"]
    confidence_tier: ConfidenceTier
    observed_component: str | None = Field(default=None, pattern=r"^synthetic-module-[a-z0-9-]+$")
    observed_version: str | None = Field(default=None, pattern=r"^\d+\.\d+\.\d+$")

    @model_validator(mode="after")
    def observation_is_coherent(self) -> "CorpusDetector":
        if (self.observed_component is None) != (self.observed_version is None):
            raise ValueError("observed component and version must be present or absent together")
        if self.detection_method == "NO_SIGNAL" and self.observed_component is not None:
            raise ValueError("NO_SIGNAL cannot contain an observed component")
        return self


class FingerprintTruth(StrictModel):
    status: Literal["AVAILABLE", "UNAVAILABLE", "CONFLICTING"]
    source_type: Literal["LOCAL_METADATA", "AUTHENTICATED_BACK_OFFICE", "DEPLOYMENT_MANIFEST", "NONE"]
    component_present: bool | None = None
    exact_component: str | None = Field(default=None, pattern=r"^synthetic-module-[a-z0-9-]+$")
    exact_version: str | None = Field(default=None, pattern=r"^\d+\.\d+\.\d+$")
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reviewer_id: str = Field(pattern=r"^synthetic-reviewer-[a-z0-9-]+$")

    @model_validator(mode="after")
    def ground_truth_is_coherent(self) -> "FingerprintTruth":
        exact_values = (self.exact_component, self.exact_version, self.evidence_sha256)
        if self.status == "AVAILABLE":
            if self.source_type == "NONE" or self.component_present is None or self.evidence_sha256 is None:
                raise ValueError("available fingerprint truth requires a source, presence and evidence hash")
            if self.component_present and (self.exact_component is None or self.exact_version is None):
                raise ValueError("present component truth requires exact component and version")
            if not self.component_present and any(value is not None for value in exact_values[:2]):
                raise ValueError("absent component truth cannot contain component metadata")
        elif self.status == "UNAVAILABLE":
            if self.source_type != "NONE" or self.component_present is not None or any(value is not None for value in exact_values):
                raise ValueError("unavailable fingerprint truth cannot contain asserted evidence")
        else:
            if self.source_type == "NONE" or self.evidence_sha256 is None:
                raise ValueError("conflicting fingerprint truth requires a source and evidence hash")
            if self.component_present is not None or self.exact_component is not None or self.exact_version is not None:
                raise ValueError("conflicting fingerprint truth cannot assert one exact answer")
        return self


class AdvisoryTruth(StrictModel):
    review_status: Literal["REVIEWED", "UNKNOWN", "NOT_APPLICABLE"]
    advisory_record_id: str | None = Field(default=None, pattern=r"^synthetic-advisory-[a-z0-9-]+$")
    truth_classification: AdvisoryClassification
    observed_classification: AdvisoryClassification
    reviewer_id: str = Field(pattern=r"^synthetic-reviewer-[a-z0-9-]+$")


class ValidationRecord(StrictModel):
    schema_version: Literal["1.0"]
    shop_id: str = Field(pattern=r"^synthetic-shop-\d{3}$")
    observation_id: str = Field(pattern=r"^synthetic-observation-\d{3}$")
    collected_at: datetime
    scope: CorpusScope
    strata: CorpusStrata
    detector: CorpusDetector
    fingerprint_truth: FingerprintTruth
    fingerprint_outcome: FingerprintOutcome
    advisory_truth: AdvisoryTruth
    advisory_outcome: AdvisoryOutcome

    @model_validator(mode="after")
    def outcomes_are_coherent(self) -> "ValidationRecord":
        if self.collected_at.year != 2000:
            raise ValueError("synthetic collection timestamps must use the year 2000")
        if self.collected_at.tzinfo is None:
            raise ValueError("synthetic collection timestamps must include a timezone")
        observed = self.detector.observed_component
        truth = self.fingerprint_truth
        if self.fingerprint_outcome == "TP":
            if truth.status != "AVAILABLE" or truth.component_present is not True:
                raise ValueError("TP requires an available present-component truth")
            if observed != truth.exact_component or self.detector.observed_version != truth.exact_version:
                raise ValueError("TP observation must match fingerprint truth")
        elif self.fingerprint_outcome == "FP":
            if observed is None or truth.status != "AVAILABLE":
                raise ValueError("FP requires an observation and available fingerprint truth")
            if truth.component_present and observed == truth.exact_component and self.detector.observed_version == truth.exact_version:
                raise ValueError("matching observation cannot be FP")
        elif self.fingerprint_outcome == "FN":
            if observed is not None or truth.status != "AVAILABLE" or truth.component_present is not True:
                raise ValueError("FN requires no observation and an available present-component truth")
        elif self.fingerprint_outcome == "CORRECT_ABSTENTION":
            if observed is not None or truth.status != "AVAILABLE" or truth.component_present is not False:
                raise ValueError("CORRECT_ABSTENTION requires an available absent-component truth")
        elif self.fingerprint_outcome == "INDETERMINATE" and truth.status != "UNAVAILABLE":
            raise ValueError("INDETERMINATE requires unavailable fingerprint truth")
        elif self.fingerprint_outcome == "GROUND_TRUTH_CONFLICT" and truth.status != "CONFLICTING":
            raise ValueError("GROUND_TRUTH_CONFLICT requires conflicting fingerprint truth")

        advisory = self.advisory_truth
        if self.advisory_outcome == "CORRECT":
            if advisory.review_status != "REVIEWED" or advisory.truth_classification != advisory.observed_classification:
                raise ValueError("CORRECT advisory outcome requires equal reviewed classifications")
            if advisory.truth_classification in {"UNKNOWN", "NOT_APPLICABLE"}:
                raise ValueError("CORRECT cannot replace UNKNOWN or NOT_APPLICABLE")
        elif self.advisory_outcome == "INCORRECT":
            known = {"AFFECTED", "FIXED"}
            if advisory.review_status != "REVIEWED" or advisory.truth_classification not in known or advisory.observed_classification not in known:
                raise ValueError("INCORRECT requires two reviewed known classifications")
            if advisory.truth_classification == advisory.observed_classification:
                raise ValueError("equal advisory classifications cannot be INCORRECT")
        elif self.advisory_outcome == "UNKNOWN":
            if advisory.review_status != "UNKNOWN" or advisory.truth_classification != "UNKNOWN":
                raise ValueError("UNKNOWN requires unknown advisory ground truth")
        elif (
            advisory.review_status != "NOT_APPLICABLE"
            or advisory.advisory_record_id is not None
            or advisory.truth_classification != "NOT_APPLICABLE"
            or advisory.observed_classification != "NOT_APPLICABLE"
        ):
            raise ValueError("NOT_APPLICABLE cannot contain an advisory assertion")
        if advisory.review_status in {"REVIEWED", "UNKNOWN"} and advisory.advisory_record_id is None:
            raise ValueError("advisory review requires a synthetic advisory record ID")
        return self


class ValidationCorpus(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"$id": "urn:logialog:schema:synthetic-validation-corpus:1.0"},
    )

    format: Literal["logialog-synthetic-validation-corpus"]
    schema_version: Literal["1.0"]
    synthetic: Literal[True]
    real_client_data: Literal[False]
    real_domains: Literal[False]
    external_collection: Literal[False]
    records: list[ValidationRecord] = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def reject_privacy_data(cls, value: object) -> object:
        _assert_privacy_safe(value, "corpus")
        return value

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> "ValidationCorpus":
        observation_ids = [record.observation_id for record in self.records]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("observation IDs must be unique")
        return self


def load_validation_corpus(path: Path) -> ValidationCorpus:
    return ValidationCorpus.model_validate(json.loads(path.read_text(encoding="utf-8")))
