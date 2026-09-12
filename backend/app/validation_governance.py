from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.app.validation_corpus import AdvisoryOutcome, ConfidenceTier, FingerprintOutcome


ApprovalState = Literal["PENDING_OWNER_APPROVAL"]
ArtifactState = Literal["PRESENT"]
FreezeState = Literal["FROZEN_FOR_SYNTHETIC_REHEARSAL"]

REQUIRED_SAMPLING_DIMENSIONS = {
    "CORE_FAMILY",
    "HOSTING",
    "EDGE_LAYER",
    "MODULE_PROVENANCE",
    "VERSION_EXPOSURE",
    "ASSET_CONDITION",
    "GROUND_TRUTH_STATE",
}
REQUIRED_RECRUITMENT_FIELDS = {
    "SYNTHETIC_CANDIDATE_ID",
    "RECRUITMENT_SOURCE",
    "SELECTION_MECHANISM",
    "ELIGIBILITY_STATE",
    "NON_RESPONSE_STATE",
    "EXCLUSION_REASON",
}
REQUIRED_FINGERPRINT_FIELDS = {
    "SYNTHETIC_OBSERVATION_ID",
    "TRUTH_STATUS",
    "SOURCE_TYPE",
    "COMPONENT_PRESENT",
    "EXACT_COMPONENT",
    "EXACT_VERSION",
    "EVIDENCE_SHA256",
    "SYNTHETIC_REVIEWER_ID",
}
REQUIRED_ADVISORY_FIELDS = {
    "SYNTHETIC_OBSERVATION_ID",
    "SYNTHETIC_ADVISORY_ID",
    "REVIEW_STATUS",
    "SOURCE_SET_DIGEST",
    "TRUTH_CLASSIFICATION",
    "OBSERVED_CLASSIFICATION",
    "SYNTHETIC_REVIEWER_ID",
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GovernanceRoles(StrictModel):
    data_controller_id: str = Field(pattern=r"^synthetic-owner-[a-z0-9-]+$")
    research_owner_id: str = Field(pattern=r"^synthetic-owner-[a-z0-9-]+$")
    assignments_real: Literal[False]
    approval_state: ApprovalState


class GovernanceArtifacts(StrictModel):
    consent_authorization_template: ArtifactState
    fingerprint_truth_form: ArtifactState
    advisory_truth_form: ArtifactState
    sampling_recruitment_template: ArtifactState
    metric_exclusion_rules: ArtifactState
    lifecycle_incident_procedure: ArtifactState


class SamplingRehearsal(StrictModel):
    dimensions: list[str] = Field(min_length=1)
    recruitment_fields: list[str] = Field(min_length=1)
    numeric_targets_state: ApprovalState
    real_recruitment_started: Literal[False]

    @model_validator(mode="after")
    def required_sampling_structure_is_present(self) -> "SamplingRehearsal":
        if (
            len(self.dimensions) != len(set(self.dimensions))
            or set(self.dimensions) != REQUIRED_SAMPLING_DIMENSIONS
        ):
            raise ValueError("sampling dimensions must match the canonical protocol")
        if (
            len(self.recruitment_fields) != len(set(self.recruitment_fields))
            or set(self.recruitment_fields) != REQUIRED_RECRUITMENT_FIELDS
        ):
            raise ValueError("recruitment fields must match the governance template")
        return self


class ReviewForms(StrictModel):
    fingerprint_fields: list[str] = Field(min_length=1)
    advisory_fields: list[str] = Field(min_length=1)
    real_evidence_allowed: Literal[False]

    @model_validator(mode="after")
    def required_review_fields_are_present(self) -> "ReviewForms":
        if (
            len(self.fingerprint_fields) != len(set(self.fingerprint_fields))
            or set(self.fingerprint_fields) != REQUIRED_FINGERPRINT_FIELDS
        ):
            raise ValueError("fingerprint review fields must match the governance template")
        if (
            len(self.advisory_fields) != len(set(self.advisory_fields))
            or set(self.advisory_fields) != REQUIRED_ADVISORY_FIELDS
        ):
            raise ValueError("advisory review fields must match the governance template")
        return self


class FrozenInputs(StrictModel):
    baseline_commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    extractor_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    advisory_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    synthetic_corpus_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    extractor_state: FreezeState
    advisory_state: FreezeState
    approved_for_real_collection: Literal[False]


class MetricPolicy(StrictModel):
    fingerprint_outcomes: list[FingerprintOutcome] = Field(min_length=1)
    advisory_outcomes: list[AdvisoryOutcome] = Field(min_length=1)
    confidence_tiers: list[ConfidenceTier] = Field(min_length=1)
    correctness_metric_exclusions: list[Literal["INDETERMINATE", "GROUND_TRUTH_CONFLICT"]]
    analysis_unit: Literal["OBSERVATION_WITH_SHOP_CLUSTERING"]
    confidence_is_probability: Literal[False]
    ecosystem_claims_allowed: Literal[False]

    @model_validator(mode="after")
    def metric_domains_are_complete_and_separate(self) -> "MetricPolicy":
        fingerprint_domain = {
            "TP",
            "FP",
            "FN",
            "CORRECT_ABSTENTION",
            "INDETERMINATE",
            "GROUND_TRUTH_CONFLICT",
        }
        if (
            len(self.fingerprint_outcomes) != len(set(self.fingerprint_outcomes))
            or set(self.fingerprint_outcomes) != fingerprint_domain
        ):
            raise ValueError("fingerprint outcome domain is incomplete")
        advisory_domain = {"CORRECT", "INCORRECT", "UNKNOWN", "NOT_APPLICABLE"}
        if (
            len(self.advisory_outcomes) != len(set(self.advisory_outcomes))
            or set(self.advisory_outcomes) != advisory_domain
        ):
            raise ValueError("advisory outcome domain is incomplete")
        if len(self.confidence_tiers) != len(set(self.confidence_tiers)) or set(self.confidence_tiers) != {
            "HIGH",
            "MEDIUM",
            "LOW",
        }:
            raise ValueError("confidence tiers must remain qualitative")
        if len(self.correctness_metric_exclusions) != len(set(self.correctness_metric_exclusions)) or set(
            self.correctness_metric_exclusions
        ) != {"INDETERMINATE", "GROUND_TRUTH_CONFLICT"}:
            raise ValueError("indeterminate and conflicting truth must remain visible but excluded")
        return self


class LifecycleDecisions(StrictModel):
    access_control: ApprovalState
    retention_periods: ApprovalState
    deletion_process: ApprovalState
    backup_propagation: ApprovalState
    incident_process: ApprovalState
    withdrawal_process: ApprovalState
    git_storage_allowed: Literal[False]
    public_issue_storage_allowed: Literal[False]


class ValidationGovernanceRehearsal(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"$id": "urn:logialog:schema:synthetic-validation-governance:1.0"},
    )

    format: Literal["logialog-synthetic-validation-governance"]
    schema_version: Literal["1.0"]
    created_at: datetime
    synthetic: Literal[True]
    real_client_data: Literal[False]
    real_domains: Literal[False]
    production_access: Literal[False]
    collection_authorized: Literal[False]
    approval_state: ApprovalState
    roles: GovernanceRoles
    artifacts: GovernanceArtifacts
    sampling: SamplingRehearsal
    review_forms: ReviewForms
    frozen_inputs: FrozenInputs
    metrics: MetricPolicy
    lifecycle: LifecycleDecisions

    @model_validator(mode="after")
    def rehearsal_remains_non_operational(self) -> "ValidationGovernanceRehearsal":
        if self.created_at.year != 2000 or self.created_at.tzinfo is None:
            raise ValueError("synthetic governance timestamps must use year 2000 with a timezone")
        return self


def load_validation_governance(path: Path) -> ValidationGovernanceRehearsal:
    return ValidationGovernanceRehearsal.model_validate(json.loads(path.read_text(encoding="utf-8")))
