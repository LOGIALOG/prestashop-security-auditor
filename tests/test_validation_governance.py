import copy
import hashlib
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.app.validation_governance import ValidationGovernanceRehearsal, load_validation_governance


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "validation-governance.synthetic.json"
GOVERNANCE_DOC = ROOT / "docs" / "VALIDATION_GOVERNANCE.md"
PROTOCOL_DOC = ROOT / "docs" / "VALIDATION_PROTOCOL.md"


def payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def canonical_text_sha256(path: Path) -> str:
    normalized = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def test_synthetic_governance_rehearsal_covers_every_preparation_artifact():
    rehearsal = load_validation_governance(FIXTURE)

    assert rehearsal.synthetic is True
    assert rehearsal.real_client_data is False
    assert rehearsal.real_domains is False
    assert rehearsal.production_access is False
    assert rehearsal.collection_authorized is False
    assert rehearsal.approval_state == "PENDING_OWNER_APPROVAL"
    assert set(rehearsal.artifacts.model_dump().values()) == {"PRESENT"}
    assert rehearsal.sampling.real_recruitment_started is False
    assert rehearsal.review_forms.real_evidence_allowed is False


def test_rehearsal_preserves_separate_outcome_domains_and_qualitative_tiers():
    rehearsal = load_validation_governance(FIXTURE)

    assert set(rehearsal.metrics.fingerprint_outcomes) == {
        "TP",
        "FP",
        "FN",
        "CORRECT_ABSTENTION",
        "INDETERMINATE",
        "GROUND_TRUTH_CONFLICT",
    }
    assert set(rehearsal.metrics.advisory_outcomes) == {
        "CORRECT",
        "INCORRECT",
        "UNKNOWN",
        "NOT_APPLICABLE",
    }
    assert not set(rehearsal.metrics.fingerprint_outcomes) & set(rehearsal.metrics.advisory_outcomes)
    assert set(rehearsal.metrics.confidence_tiers) == {"HIGH", "MEDIUM", "LOW"}
    assert rehearsal.metrics.confidence_is_probability is False
    assert rehearsal.metrics.ecosystem_claims_allowed is False


@pytest.mark.parametrize(
    ("field_path", "value"),
    [
        (("collection_authorized",), True),
        (("real_client_data",), True),
        (("real_domains",), True),
        (("production_access",), True),
        (("roles", "assignments_real"), True),
        (("review_forms", "real_evidence_allowed"), True),
        (("sampling", "real_recruitment_started"), True),
        (("frozen_inputs", "approved_for_real_collection"), True),
        (("metrics", "confidence_is_probability"), True),
        (("metrics", "ecosystem_claims_allowed"), True),
        (("approval_state",), "APPROVED"),
    ],
)
def test_rehearsal_cannot_authorize_real_collection_or_product_claims(field_path, value):
    candidate = copy.deepcopy(payload())
    target = candidate
    for part in field_path[:-1]:
        target = target[part]
    target[field_path[-1]] = value

    with pytest.raises(ValidationError):
        ValidationGovernanceRehearsal.model_validate(candidate)


def test_rehearsal_requires_synthetic_year_2000_timestamp_and_identifiers():
    rehearsal = load_validation_governance(FIXTURE)

    assert rehearsal.created_at.year == 2000
    assert rehearsal.created_at.tzinfo is not None
    assert rehearsal.roles.data_controller_id.startswith("synthetic-owner-")
    assert rehearsal.roles.research_owner_id.startswith("synthetic-owner-")

    invalid_time = payload()
    invalid_time["created_at"] = "2026-01-01T00:00:00Z"
    with pytest.raises(ValidationError, match="year 2000"):
        ValidationGovernanceRehearsal.model_validate(invalid_time)


def test_frozen_rehearsal_hashes_match_canonical_inputs():
    frozen = load_validation_governance(FIXTURE).frozen_inputs
    governance = GOVERNANCE_DOC.read_text(encoding="utf-8")

    assert frozen.extractor_source_sha256 == canonical_text_sha256(ROOT / "backend" / "app" / "extractors.py")
    assert frozen.advisory_manifest_sha256 == canonical_text_sha256(ROOT / "advisories" / "snapshot-manifest.json")
    assert frozen.synthetic_corpus_schema_sha256 == canonical_text_sha256(
        ROOT / "docs" / "validation-corpus-v1.schema.json"
    )
    assert frozen.extractor_state == "FROZEN_FOR_SYNTHETIC_REHEARSAL"
    assert frozen.advisory_state == "FROZEN_FOR_SYNTHETIC_REHEARSAL"
    assert frozen.baseline_commit_sha in governance
    assert frozen.extractor_source_sha256 in governance
    assert frozen.advisory_manifest_sha256 in governance
    assert frozen.synthetic_corpus_schema_sha256 in governance


def test_fixture_contains_no_real_target_or_personal_identifier():
    serialized = FIXTURE.read_text(encoding="utf-8")

    assert "http://" not in serialized and "https://" not in serialized
    assert not re.search(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b", serialized)
    assert not re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", serialized)
    assert not re.search(r"[a-zA-Z]:[\\/]", serialized)
    assert "synthetic-owner-" in serialized


def test_validation_path_performs_no_network_access(monkeypatch):
    def reject_network(*_args, **_kwargs):
        raise AssertionError("governance rehearsal validation must not access a network")

    monkeypatch.setattr("socket.getaddrinfo", reject_network)
    monkeypatch.setattr("httpx.Client", reject_network)
    monkeypatch.setattr("httpx.AsyncClient", reject_network)

    assert load_validation_governance(FIXTURE).collection_authorized is False


def test_unknown_fields_and_incomplete_gate_structures_fail():
    unknown = payload()
    unknown["automatic_approval"] = False
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ValidationGovernanceRehearsal.model_validate(unknown)

    missing_dimension = payload()
    missing_dimension["sampling"]["dimensions"].remove("GROUND_TRUTH_STATE")
    with pytest.raises(ValidationError, match="sampling dimensions"):
        ValidationGovernanceRehearsal.model_validate(missing_dimension)

    mixed_domain = payload()
    mixed_domain["metrics"]["fingerprint_outcomes"][0] = "CORRECT"
    with pytest.raises(ValidationError):
        ValidationGovernanceRehearsal.model_validate(mixed_domain)

    duplicate_dimension = payload()
    duplicate_dimension["sampling"]["dimensions"].append("CORE_FAMILY")
    with pytest.raises(ValidationError, match="sampling dimensions"):
        ValidationGovernanceRehearsal.model_validate(duplicate_dimension)


def test_canonical_protocol_links_governance_pack_without_approving_collection():
    protocol = PROTOCOL_DOC.read_text(encoding="utf-8")
    governance = GOVERNANCE_DOC.read_text(encoding="utf-8")

    assert "VALIDATION_GOVERNANCE.md" in protocol
    assert "real-client collection remains blocked" in governance
    assert "collection_authorized` remains `false`" in governance
    assert "- [x] named data controller and research owner" in protocol
    assert "- [ ] consent text and authorization record;" in protocol
    assert "`LOGIALOG SARL AU`" in governance
    assert "`logialog-research-owner-01`" in governance
    assert "Abdelmoula Nami" not in governance
