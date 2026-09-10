import copy
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.app.validation_corpus import ValidationCorpus, load_validation_corpus


ROOT = Path(__file__).parents[1]
VALID_FIXTURE = ROOT / "tests" / "fixtures" / "validation-corpus.synthetic.json"
INVALID_PRIVACY_FIXTURE = ROOT / "tests" / "fixtures" / "validation-corpus.invalid-privacy.json"
SCHEMA_PATH = ROOT / "docs" / "validation-corpus-v1.schema.json"


def valid_payload() -> dict:
    return json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))


def test_synthetic_corpus_covers_required_outcomes_tiers_and_strata():
    corpus = load_validation_corpus(VALID_FIXTURE)

    assert corpus.synthetic is True
    assert corpus.real_client_data is False
    assert corpus.real_domains is False
    assert corpus.external_collection is False
    assert {record.fingerprint_outcome for record in corpus.records} == {
        "TP",
        "FP",
        "FN",
        "CORRECT_ABSTENTION",
        "INDETERMINATE",
        "GROUND_TRUTH_CONFLICT",
    }
    assert {record.advisory_outcome for record in corpus.records} == {
        "CORRECT",
        "INCORRECT",
        "UNKNOWN",
        "NOT_APPLICABLE",
    }
    assert {record.detector.confidence_tier for record in corpus.records} == {"HIGH", "MEDIUM", "LOW"}
    assert {record.strata.core_family for record in corpus.records} == {"PS_1_7", "PS_8", "PS_9"}
    assert {record.strata.hosting for record in corpus.records} == {"SHARED", "VPS_DEDICATED", "MANAGED", "CONTAINERIZED"}
    assert {record.strata.edge_layer for record in corpus.records} == {"NONE", "CDN_ONLY", "WAF_ONLY", "CDN_WAF"}
    assert {record.strata.module_provenance for record in corpus.records} == {"OFFICIAL_VENDOR", "COMMUNITY", "CUSTOM_PRIVATE"}
    assert {record.strata.version_exposure for record in corpus.records} == {"EXACT", "PARTIAL", "ABSENT", "CONFLICTING_SPOOFED"}
    assert {record.strata.asset_condition for record in corpus.records} == {"CURRENT", "STALE_CACHE", "RENAMED", "MINIFIED_BUNDLED", "REMOVED"}
    assert all(record.scope.network_access is False and record.scope.requests_sent == 0 for record in corpus.records)


def test_published_json_schema_matches_strict_model():
    published = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert published == ValidationCorpus.model_json_schema(mode="validation")
    assert published["$id"] == "urn:logialog:schema:synthetic-validation-corpus:1.0"
    assert published["additionalProperties"] is False


def test_malformed_record_and_duplicate_identifier_fail():
    malformed = valid_payload()
    del malformed["records"][0]["shop_id"]
    with pytest.raises(ValidationError):
        ValidationCorpus.model_validate(malformed)

    duplicate = valid_payload()
    duplicate["records"][1]["observation_id"] = duplicate["records"][0]["observation_id"]
    with pytest.raises(ValidationError, match="observation IDs must be unique"):
        ValidationCorpus.model_validate(duplicate)

    unknown_field = valid_payload()
    unknown_field["records"][0]["unapproved_note"] = "synthetic-note"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ValidationCorpus.model_validate(unknown_field)


@pytest.mark.parametrize("invalid_case", json.loads(INVALID_PRIVACY_FIXTURE.read_text(encoding="utf-8")))
def test_forbidden_privacy_fields_and_values_fail(invalid_case):
    payload = valid_payload()
    record = payload["records"][0]
    parts = invalid_case["record_field"].split(".")
    target = record
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = invalid_case["value"]

    with pytest.raises(ValidationError, match="Forbidden privacy"):
        ValidationCorpus.model_validate(payload)


def test_unknown_enums_and_mixed_outcome_domains_fail():
    unknown_tier = valid_payload()
    unknown_tier["records"][0]["detector"]["confidence_tier"] = "VERY_HIGH"
    with pytest.raises(ValidationError):
        ValidationCorpus.model_validate(unknown_tier)

    fingerprint_uses_advisory_domain = valid_payload()
    fingerprint_uses_advisory_domain["records"][0]["fingerprint_outcome"] = "CORRECT"
    with pytest.raises(ValidationError):
        ValidationCorpus.model_validate(fingerprint_uses_advisory_domain)

    advisory_uses_fingerprint_domain = valid_payload()
    advisory_uses_fingerprint_domain["records"][0]["advisory_outcome"] = "TP"
    with pytest.raises(ValidationError):
        ValidationCorpus.model_validate(advisory_uses_fingerprint_domain)


def test_synthetic_corpus_requires_no_real_identifiers_or_customer_data():
    serialized = VALID_FIXTURE.read_text(encoding="utf-8")

    assert "http://" not in serialized and "https://" not in serialized
    assert not re.search(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b", serialized)
    assert not re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", serialized)
    assert not re.search(r"[a-zA-Z]:\\", serialized)
    assert all(value not in serialized.casefold() for value in ("cookie", "password", "credential", "customer_name"))
    assert "synthetic-shop-" in serialized


def test_validation_has_no_network_side_effect(monkeypatch):
    def reject_network(*_args, **_kwargs):
        raise AssertionError("synthetic corpus validation must not access a network")

    monkeypatch.setattr("socket.getaddrinfo", reject_network)
    monkeypatch.setattr("httpx.Client", reject_network)
    monkeypatch.setattr("httpx.AsyncClient", reject_network)

    corpus = load_validation_corpus(VALID_FIXTURE)

    assert len(corpus.records) == 6


def test_privacy_assertions_cannot_be_enabled():
    payload = copy.deepcopy(valid_payload())
    payload["real_client_data"] = True
    with pytest.raises(ValidationError):
        ValidationCorpus.model_validate(payload)
