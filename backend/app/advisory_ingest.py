from __future__ import annotations

import hashlib
import json
from datetime import date
from typing import Literal

from packaging.version import Version
from pydantic import BaseModel, Field, HttpUrl

from .advisories import ADVISORY_ADAPTER


class AdvisoryReviewCandidate(BaseModel):
    format: Literal["logialog-advisory-review"] = "logialog-advisory-review"
    format_version: Literal["1.0"] = "1.0"
    review_status: Literal["pending"] = "pending"
    adapter: Literal["friendsofpresta", "prestashop"]
    source_payload_sha256: str
    proposed_record: dict
    review_checks: list[str] = Field(default_factory=lambda: [
        "Confirm the direct upstream source URL.",
        "Confirm affected and fixed version boundaries.",
        "Confirm identifiers, severity and authentication requirements.",
        "Review business-risk wording without adding exploit claims.",
        "Regenerate and review the advisory snapshot manifest.",
    ])


def _required(payload: dict, key: str):
    value = payload.get(key)
    if value is None or value == "":
        raise ValueError(f"Champ upstream obligatoire absent: {key}")
    return value


def propose_advisory(adapter: str, payload: dict, retrieved_at: date) -> AdvisoryReviewCandidate:
    raw_hash = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if adapter == "friendsofpresta":
        cve = str(_required(payload, "cve"))
        proposed = {
            "schema_version": 1,
            "record_id": f"friendsofpresta-{cve}",
            "module": str(_required(payload, "module")),
            "cve": cve,
            "type": str(_required(payload, "type")),
            "cwe": str(_required(payload, "cwe")),
            "cvss": str(_required(payload, "cvss")),
            "affected_max": str(_required(payload, "affected_max")),
            "fixed_version": str(_required(payload, "fixed_version")),
            "authentication_required": _required(payload, "authentication_required"),
            "business_risk": str(_required(payload, "business_risk")),
            "source": str(HttpUrl(str(_required(payload, "source")))),
            "source_authority": "Friends of Presta",
            "published": str(_required(payload, "published")),
            "retrieved_at": retrieved_at.isoformat(),
        }
        Version(proposed["affected_max"])
        Version(proposed["fixed_version"])
    elif adapter == "prestashop":
        release = str(_required(payload, "release"))
        proposed = {
            "schema_version": 1,
            "record_id": f"prestashop-core-{release}-security-release",
            "product": "PrestaShop Core",
            "release": release,
            "published": str(_required(payload, "published")),
            "retrieved_at": retrieved_at.isoformat(),
            "summary": str(_required(payload, "summary")),
            "source": str(HttpUrl(str(_required(payload, "source")))),
            "source_authority": "PrestaShop Project",
        }
        Version(release)
    else:
        raise ValueError(f"Adapter inconnu: {adapter}")
    ADVISORY_ADAPTER.validate_python(proposed)
    return AdvisoryReviewCandidate(adapter=adapter, source_payload_sha256=raw_hash, proposed_record=proposed)
