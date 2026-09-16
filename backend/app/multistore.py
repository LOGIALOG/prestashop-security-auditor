from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

import httpx

from .models import AuditRequest, AuditResult
from .scanner import PassiveScanner, normalized_origin


class ShopScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shop_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    name: str = Field(min_length=1, max_length=100)
    target: HttpUrl
    public_pages: list[HttpUrl] = Field(default_factory=list, max_length=10)
    max_requests: int = Field(default=20, ge=1, le=20)

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        value = value.strip()
        if not value or any(character in value for character in "<>\r\n"):
            raise ValueError("Le nom de boutique contient des caractères interdits")
        return value

    @model_validator(mode="after")
    def pages_stay_on_shop_origin(self) -> "ShopScope":
        origin = normalized_origin(str(self.target))
        if any(normalized_origin(str(page)) != origin for page in self.public_pages):
            raise ValueError("Chaque page publique doit rester sur l’origine exacte de sa boutique")
        return self


class MultistoreManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    authorization_confirmed: bool
    delay_seconds: float = Field(default=1.0, ge=1.0, le=10.0)
    shops: list[ShopScope] = Field(min_length=1, max_length=10)

    @field_validator("authorization_confirmed")
    @classmethod
    def authorization_required(cls, value: bool) -> bool:
        if not value:
            raise ValueError("Une autorisation explicite est obligatoire pour toutes les boutiques")
        return value

    @model_validator(mode="after")
    def unique_bounded_scopes(self) -> "MultistoreManifest":
        identifiers = [shop.shop_id.casefold() for shop in self.shops]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Chaque boutique doit avoir un shop_id unique")
        if sum(shop.max_requests for shop in self.shops) > 100:
            raise ValueError("Le budget multistore total ne peut pas dépasser 100 requêtes")
        return self


class ShopAudit(BaseModel):
    shop_id: str
    name: str
    audit: AuditResult


class MultistoreScannerError(OSError):
    """Scanner runtime failure that keeps already completed shops.

    Only wraps the runtime-error family (OSError, httpx.HTTPError) so
    invalid-input errors (ValueError, ValidationError, AuditPolicyError)
    keep propagating unwrapped toward EXIT_INVALID_INPUT. Never fabricates
    an AuditResult for the failed shop.
    """

    def __init__(
        self,
        failed_shop_id: str,
        partial_shops: list[ShopAudit],
        cause: BaseException,
    ) -> None:
        self.failed_shop_id = failed_shop_id
        self.partial_shops: tuple[ShopAudit, ...] = tuple(partial_shops)
        super().__init__(f"Echec du scanner multistore pour la boutique '{failed_shop_id}': {cause}")


class MultistoreAudit(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    batch_id: str
    started_at: datetime
    completed_at: datetime
    shops: list[ShopAudit]

    def portable_export(self) -> dict:
        return {
            "format": "logialog-multistore-audit",
            "format_version": self.schema_version,
            "batch_id": self.batch_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "shops": [
                {
                    "shop_id": shop.shop_id,
                    "name": shop.name,
                    "audit": shop.audit.model_dump(mode="json", exclude={"report_path"}),
                }
                for shop in self.shops
            ],
        }


def load_multistore_manifest(path: Path) -> MultistoreManifest:
    if not path.is_file():
        raise ValueError(f"Manifest multistore introuvable: {path}")
    return MultistoreManifest.model_validate_json(path.read_text(encoding="utf-8"))


async def run_multistore(
    manifest: MultistoreManifest,
    scanner_factory: Callable[[], PassiveScanner] = PassiveScanner,
) -> MultistoreAudit:
    started_at = datetime.now(timezone.utc)
    results: list[ShopAudit] = []
    for shop in manifest.shops:
        request = AuditRequest(
            target=shop.target,
            authorization_confirmed=manifest.authorization_confirmed,
            public_pages=shop.public_pages,
            max_requests=shop.max_requests,
            delay_seconds=manifest.delay_seconds,
        )
        try:
            audit = await scanner_factory().run(request)
        except (OSError, httpx.HTTPError) as exc:
            raise MultistoreScannerError(shop.shop_id, results, exc) from exc
        results.append(ShopAudit(shop_id=shop.shop_id, name=shop.name, audit=audit))
        if audit.scan_completeness != "COMPLETED":
            break
    return MultistoreAudit(
        batch_id=str(uuid4()),
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
        shops=results,
    )
