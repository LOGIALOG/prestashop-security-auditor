from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

COLOR_PATTERN = re.compile(r"^#[0-9a-fA-F]{6}$")
LOGO_PATTERN = re.compile(r"^data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$")
MAX_LOGO_BYTES = 256 * 1024


class ReportProfile(BaseModel):
    """Validated presentation settings; engine provenance is intentionally not configurable."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    brand_name: str = Field(default="LOGIALOG SARL AU", min_length=1, max_length=80)
    report_title: str = Field(default="Rapport d’audit passif PrestaShop", min_length=1, max_length=120)
    primary_color: str = "#0b6ffb"
    accent_color: str = "#45b800"
    contact_url: HttpUrl | None = None
    logo_data_uri: str | None = Field(default=None, max_length=360_000)

    @field_validator("brand_name", "report_title")
    @classmethod
    def safe_text(cls, value: str) -> str:
        value = value.strip()
        if not value or any(character in value for character in "<>\r\n"):
            raise ValueError("Le texte du profil ne peut pas contenir de balise ou de saut de ligne")
        return value

    @field_validator("primary_color", "accent_color")
    @classmethod
    def safe_color(cls, value: str) -> str:
        if not COLOR_PATTERN.fullmatch(value):
            raise ValueError("Une couleur doit utiliser le format hexadécimal #RRGGBB")
        return value.lower()

    @field_validator("logo_data_uri")
    @classmethod
    def safe_embedded_logo(cls, value: str | None) -> str | None:
        if value is None:
            return None
        match = LOGO_PATTERN.fullmatch(value)
        if match is None:
            raise ValueError("Le logo doit être une image PNG, JPEG ou WebP encodée en data URI base64")
        try:
            decoded = base64.b64decode(match.group(2), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Le logo base64 est invalide") from exc
        if not decoded or len(decoded) > MAX_LOGO_BYTES:
            raise ValueError("Le logo doit contenir entre 1 octet et 256 Kio")
        return value


def load_report_profile(path: Path) -> ReportProfile:
    if not path.is_file():
        raise ValueError(f"Profil de rapport introuvable: {path}")
    return ReportProfile.model_validate_json(path.read_text(encoding="utf-8"))
