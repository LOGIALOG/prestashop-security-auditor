from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal, Protocol, Sequence, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from .extractors import Extracted
from .models import Evidence
from .redaction import redact_text, redact_url

EXTRACTOR_API_VERSION = "1.0"
MAX_PLUGINS = 10
MAX_SIGNALS_PER_PLUGIN = 100
PLUGIN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


@dataclass(frozen=True)
class ExtractionContext:
    url: str
    body: str
    content_type: str


class PluginSignal(BaseModel):
    """A bounded location signal. Community plugins cannot assert a trusted version."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["active_module", "asset_module", "theme"]
    name: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    confidence: Literal["low", "medium"] = "low"
    method: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    start: int = Field(ge=0)
    end: int = Field(gt=0)

    @model_validator(mode="after")
    def bounded_span(self) -> "PluginSignal":
        if self.end <= self.start or self.end - self.start > 512:
            raise ValueError("Le signal doit pointer vers 1 à 512 caractères")
        return self


@runtime_checkable
class ExtractorPlugin(Protocol):
    plugin_id: str
    api_version: str

    def extract(self, context: ExtractionContext) -> Sequence[PluginSignal | dict]: ...


SIGNAL_ADAPTER = TypeAdapter(PluginSignal)


class ExtractorPluginError(ValueError):
    pass


class UnsupportedExtractorPluginError(ExtractorPluginError):
    def __init__(self, plugin_id: str, api_version: str):
        self.plugin_id = plugin_id
        self.api_version = api_version
        super().__init__(f"Version SDK incompatible pour {plugin_id}: {api_version}")


def validate_extractor_plugins(plugins: Sequence[ExtractorPlugin]) -> None:
    if len(plugins) > MAX_PLUGINS:
        raise ExtractorPluginError(f"Maximum {MAX_PLUGINS} extracteurs par audit")
    seen_ids: set[str] = set()
    for plugin in plugins:
        plugin_id = getattr(plugin, "plugin_id", "")
        api_version = getattr(plugin, "api_version", "")
        if not PLUGIN_ID.fullmatch(plugin_id):
            raise ExtractorPluginError("plugin_id invalide")
        if plugin_id in seen_ids:
            raise ExtractorPluginError(f"plugin_id dupliqué: {plugin_id}")
        if api_version != EXTRACTOR_API_VERSION:
            raise UnsupportedExtractorPluginError(plugin_id, api_version)
        seen_ids.add(plugin_id)


def run_extractor_plugins(
    url: str,
    body: str,
    content_type: str,
    plugins: Sequence[ExtractorPlugin],
) -> list[Extracted]:
    validate_extractor_plugins(plugins)
    context = ExtractionContext(url=url, body=body, content_type=content_type)
    output: list[Extracted] = []
    for plugin in plugins:
        plugin_id = getattr(plugin, "plugin_id", "")
        try:
            raw_signals = list(plugin.extract(context))
        except Exception as exc:
            raise ExtractorPluginError(f"Échec de l’extracteur {plugin_id}") from exc
        if len(raw_signals) > MAX_SIGNALS_PER_PLUGIN:
            raise ExtractorPluginError(f"{plugin_id} dépasse {MAX_SIGNALS_PER_PLUGIN} signaux par ressource")
        for raw_signal in raw_signals:
            try:
                signal = SIGNAL_ADAPTER.validate_python(raw_signal)
            except Exception as exc:
                raise ExtractorPluginError(f"Signal invalide produit par {plugin_id}") from exc
            if signal.end > len(body):
                raise ExtractorPluginError(f"Signal hors limites produit par {plugin_id}")
            excerpt = redact_text(body[signal.start:signal.end])
            evidence = Evidence(
                url=redact_url(url),
                evidence_type=signal.kind,
                excerpt=excerpt,
                response_sha256=hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
                confidence=signal.confidence,
                detection_method=f"plugin:{plugin_id}:{signal.method}",
            )
            output.append(Extracted(signal.kind, signal.name.casefold(), None, evidence))
    return output
