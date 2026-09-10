from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urljoin

from .models import Evidence
from .redaction import redact_text, redact_url

MODULE_PATH = re.compile(r"/(?:modules|module)/([a-zA-Z0-9_-]+)(?:/|\b)")
DATA_MODULE = re.compile(r"data-module-name=[\"']([a-zA-Z0-9_-]+)[\"']", re.I)
PS_VERSION = re.compile(r"\bps[_-](\d)(\d)(\d)\b", re.I)
GENERIC_VERSION = re.compile(r'(?i)(?:version|ver|v)[\s:="\']+(\d+(?:\.\d+){1,3})')
THEME = re.compile(r"/themes/([a-zA-Z0-9_-]+)/")
SCRIPT_VAR = re.compile(r"(?i)\b(?:moduleName|module_name|prestashop\.modules\.)(?:\s*[:=.]\s*)[\"']?([a-z0-9_-]+)")
KNOWN_ASSET_MODULES = {
    "ybc_blog", "newsletterpro", "ets_superspeed", "adpmicrodatos", "blockwishlist",
    "ps_emailsubscription", "ps_emailalerts", "ps_feeder", "angarbanners", "angarslider",
    "ps_customersignin", "ps_shoppingcart", "productcomments", "codfee", "smartblog", "leopartsfilter",
}


@dataclass(frozen=True)
class Extracted:
    kind: str
    name: str
    version: str | None
    evidence: Evidence


def _evidence(url: str, body: str, kind: str, excerpt: str, confidence: str, method: str) -> Evidence:
    return Evidence(
        url=redact_url(url), evidence_type=kind, excerpt=redact_text(excerpt),
        response_sha256=hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
        confidence=confidence, detection_method=method,
    )


def _nearby_version(body: str, name: str, detected_names: set[str]) -> str | None:
    match = re.search(rf'(?is)(?:{re.escape(name)}.{{0,100}}(?:version|ver|v)[\s:="\']+(\d+(?:\.\d+){{1,3}})|(?:version|ver|v)[\s:="\']+(\d+(?:\.\d+){{1,3}}).{{0,100}}{re.escape(name)})', body)
    if not match:
        return None
    segment = match.group(0).casefold()
    if any(other != name.casefold() and re.search(rf"(?<![a-z0-9_-]){re.escape(other)}(?![a-z0-9_-])", segment) for other in detected_names):
        return None
    return next((group for group in match.groups() if group), None)


def extract_html(url: str, body: str, content_type: str = "text/html") -> list[Extracted]:
    results: list[Extracted] = []
    is_asset = "javascript" in content_type or "css" in content_type or url.lower().split("?")[0].endswith((".js", ".css"))
    matches = [(m.group(1), m.group(0), "module_path") for m in MODULE_PATH.finditer(body)]
    matches += [(m.group(1), m.group(0), "data_module_name") for m in DATA_MODULE.finditer(body)]
    matches += [(m.group(1), m.group(0), "javascript_namespace") for m in SCRIPT_VAR.finditer(body)]
    if is_asset:
        for module in KNOWN_ASSET_MODULES:
            token = re.search(rf"(?<![a-z0-9_]){re.escape(module)}(?![a-z0-9_])", body, re.I)
            if token:
                matches.append((module, token.group(0), "compiled_asset_identifier"))
    detected_names = {name.casefold() for name, _, _ in matches}
    for name, excerpt, method in matches:
        status_kind = "asset_module" if is_asset else "active_module"
        confidence = "low" if is_asset else ("high" if method != "javascript_namespace" else "medium")
        window_start = max(0, body.find(excerpt) - 100)
        window = body[window_start:window_start + 420]
        version = _nearby_version(body, name, detected_names)
        if is_asset and name.lower() == "newsletterpro" and version:
            confidence = "medium"
        results.append(Extracted(status_kind, name.lower(), version, _evidence(url, body, status_kind, window, confidence, method)))
    for match in PS_VERSION.finditer(body):
        version = ".".join(match.groups())
        results.append(Extracted("prestashop_version", "prestashop", version, _evidence(url, body, "html_fingerprint", match.group(0), "medium", "ps_html_class")))
    for match in THEME.finditer(body):
        results.append(Extracted("theme", match.group(1), None, _evidence(url, body, "theme_path", match.group(0), "high", "theme_asset_path")))
    return _deduplicate(results)


def extract_asset_urls(base_url: str, body: str) -> list[str]:
    candidates = re.findall(r"(?:src|href)=[\"']([^\"']+\.(?:css|js)(?:\?[^\"']*)?)[\"']", body, re.I)
    return list(dict.fromkeys(urljoin(base_url, item) for item in candidates))


def _deduplicate(items: list[Extracted]) -> list[Extracted]:
    unique: dict[tuple[str, str, str | None, str], Extracted] = {}
    for item in items:
        key = (item.kind, item.name, item.version, item.evidence.url)
        unique.setdefault(key, item)
    return list(unique.values())
