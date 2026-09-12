from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from typing import Sequence

from .advisories import correlate
from .extractors import Extracted, extract_asset_urls, extract_html
from .extractor_sdk import ExtractorPlugin, run_extractor_plugins
from .models import AuditRequest, AuditResult, Evidence, Finding, ScanIssue, Status
from .redaction import redact_url
from .scoring import calculate_score

SECURITY_HEADERS = ["content-security-policy", "strict-transport-security", "permissions-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "server", "cf-ray", "cf-cache-status", "x-litespeed-cache"]
REQUIRED_HEADERS = set(SECURITY_HEADERS[:6])


class AuditPolicyError(ValueError):
    pass


def normalized_origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme.lower(), (parts.hostname or "").lower(), port


def assert_allowed(url: str, origin: tuple[str, str, int]) -> None:
    if normalized_origin(url) != origin:
        raise AuditPolicyError("URL hors du domaine autorisé")


def reject_private_target(host: str) -> None:
    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise AuditPolicyError("Les cibles privées ou locales ne sont pas autorisées pour l'audit distant")


def cookie_metadata(headers: httpx.Headers) -> list[dict[str, str | bool]]:
    output = []
    for raw in headers.get_list("set-cookie"):
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        lowered = {p.lower() for p in parts[1:]}
        same_site = next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), "Non défini")
        output.append({"name": name, "secure": "secure" in lowered, "http_only": "httponly" in lowered, "same_site": same_site})
    return output


class PassiveScanner:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None, plugins: Sequence[ExtractorPlugin] = ()):
        self.transport = transport
        self.plugins = tuple(plugins)
        self.methods: list[str] = []

    async def run(self, request: AuditRequest) -> AuditResult:
        start = datetime.now(timezone.utc)
        root = str(request.target).rstrip("/") + "/"
        origin = normalized_origin(root)
        urls = [root, root.rstrip("/") + "/robots.txt"] + [str(u) for u in request.public_pages]
        for url in urls:
            assert_allowed(url, origin)
        if self.transport is None:
            await asyncio.to_thread(reject_private_target, origin[1])
        extracted: list[Extracted] = []
        headers_seen: dict[str, str] = {}
        cookies: list[dict[str, str | bool]] = []
        scan_issues: list[ScanIssue] = []
        root_hash = ""
        visited: set[str] = set()
        attempted: list[str] = []
        async with httpx.AsyncClient(transport=self.transport, follow_redirects=False, timeout=12, headers={"User-Agent": "LOGIALOG-Passive-Auditor/1.0"}) as client:
            while urls and len(attempted) < request.max_requests:
                url = urls.pop(0)
                if url in visited:
                    continue
                assert_allowed(url, origin)
                if attempted:
                    await asyncio.sleep(request.delay_seconds)
                self.methods.append("GET")
                attempted.append(url)
                try:
                    response = await client.get(url)
                except httpx.TransportError:
                    scan_issues.append(ScanIssue(kind="TRANSPORT_ERROR", url=redact_url(url)))
                    continue
                visited.add(url)
                if 300 <= response.status_code < 400 and response.headers.get("location"):
                    destination = str(response.url.join(response.headers["location"]))
                    assert_allowed(destination, origin)
                    urls.append(destination)
                    continue
                if response.status_code == 404 and urlsplit(url).path.endswith("/robots.txt"):
                    continue
                if response.status_code >= 300:
                    scan_issues.append(
                        ScanIssue(kind="HTTP_STATUS", url=redact_url(url), status_code=response.status_code)
                    )
                    continue
                if url == root:
                    root_hash = hashlib.sha256(response.content).hexdigest()
                    headers_seen = {name: response.headers.get(name, "Absent") for name in SECURITY_HEADERS}
                    cookies = cookie_metadata(response.headers)
                content_type = response.headers.get("content-type", "")
                body = response.text[:2_000_000]
                extracted.extend(extract_html(url, body, content_type))
                extracted.extend(run_extractor_plugins(url, body, content_type, self.plugins))
                if "html" in content_type:
                    for asset in extract_asset_urls(url, body):
                        try:
                            assert_allowed(asset, origin)
                        except AuditPolicyError:
                            continue
                        if len(attempted) + len(urls) < request.max_requests:
                            urls.append(asset)
        findings = correlate(extracted)
        for name, value in headers_seen.items():
            if name in REQUIRED_HEADERS and value == "Absent":
                evidence = Evidence(url=root, evidence_type="http_header", excerpt=f"{name}: Absent", response_sha256=root_hash, confidence="high", detection_method="response_header_check")
                findings.append(Finding(subject=name, status=Status.HARDENING, severity="Faible", interpretation=f"En-tête {name} absent; aucune exploitation démontrée.", business_risk="Réduction de la défense en profondeur du navigateur.", remediation=f"Ajouter {name} après tests de compatibilité.", evidence=[evidence]))
        score = calculate_score(findings)
        return AuditResult(
            is_demo=False,
            target=root.rstrip("/"),
            id=str(uuid4()),
            domain=origin[1],
            started_at=start,
            completed_at=datetime.now(timezone.utc),
            request_count=len(attempted),
            scope=sorted(set(attempted)),
            findings=findings,
            headers=headers_seen,
            cookies=cookies,
            scan_completeness="INCOMPLETE" if scan_issues else "COMPLETED",
            scan_issues=scan_issues,
            score=score,
        )
