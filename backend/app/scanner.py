from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from typing import Sequence

from .advisories import advisory_snapshot_identity, correlate
from .extractors import Extracted, extract_asset_urls, extract_html
from .extractor_sdk import (
    ExtractorPlugin,
    ExtractorPluginError,
    UnsupportedExtractorPluginError,
    run_extractor_plugins,
    validate_extractor_plugins,
)
from .models import (
    REQUIRED_HEADERS,
    SECURITY_HEADERS,
    AuditRequest,
    AuditResult,
    Evidence,
    Finding,
    HttpMetadataObservation,
    ScanIssue,
    Status,
)
from .network_policy import EgressPolicyError, build_safe_async_client
from .redaction import redact_parameters, redact_text, redact_url
from .scoring import calculate_score


class AuditPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ScanResource:
    url: str
    required: bool
    check_id: str
    redirect_ancestry: frozenset[str] = frozenset()


@dataclass(frozen=True)
class CheckDeclaration:
    check_id: str
    required: bool
    target: str

    @property
    def identity(self) -> tuple[str, str]:
        return (self.check_id, self.target)


@dataclass(frozen=True)
class CheckExecutionResult:
    state: str
    reason: str | None = None


TERMINAL_STATES = frozenset({"SUCCESS_WITH_EVIDENCE", "SUCCESS_NO_FINDING", "FAILED_OBSERVATION", "NOT_EXECUTED"})
COVERAGE_FAILURE_STATES = frozenset({"FAILED_OBSERVATION", "NOT_EXECUTED"})
CHECK_STATE_SUCCESS_WITH_EVIDENCE = "SUCCESS_WITH_EVIDENCE"
CHECK_STATE_SUCCESS_NO_FINDING = "SUCCESS_NO_FINDING"
CHECK_STATE_FAILED_OBSERVATION = "FAILED_OBSERVATION"
CHECK_STATE_NOT_EXECUTED = "NOT_EXECUTED"
REASON_ROOT_UNAVAILABLE = "root-unavailable"


class CheckExecutionRegistry:
    def __init__(self, declarations: Sequence[CheckDeclaration]) -> None:
        self._declarations: dict[tuple[str, str], CheckDeclaration] = {}
        for declaration in declarations:
            if declaration.identity in self._declarations:
                raise ValueError("Déclaration de contrôle dupliquée")
            self._declarations[declaration.identity] = declaration
        self._results: dict[tuple[str, str], CheckExecutionResult] = {}

    @property
    def declarations(self) -> tuple[CheckDeclaration, ...]:
        return tuple(self._declarations.values())

    def record(self, declaration: CheckDeclaration, state: str, reason: str | None = None) -> None:
        if state not in TERMINAL_STATES:
            raise ValueError("État terminal de contrôle invalide")
        identity = declaration.identity
        if identity not in self._declarations:
            raise ValueError("Résultat pour une déclaration de contrôle inconnue")
        if identity in self._results:
            raise ValueError("Un contrôle ne peut produire qu'un seul résultat terminal")
        self._results[identity] = CheckExecutionResult(state=state, reason=reason)

    def result_for(self, declaration: CheckDeclaration) -> CheckExecutionResult | None:
        return self._results.get(declaration.identity)

    def finalize(self) -> tuple[tuple[CheckDeclaration, CheckExecutionResult], ...]:
        terminal: list[tuple[CheckDeclaration, CheckExecutionResult]] = []
        for declaration in self._declarations.values():
            result = self._results.get(declaration.identity)
            if result is None:
                result = CheckExecutionResult(state=CHECK_STATE_NOT_EXECUTED, reason="missing-terminal-result")
            terminal.append((declaration, result))
        return tuple(terminal)



@dataclass(frozen=True)
class UrlObservation:
    terminal_success: bool = False
    failed_optional: bool = False
    failed_required: bool = False
    redirect_destination: str | None = None


def normalized_origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme.lower(), (parts.hostname or "").lower(), port


def assert_allowed(url: str, origin: tuple[str, str, int]) -> None:
    if normalized_origin(url) != origin:
        raise AuditPolicyError("URL hors du domaine autorisé")


def issue_detail(exc: BaseException, *, check_id: str | None = None, include_message: bool = False) -> str:
    parts = [type(exc).__name__]
    cause = exc.__cause__
    if cause is not None:
        parts.append(type(cause).__name__)
        if include_message:
            parts.append(str(cause))
    elif include_message:
        parts.append(str(exc))
    if check_id:
        parts.append(check_id)
    return redact_text(redact_parameters(": ".join(parts)), limit=200)


def cookie_metadata(headers: httpx.Headers) -> list[dict[str, str | bool]]:
    output = []
    for raw in headers.get_list("set-cookie"):
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        lowered = {p.lower() for p in parts[1:]}
        same_site = next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), "Non défini")
        output.append({"name": name, "secure": "secure" in lowered, "http_only": "httponly" in lowered, "same_site": same_site})
    return output


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def header_projection(headers: httpx.Headers) -> list[dict[str, object]]:
    projection: list[dict[str, object]] = []
    for name in SECURITY_HEADERS:
        value = headers.get(name)
        if value is None:
            projection.append({"name": name, "present": False, "value": None})
        else:
            projection.append({"name": name, "present": True, "value": value})
    return projection


def cookie_projection(cookies: list[dict[str, str | bool]]) -> list[dict[str, object]]:
    return [
        {"name": cookie["name"], "secure": cookie["secure"], "http_only": cookie["http_only"], "same_site": cookie["same_site"]}
        for cookie in cookies
    ]


class PassiveScanner:
    def __init__(self, plugins: Sequence[ExtractorPlugin] = ()):
        self.plugins = tuple(plugins)
        self.methods: list[str] = []

    async def run(self, request: AuditRequest) -> AuditResult:
        start = datetime.now(timezone.utc)
        root = str(request.target).rstrip("/") + "/"
        origin = normalized_origin(root)
        candidates = [
            ScanResource(root, True, "http:root"),
            *[ScanResource(str(url), True, "http:public-page") for url in request.public_pages],
            ScanResource(root.rstrip("/") + "/robots.txt", False, "http:robots"),
        ]
        resources: list[ScanResource] = []
        for candidate in candidates:
            if not any(resource.url == candidate.url for resource in resources):
                resources.append(candidate)
        for resource in resources:
            assert_allowed(resource.url, origin)
        extracted: list[Extracted] = []
        headers_seen: dict[str, str] = {}
        cookies: list[dict[str, str | bool]] = []
        scan_issues: list[ScanIssue] = []
        active_plugins = self.plugins
        try:
            validate_extractor_plugins(active_plugins)
        except UnsupportedExtractorPluginError as exc:
            scan_issues.append(
                ScanIssue(
                    kind="CHECK_NOT_TESTED",
                    url=redact_url(root),
                    required=True,
                    check_id=f"plugin:{exc.plugin_id}",
                )
            )
            active_plugins = ()
        root_hash = ""
        http_observation: HttpMetadataObservation | None = None
        observations: dict[str, UrlObservation] = {}
        attempted: list[str] = []

        security_headers_declaration = CheckDeclaration(
            check_id="http:security-headers",
            required=True,
            target=root.rstrip("/"),
        )
        execution_registry = CheckExecutionRegistry([security_headers_declaration])

        def record_failure(url: str, required: bool) -> None:
            previous = observations.get(url)
            observations[url] = UrlObservation(
                failed_optional=(previous.failed_optional if previous else False) or not required,
                failed_required=(previous.failed_required if previous else False) or required,
            )

        def schedule_redirect(resource: ScanResource, source: str, destination: str) -> None:
            redirect_ancestry = resource.redirect_ancestry | {source}
            if destination in redirect_ancestry:
                scan_issues.append(
                    ScanIssue(
                        kind="REDIRECT_LOOP",
                        url=redact_url(destination),
                        required=resource.required,
                        check_id=resource.check_id,
                    )
                )
                return
            resources.append(
                ScanResource(
                    destination,
                    resource.required,
                    resource.check_id,
                    redirect_ancestry=redirect_ancestry,
                )
            )

        async with build_safe_async_client(timeout=12, headers={"User-Agent": "LOGIALOG-Passive-Auditor/1.0"}) as client:
            while resources:
                resource = resources.pop(0)
                url = resource.url
                observation = observations.get(url)
                if observation is not None:
                    if observation.terminal_success:
                        continue
                    if observation.redirect_destination is not None:
                        schedule_redirect(resource, url, observation.redirect_destination)
                        continue
                    if observation.failed_required or (observation.failed_optional and not resource.required):
                        continue
                if len(attempted) >= request.max_requests:
                    if resource.required:
                        resources.insert(0, resource)
                        break
                    continue
                assert_allowed(url, origin)
                if attempted:
                    await asyncio.sleep(request.delay_seconds)
                self.methods.append("GET")
                attempted.append(url)
                try:
                    response = await client.get(url)
                except (httpx.TransportError, EgressPolicyError) as exc:
                    record_failure(url, resource.required)
                    scan_issues.append(
                        ScanIssue(
                            kind="TRANSPORT_ERROR",
                            url=redact_url(url),
                            required=resource.required,
                            detail=issue_detail(exc, include_message=True),
                            captured_at=datetime.now(timezone.utc),
                        )
                    )
                    continue
                if 300 <= response.status_code < 400 and response.headers.get("location"):
                    destination = str(response.url.join(response.headers["location"]))
                    assert_allowed(destination, origin)
                    observations[url] = UrlObservation(redirect_destination=destination)
                    schedule_redirect(resource, url, destination)
                    continue
                if response.status_code == 404 and urlsplit(url).path.endswith("/robots.txt") and not resource.required:
                    record_failure(url, required=False)
                    continue
                if response.status_code >= 300:
                    record_failure(url, resource.required)
                    scan_issues.append(
                        ScanIssue(
                            kind="HTTP_STATUS",
                            url=redact_url(url),
                            required=resource.required,
                            status_code=response.status_code,
                        )
                    )
                    continue
                if resource.check_id == "http:root" and http_observation is None:
                    root_hash = hashlib.sha256(response.content).hexdigest()
                    headers_seen = {name: response.headers.get(name, "Absent") for name in SECURITY_HEADERS}
                    cookies = cookie_metadata(response.headers)
                    projection = header_projection(response.headers)
                    http_observation = HttpMetadataObservation(
                        url=redact_url(str(response.url)),
                        captured_at=datetime.now(timezone.utc),
                        observed=True,
                        absent_headers=[entry["name"] for entry in projection if not entry["present"]],
                        headers_sha256=_canonical_digest(projection),
                        cookies_sha256=_canonical_digest(cookie_projection(cookies)),
                    )
                content_type = response.headers.get("content-type", "")
                body = response.text[:2_000_000]
                try:
                    extracted.extend(extract_html(url, body, content_type))
                except Exception as exc:
                    record_failure(url, resource.required)
                    scan_issues.append(
                        ScanIssue(
                            kind="EXTRACTOR_ERROR",
                            url=redact_url(url),
                            required=resource.required,
                            check_id="builtin:html-extractor",
                            detail=issue_detail(exc, check_id="builtin:html-extractor"),
                            captured_at=datetime.now(timezone.utc),
                        )
                    )
                    continue
                try:
                    extracted.extend(run_extractor_plugins(url, body, content_type, active_plugins))
                except ExtractorPluginError as exc:
                    record_failure(url, resource.required)
                    scan_issues.append(
                        ScanIssue(
                            kind="EXTRACTOR_ERROR",
                            url=redact_url(url),
                            required=resource.required,
                            check_id="plugin:configured-extractors",
                            detail=issue_detail(exc, check_id="plugin:configured-extractors"),
                            captured_at=datetime.now(timezone.utc),
                        )
                    )
                    continue
                if "html" in content_type:
                    for asset in extract_asset_urls(url, body):
                        try:
                            assert_allowed(asset, origin)
                        except AuditPolicyError:
                            continue
                        queued_urls = {queued.url for queued in resources}
                        if asset not in observations and asset not in queued_urls and len(attempted) + len(resources) < request.max_requests:
                            resources.append(ScanResource(asset, False, "http:discovered-asset"))
                observations[url] = UrlObservation(terminal_success=True)
        pending_required = next((resource for resource in resources if resource.required), None)
        if pending_required is not None:
            scan_issues.append(
                ScanIssue(
                    kind="BUDGET_EXHAUSTED",
                    url=redact_url(pending_required.url),
                    required=True,
                    check_id=pending_required.check_id,
                )
            )
        if http_observation is None:
            http_observation = HttpMetadataObservation(
                url=redact_url(root),
                captured_at=datetime.now(timezone.utc),
                observed=False,
            )
        snapshot = advisory_snapshot_identity()
        findings = correlate(extracted, snapshot.snapshot_sha256)
        if http_observation.observed:
            for name in http_observation.absent_headers:
                if name in REQUIRED_HEADERS:
                    evidence = Evidence(url=http_observation.url, evidence_type="http_header", excerpt=f"{name}: Absent", response_sha256=root_hash, observation_sha256=http_observation.headers_sha256, confidence="high", detection_method="response_header_check")
                    findings.append(Finding(subject=name, status=Status.HARDENING, severity="Faible", interpretation=f"En-tête {name} absent; aucune exploitation démontrée.", business_risk="Réduction de la défense en profondeur du navigateur.", remediation=f"Ajouter {name} après tests de compatibilité.", evidence=[evidence]))

        if http_observation.observed:
            required_absent = any(name in REQUIRED_HEADERS for name in http_observation.absent_headers)
            execution_registry.record(
                security_headers_declaration,
                CHECK_STATE_SUCCESS_WITH_EVIDENCE if required_absent else CHECK_STATE_SUCCESS_NO_FINDING,
            )
        else:
            execution_registry.record(
                security_headers_declaration,
                CHECK_STATE_FAILED_OBSERVATION,
                reason=REASON_ROOT_UNAVAILABLE,
            )

        required_terminal_failure = False
        existing_not_tested = {
            (issue.check_id, issue.url)
            for issue in scan_issues
            if issue.kind == "CHECK_NOT_TESTED"
        }
        for declaration, terminal in execution_registry.finalize():
            if terminal.state not in COVERAGE_FAILURE_STATES:
                continue
            if terminal.reason == REASON_ROOT_UNAVAILABLE:
                if declaration.required:
                    required_terminal_failure = True
                continue
            if declaration.required:
                required_terminal_failure = True
                key = (declaration.check_id, redact_url(declaration.target))
                if key not in existing_not_tested:
                    scan_issues.append(
                        ScanIssue(
                            kind="CHECK_NOT_TESTED",
                            url=redact_url(declaration.target),
                            required=True,
                            check_id=declaration.check_id,
                        )
                    )
                    existing_not_tested.add(key)

        scan_completeness = (
            "INCOMPLETE"
            if required_terminal_failure or any(issue.required for issue in scan_issues)
            else "COMPLETED"
        )
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
            scan_completeness=scan_completeness,
            scan_issues=scan_issues,
            advisory_snapshot_sha256=snapshot.snapshot_sha256,
            advisory_snapshot_date=snapshot.snapshot_date,
            http_observation=http_observation,
            score=score,
        )
