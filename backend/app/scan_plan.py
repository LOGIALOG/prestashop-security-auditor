from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .models import AuditRequest
from .scanner import assert_allowed, normalized_origin


class ScanPlan(BaseModel):
    format: Literal["logialog-scan-plan"] = "logialog-scan-plan"
    format_version: Literal["1.0"] = "1.0"
    target_origin: str
    fixed_requests: list[str]
    required_requests: list[str]
    optional_requests: list[str]
    methods: list[Literal["GET"]] = Field(default_factory=lambda: ["GET"])
    dynamic_same_origin_assets: bool = True
    redirects_same_origin_only: bool = True
    cross_origin_requests: bool = False
    network_access: Literal[False] = False
    delay_seconds: float
    maximum_requests: int
    minimum_requests: int


def build_scan_plan(request: AuditRequest) -> ScanPlan:
    root = str(request.target).rstrip("/") + "/"
    origin = normalized_origin(root)
    scheme, host, port = origin
    default_port = 443 if scheme == "https" else 80
    authority = host if port == default_port else f"{host}:{port}"
    target_origin = f"{scheme}://{authority}"
    required_requests = [root, *[str(page) for page in request.public_pages]]
    optional_requests = [root.rstrip("/") + "/robots.txt"]
    candidates = [*required_requests, *optional_requests]
    fixed_requests: list[str] = []
    for url in candidates:
        assert_allowed(url, origin)
        if url not in fixed_requests:
            fixed_requests.append(url)
    return ScanPlan(
        target_origin=target_origin,
        fixed_requests=fixed_requests,
        required_requests=list(dict.fromkeys(required_requests)),
        optional_requests=[url for url in dict.fromkeys(optional_requests) if url not in required_requests],
        delay_seconds=request.delay_seconds,
        maximum_requests=request.max_requests,
        minimum_requests=min(len(fixed_requests), request.max_requests),
    )
