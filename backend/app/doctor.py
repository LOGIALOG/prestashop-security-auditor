from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .advisories import validate_advisory_files, validate_advisory_manifest
from .manifest_signing import verify_manifest_signature
from .repository_safety import validate_repository_safety


class DoctorCheck(BaseModel):
    check_id: str
    status: Literal["PASS", "FAIL", "INFO"]
    required: bool
    detail: str


class DoctorReport(BaseModel):
    format: Literal["logialog-doctor"] = "logialog-doctor"
    format_version: Literal["1.0"] = "1.0"
    ready: bool
    network_access: Literal[False] = False
    checks: list[DoctorCheck] = Field(default_factory=list)


def _required(check_id: str, action, success: str) -> DoctorCheck:
    try:
        action()
    except (OSError, ValueError) as exc:
        return DoctorCheck(check_id=check_id, status="FAIL", required=True, detail=str(exc))
    return DoctorCheck(check_id=check_id, status="PASS", required=True, detail=success)


def run_doctor(root: Path) -> DoctorReport:
    repository = root.resolve()
    python_ready = sys.version_info >= (3, 13)
    checks = [
        DoctorCheck(
            check_id="python",
            status="PASS" if python_ready else "FAIL",
            required=True,
            detail=f"Python {platform.python_version()} ({platform.architecture()[0]})",
        ),
        _required(
            "advisory_snapshot",
            lambda: (validate_advisory_files(repository / "advisories"), validate_advisory_manifest(repository / "advisories")),
            "Bundled advisory records and SHA-256 manifest are valid.",
        ),
        _required(
            "advisory_signature",
            lambda: verify_manifest_signature(
                repository / "advisories" / "snapshot-manifest.json",
                repository / "advisories" / "snapshot-manifest.sig.json",
                repository / "keys" / "logialog-ed25519-public.pem",
            ),
            "Published advisory snapshot signature is valid.",
        ),
        _required(
            "repository_safety",
            lambda: validate_repository_safety(repository),
            "Repository fixtures and ignored local artifacts satisfy publication policy.",
        ),
    ]
    for executable in ("node", "npm", "php", "docker", "git"):
        path = shutil.which(executable)
        checks.append(
            DoctorCheck(
                check_id=executable,
                status="INFO",
                required=False,
                detail=f"Available at {path}" if path else "Not found; optional for this execution mode.",
            )
        )
    return DoctorReport(ready=all(check.status == "PASS" for check in checks if check.required), checks=checks)
