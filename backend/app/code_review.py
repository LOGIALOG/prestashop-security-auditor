from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field

MAX_FILES = 20_000
MAX_FILE_BYTES = 5_000_000
IGNORED_PARTS = {".git", "cache", "logs", "node_modules", "reports", "vendor"}


class CodeReviewSignal(BaseModel):
    rule_id: str
    relative_path: str
    line: int
    confidence: Literal["high", "medium", "low"]
    interpretation: str
    remediation: str
    file_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class LocalCodeReview(BaseModel):
    format: Literal["logialog-local-code-review"] = "logialog-local-code-review"
    format_version: Literal["1.0"] = "1.0"
    scanned_files: int
    signals: list[CodeReviewSignal] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    source_content_exported: Literal[False] = False
    source_code_executed: Literal[False] = False
    network_access: Literal[False] = False


RULES = (
    ("PHP-EVAL", re.compile(r"\beval\s*\(", re.I), "high", "Dynamic PHP evaluation requires manual security review.", "Remove dynamic evaluation or constrain the input and design."),
    ("PHP-PROCESS", re.compile(r"\b(?:shell_exec|passthru|proc_open|popen)\s*\(", re.I), "medium", "Operating-system process execution is present; reachability and input flow are unknown.", "Avoid process execution or use a strict allowlist and escaped arguments."),
    ("PHP-UNSERIALIZE-INPUT", re.compile(r"\bunserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|Tools::getValue)", re.I), "high", "Unserialization appears to consume request-controlled input.", "Use JSON with schema validation instead of deserializing request input."),
    ("PHP-BASE64-DECODE", re.compile(r"\bbase64_decode\s*\(", re.I), "low", "Base64 decoding is present; this is not a vulnerability by itself.", "Review provenance and downstream use, especially with dynamic execution."),
)


def review_local_php(source: Path) -> LocalCodeReview:
    root = source.resolve()
    if not root.is_dir():
        raise ValueError(f"Répertoire source introuvable: {root}")
    signals: list[CodeReviewSignal] = []
    warnings: list[str] = []
    scanned = 0
    for path in sorted(root.rglob("*.php")):
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if path.is_symlink() or any(part.casefold() in IGNORED_PARTS for part in PurePosixPath(relative).parts) or not path.is_file():
            continue
        scanned += 1
        if scanned > MAX_FILES:
            raise ValueError("Checkout refusé: trop de fichiers PHP")
        if path.stat().st_size > MAX_FILE_BYTES:
            warnings.append(f"Fichier ignoré car trop volumineux: {relative}")
            continue
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            warnings.append(f"Fichier ignoré car trop volumineux: {relative}")
            continue
        file_sha256 = hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), 1):
            for rule_id, pattern, confidence, interpretation, remediation in RULES:
                if pattern.search(line):
                    signals.append(CodeReviewSignal(rule_id=rule_id, relative_path=relative, line=line_number, confidence=confidence, interpretation=interpretation, remediation=remediation, file_sha256=file_sha256))
    return LocalCodeReview(scanned_files=scanned, signals=signals, warnings=warnings)
