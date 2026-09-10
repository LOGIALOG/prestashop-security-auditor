from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SAFE_FIXTURE_HOSTS = {"demo.local", "localhost", "127.0.0.1"}
SAFE_PROVENANCE_HOSTS = {"security.friendsofpresta.org", "build.prestashop-project.org"}
REQUIRED_IGNORE_RULES = {".env", "reports/*.html", "reports/*.sqlite3", "reports/*.json", "reports/*.sarif", "reports/*.zip", "review-queue/*.json", "keys/private/"}
FIXTURE_DIRECTORIES = ("backend/fixtures", "tests/fixtures")


def _is_reserved_fixture_host(host: str) -> bool:
    lowered = host.casefold().rstrip(".")
    return lowered in SAFE_FIXTURE_HOSTS or lowered.endswith((".test", ".example", ".invalid", ".localhost"))


def _tracked_generated_artifacts(root: Path) -> list[str]:
    process = subprocess.run(
        ["git", "ls-files", "--", "reports", ".env"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise ValueError("Impossible de vérifier l'index Git")
    return [line for line in process.stdout.splitlines() if line]


def validate_repository_safety(root: Path) -> list[str]:
    repository = root.resolve()
    gitignore = repository / ".gitignore"
    if not gitignore.is_file():
        raise ValueError(".gitignore absent")
    ignore_rules = {line.strip() for line in gitignore.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")}
    missing = sorted(REQUIRED_IGNORE_RULES - ignore_rules)
    if missing:
        raise ValueError(f"Règles .gitignore manquantes: {', '.join(missing)}")

    tracked = _tracked_generated_artifacts(repository)
    if tracked:
        raise ValueError(f"Artifacts locaux suivis par Git: {', '.join(tracked)}")

    checked: list[str] = []
    for relative_directory in FIXTURE_DIRECTORIES:
        directory = repository / relative_directory
        if not directory.exists():
            continue
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            text = path.read_text(encoding="utf-8", errors="replace")
            for raw_url in URL_PATTERN.findall(text):
                host = urlsplit(raw_url.rstrip(".,);]")).hostname or ""
                if host and not _is_reserved_fixture_host(host) and host.casefold() not in SAFE_PROVENANCE_HOSTS:
                    raise ValueError(f"Domaine réel interdit dans fixture {path.relative_to(repository)}: {host}")
            checked.append(path.relative_to(repository).as_posix())
    return checked
