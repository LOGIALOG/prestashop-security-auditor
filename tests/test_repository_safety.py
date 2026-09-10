import subprocess
from pathlib import Path

import pytest

from backend.app.repository_safety import validate_repository_safety


def initialize_repository(root):
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    (root / ".gitignore").write_text(".env\nreports/*.html\nreports/*.sqlite3\nreports/*.json\nreports/*.sarif\nreports/*.zip\nreview-queue/*.json\nkeys/private/\n", encoding="utf-8")


def test_repository_safety_accepts_reserved_fixture_domains(tmp_path):
    initialize_repository(tmp_path)
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "safe.html").write_text("https://shop.test/ https://demo.local/ https://security.friendsofpresta.org/advisory", encoding="utf-8")

    checked = validate_repository_safety(tmp_path)

    assert checked == ["tests/fixtures/safe.html"]


def test_repository_safety_rejects_real_fixture_domain(tmp_path):
    initialize_repository(tmp_path)
    fixtures = tmp_path / "backend" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "unsafe.json").write_text('{"url":"https://client-shop.com/"}', encoding="utf-8")

    with pytest.raises(ValueError, match="Domaine réel interdit"):
        validate_repository_safety(tmp_path)


def test_container_builds_do_not_depend_on_ignored_reports_and_expose_frontend():
    root = Path(__file__).parents[1]
    backend_dockerfile = (root / "backend" / "Dockerfile").read_text(encoding="utf-8")
    frontend_dockerfile = (root / "frontend" / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY reports" not in backend_dockerfile
    assert "mkdir -p /app/reports" in backend_dockerfile
    assert "COPY package.json package-lock.json" in frontend_dockerfile
    assert "RUN npm ci" in frontend_dockerfile
    assert '"--host","0.0.0.0"' in frontend_dockerfile


def test_repository_safety_requires_generated_artifact_ignores(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Règles .gitignore manquantes"):
        validate_repository_safety(tmp_path)
