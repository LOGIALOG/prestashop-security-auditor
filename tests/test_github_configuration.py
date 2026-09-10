import re
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_github_yaml_files_are_valid():
    paths = sorted((ROOT / ".github").rglob("*.yml"))

    assert paths
    for path in paths:
        assert yaml.safe_load(path.read_text(encoding="utf-8")) is not None, path


def test_ci_keeps_local_container_smoke_and_private_security_routing():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    issue_config = yaml.safe_load((ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8"))
    container_steps = workflow["jobs"]["containers"]["steps"]

    assert any(step.get("run") == "docker compose config --quiet" for step in container_steps)
    assert any("127.0.0.1:8000/api/health" in step.get("run", "") for step in container_steps)
    assert any("127.0.0.1:8010" in step.get("run", "") for step in container_steps)
    assert issue_config["blank_issues_enabled"] is False
    assert issue_config["contact_links"][0]["url"].endswith("/security/advisories/new")


def test_all_github_actions_are_pinned_to_immutable_commits():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    action_references = [
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "uses" in step
    ]

    assert action_references
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference) for reference in action_references)
