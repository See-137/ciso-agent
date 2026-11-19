"""Sensitive target paths for writes and edits, with Windows and POSIX forms."""

from __future__ import annotations

import pytest
from tests.inspection.samples import ids, write

from ciso.common.activity import ActionKind, InspectionInput, Severity
from ciso.common.paths import normalise_path
from ciso.inspection import Inspector, sensitive_path_rules

pytestmark = pytest.mark.unit

INSPECTOR = Inspector()


@pytest.mark.parametrize(
    ("path", "rule_id"),
    [
        (".env", "path.env_file"),
        ("config/.env.local", "path.env_file"),
        ("deploy/prod.env", "path.env_file"),
        (r"C:\repo\.ENV", "path.env_file"),
        ("src/../.env", "path.env_file"),
        ("/home/dev/.ssh/id_rsa", "path.private_key_file"),
        ("~/.ssh/id_ed25519", "path.private_key_file"),
        ("certs/server.pem", "path.private_key_file"),
        ("signing/release.P12", "path.private_key_file"),
        ("tls/site.key", "path.private_key_file"),
        ("~/.aws/credentials", "path.cloud_credentials"),
        (r"C:\Users\dev\.kube\config", "path.cloud_credentials"),
        (".docker/config.json", "path.cloud_credentials"),
        (".git-credentials", "path.cloud_credentials"),
        (".npmrc", "path.package_registry_config"),
        ("~/.pypirc", "path.package_registry_config"),
        (".github/workflows/ci.yml", "path.ci_pipeline"),
        (r".GitHub\Workflows\deploy.yml", "path.ci_pipeline"),
        (".github/actions/setup/action.yml", "path.ci_pipeline"),
        (".gitlab-ci.yml", "path.ci_pipeline"),
        ("azure-pipelines.yml", "path.ci_pipeline"),
        ("Jenkinsfile", "path.ci_pipeline"),
        (".circleci/config.yml", "path.ci_pipeline"),
        (".git/hooks/pre-commit", "path.git_hook"),
        (r"repo\.git\hooks\post-checkout", "path.git_hook"),
        (".git/config", "path.git_hook"),
        (".husky/pre-push", "path.git_hook"),
        (".pre-commit-config.yaml", "path.git_hook"),
        (".claude/settings.json", "path.assistant_config"),
        (".claude/settings.local.json", "path.assistant_config"),
        (".claude/hooks/check.sh", "path.assistant_config"),
        (".claude/plugins/x/plugin.json", "path.assistant_config"),
        (".claude-plugin/plugin.json", "path.assistant_config"),
        (".mcp.json", "path.assistant_config"),
        ("CLAUDE.md", "path.assistant_config"),
        ("docs/claude.md", "path.assistant_config"),
        ("CLAUDE.local.md", "path.assistant_config"),
        (r"src\..\.claude\settings.json", "path.assistant_config"),
        ("CLAUDE.md.", "path.assistant_config"),
        ("CLAUDE.md::$DATA", "path.assistant_config"),
        (r"\\?\C:\repo\.mcp.json", "path.assistant_config"),
        ("a/b/../../.claude/settings.json", "path.assistant_config"),
    ],
)
def test_sensitive_paths_are_reported(path: str, rule_id: str) -> None:
    assert rule_id in [rule.rule_id for rule in sensitive_path_rules(path)]
    result = INSPECTOR.inspect(write("hello", path=path))
    assert rule_id in ids(result)
    assert result.complete is True


@pytest.mark.parametrize(
    "path",
    [
        "src/app.py",
        ".env.example",
        "config/.env.sample",
        "~/.ssh/id_rsa.pub",
        "docs/claude.mdx",
        "README.md",
        "environment.py",
        ".github/CODEOWNERS",
        "src/claude/notes.md",
        "workflows/ci.yml",
        "hooks/pre-commit",
        "",
        ".",
    ],
)
def test_ordinary_paths_are_not_reported(path: str) -> None:
    assert sensitive_path_rules(path) == ()


def test_assistant_config_is_critical_and_located_at_the_path() -> None:
    result = INSPECTOR.inspect(write("{}", path=".claude/settings.json"))
    (finding,) = result.findings
    assert finding.severity is Severity.CRITICAL
    assert finding.location == ".claude/settings.json"
    assert finding.category == "sensitive_path"
    assert "Remediation:" in finding.detail


def test_edit_is_checked_like_a_write() -> None:
    item = InspectionInput(
        action_id="a", kind=ActionKind.FILE_EDIT, path=".git/hooks/pre-push", content="x"
    )
    assert ids(INSPECTOR.inspect(item)) == ["path.git_hook"]


def test_a_write_without_a_path_is_incomplete() -> None:
    result = INSPECTOR.inspect(write("hello", path=""))
    assert result.complete is False
    assert ids(result) == ["inspection.path_missing"]
    assert "inspection.paths" in result.checks_run


def test_paths_are_not_checked_for_reads() -> None:
    item = InspectionInput(action_id="a", kind=ActionKind.FILE_READ, path=".env")
    result = INSPECTOR.inspect(item)
    assert ids(result) == []
    assert "inspection.paths" not in result.checks_run


def test_normalisation() -> None:
    """Inspection uses the shared normaliser (queue Q13); the same cases still hold."""
    assert normalise_path(r"C:\Repo\Sub\..\.ENV. ", windows=True).text == "c:/repo/.env"
    env = ["path.env_file"]
    assert [r.rule_id for r in sensitive_path_rules(r"C:\Repo\Sub\..\.ENV. ")] == env
    assert [r.rule_id for r in sensitive_path_rules(".env ")] == env
    assert normalise_path("./a//b/./c", windows=True).text == "a/b/c"
    assert [r.rule_id for r in sensitive_path_rules("../../.env")] == env
    assert normalise_path(r"\\?\D:\x\y", windows=True).text == "d:/x/y"


def test_one_path_can_match_two_rules() -> None:
    rules = {r.rule_id for r in sensitive_path_rules(".claude/deploy.pem")}
    assert rules == {"path.assistant_config", "path.private_key_file"}
