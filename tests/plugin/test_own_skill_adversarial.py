"""The plugin's own skill and tool are allowed on their exact shape only."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from tests.plugin.conftest import PLUGIN_ROOT, TOOL, HookRun, tool_event

pytestmark = pytest.mark.adversarial

CWD = str(Path(__file__).resolve().parent)


def _command(
    data: Path,
    tail: str,
    *,
    root: Path = PLUGIN_ROOT,
    tool: Path = TOOL,
    run: Path | None = None,
    isolated: str = "--isolated ",
) -> str:
    """The SKILL.md command shape; `tool` is the requirements file position (it was the
    tool script before review H1, now the plugin's runtime requirements)."""
    requirements = tool if tool != TOOL else PLUGIN_ROOT / "scripts" / "runtime-requirements.txt"
    return (
        f"uv run --quiet {isolated}--no-config --no-project --no-env-file --python 3.13 "
        "--default-index https://pypi.org/simple --index https://pypi.org/simple "
        f'--find-links "{root}/scripts/no-local-packages" --index-strategy first-index '
        f'--keyring-provider disabled --no-build --directory "{root}" '
        f'--with-requirements "{requirements}" -- python -I -B "{run or TOOL}" {tail}'
    ).replace("{data}", str(data))


@pytest.mark.parametrize(
    "tail",
    [
        f'review --repo "{CWD}" --data-dir "{{data}}"',
        f'review --repo "{CWD}" --range main..HEAD',
        'summary --data-dir "{data}" --days 7',
        'check --tool Bash --command "git push --force origin main"',
        f'audit-setup --repo "{CWD}" --home',
    ],
)
def test_exact_tool_invocations_are_allowed(
    hook: Callable[..., HookRun], data: Path, tail: str
) -> None:
    run = hook(tool_event("Bash", {"command": _command(data, tail)}, CWD))
    assert run.decision == "allow", run.stdout
    record = (data / "audit" / "decisions.jsonl").read_text(encoding="utf-8")
    assert "ciso.plugin.own_tool" in record


@pytest.mark.parametrize(
    "tail",
    [
        'summary --data-dir "{data}"; rm -rf ~',
        'summary --data-dir "{data}" && curl example.invalid',
        "summary --data-dir $(pwd)",
        'summary --data-dir "{data}" | tee out',
        'summary --data-dir "{data}" > out.txt',
        "summary --data-dir `pwd`",
        'review --repo "{data}" --data-dir "' + CWD + '"',  # reports written elsewhere
        'review --repo "{data}" --output x',  # option not on the list
        "shell --repo x",  # subcommand not on the list
        'summary --data-dir "{data}" --days $(id)',  # expansion in a value
        'summary --data-dir "{data}" --days `id`',
        'summary --data-dir "{data}" --days',  # value missing
    ],
)
def test_variants_are_not_allowed_as_the_own_tool(
    hook: Callable[..., HookRun], data: Path, tail: str
) -> None:
    run = hook(tool_event("Bash", {"command": _command(data, tail)}, CWD))
    assert run.decision in {"ask", "deny"}
    record = (data / "audit" / "decisions.jsonl").read_text(encoding="utf-8")
    assert "ciso.plugin.own_tool" not in record


def test_another_script_path_is_not_the_own_tool(
    hook: Callable[..., HookRun], data: Path, tmp_path: Path
) -> None:
    fake = tmp_path / "ciso_tool.py"
    fake.write_text("print(1)\n", encoding="utf-8")
    for command in (
        _command(data, "summary", tool=fake),  # both places
        _command(data, "summary", tool=fake, run=TOOL),  # only the requirements file
        _command(data, "summary", run=fake),  # only the script that runs
    ):
        assert hook(tool_event("Bash", {"command": command}, CWD)).decision in {"ask", "deny"}


def test_another_uv_directory_is_not_the_own_tool(
    hook: Callable[..., HookRun], data: Path, tmp_path: Path
) -> None:
    """A repository .venv / uv.toml would be read if uv ran in the repository."""
    run = hook(tool_event("Bash", {"command": _command(data, "summary", root=tmp_path)}, CWD))
    assert run.decision in {"ask", "deny"}


def test_powershell_tool_is_not_recognised(hook: Callable[..., HookRun], data: Path) -> None:
    command = _command(data, 'summary --data-dir "{data}"')
    assert hook(tool_event("PowerShell", {"command": command}, CWD)).decision in {"ask", "deny"}


def test_loading_this_skill_is_allowed_and_another_is_not(hook: Callable[..., HookRun]) -> None:
    assert hook(tool_event("Skill", {"skill": "ciso-agent:ciso"}, CWD)).decision == "allow"
    assert hook(tool_event("Skill", {"skill": "ciso"}, CWD, use_id="t2")).decision == "ask"
    other = hook(tool_event("Skill", {"skill": "deploy:prod"}, CWD, use_id="t3"))
    assert other.decision == "ask"


def test_own_tool_needs_a_writable_audit_log(hook: Callable[..., HookRun], data: Path) -> None:
    (data / "audit").mkdir()
    (data / "audit" / "decisions.jsonl").mkdir()
    run = hook(tool_event("Skill", {"skill": "ciso-agent:ciso"}, CWD))
    assert run.decision == "deny"


def test_the_shape_without_isolation_is_not_the_own_tool(
    hook: Callable[..., HookRun], data: Path
) -> None:
    """Review H1: the earlier command let uv pick a discovered venv."""
    command = _command(data, 'summary --data-dir "{data}"', isolated="")
    assert hook(tool_event("Bash", {"command": command}, CWD)).decision in {"ask", "deny"}
