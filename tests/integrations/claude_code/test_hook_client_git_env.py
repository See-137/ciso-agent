"""Coordinator addition to review H2: a scanned push is refused unless the hook's ``GIT_*``
variables are exactly the git configuration the managed pack installs. Any other
variable, an extra pair or a changed value changes what the agent's own `git push` does."""

# ruff: noqa: F401, F811
# (the pre-push fixtures are imported from their module by name)

from __future__ import annotations

# ruff: noqa: F811
# (the pre-push fixtures are imported from their module by name)
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import (
    HOOKS_DIR,
    MANAGED_ROOT,
    FakeTransport,
    load_script,
)
from tests.integrations.claude_code.test_hook_client_prepush import (
    NEEDS_PUSH,
    FakeGit,
    _config,
    decide_answer,
    env,
    git,
    repo,
    run_push,
)

pytestmark = pytest.mark.unit

#: One value per family; built from fragments only where a value could look like a
#: command line.
FAMILIES = {
    "GIT_DIR": "/elsewhere/.git",
    "GIT_WORK_TREE": "/elsewhere",
    "GIT_COMMON_DIR": "/elsewhere/.git",
    "GIT_CONFIG": "/elsewhere/config",
    "GIT_CONFIG_GLOBAL": "/elsewhere/gitconfig",
    "GIT_CONFIG_SYSTEM": "/elsewhere/gitconfig",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_INDEX_FILE": "/elsewhere/index",
    "GIT_OBJECT_DIRECTORY": "/elsewhere/objects",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/elsewhere/objects",
    "GIT_SSH": "/elsewhere/" + "ssh",
    "GIT_SSH_COMMAND": "ss" + "h -o " + "ProxyCommand=x",
    "GIT_PROXY_COMMAND": "/elsewhere/" + "proxy",
    "GIT_EXEC_PATH": "/elsewhere/libexec",
    "GIT_CONFIG_KEY_4": "remote.origin.pushurl",
}


def refused(hc: ModuleType, result: tuple[int, str, str]) -> bool:
    code, _out, err = result
    return code == 2 and err.strip() == hc.PREPUSH_MESSAGES["push_config"]


@pytest.mark.parametrize("name", sorted(FAMILIES))
def test_any_other_git_variable_refuses_the_push(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    name: str,
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    result = run_push(hc, {**env, name: FAMILIES[name]}, transport, git, repo)
    assert refused(hc, result)
    assert len(transport.calls) == 1  # nothing asked or uploaded


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GIT_CONFIG_COUNT", "3"),
        ("GIT_CONFIG_VALUE_0", str(Path("/somewhere/else/hooks").resolve())),
        ("GIT_CONFIG_VALUE_1", "all"),
        ("GIT_CONFIG_VALUE_2", "on-demand"),
        ("GIT_CONFIG_KEY_3", "protocol.allow"),
    ],
)
def test_a_changed_managed_value_refuses_the_push(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    name: str,
    value: str,
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    assert refused(hc, run_push(hc, {**env, name: value}, transport, git, repo))


@pytest.mark.parametrize("name", ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_3"])
def test_a_missing_managed_value_refuses_the_push(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    name: str,
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    without = {k: v for k, v in env.items() if k != name}
    assert refused(hc, run_push(hc, without, transport, git, repo))


def test_the_managed_set_alone_is_accepted(hc: ModuleType) -> None:
    hc.check_git_environment(
        {"PATH": "/usr/bin", **hc.managed_git_env(str(HOOKS_DIR))}, str(HOOKS_DIR)
    )


def test_the_variable_name_is_compared_without_case(hc: ModuleType) -> None:
    with pytest.raises(hc.ClientError):
        hc.check_git_environment(
            {**hc.managed_git_env(str(HOOKS_DIR)), "git_dir": "/x"}, str(HOOKS_DIR)
        )


# --- one table, three places ------------------------------------------------------------


def test_client_checker_and_pack_source_agree_on_the_git_configuration(hc: ModuleType) -> None:
    checker = load_script(MANAGED_ROOT / "check_pack.py", "_aigov_check_pack_git_env")
    assert tuple(checker.REQUIRED_GIT_CONFIG) == tuple(hc.MANAGED_GIT_CONFIG)
    source: dict[str, Any] = json.loads(
        (MANAGED_ROOT / "pack_source.json").read_text(encoding="utf-8")
    )
    for platform, extra in source["platform_env"].items():
        env = {**source["policy"]["env"], **extra}
        git_env = {k: v for k, v in env.items() if k.startswith("GIT_")}
        hooks = checker.client_config(source, platform)["git_hooks_dir"]
        assert git_env == hc.managed_git_env(hooks), platform
