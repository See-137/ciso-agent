"""Review H1: the hook's runtime cannot be steered by anything the user or the agent
controls (an ancestor `.venv`, `VIRTUAL_ENV`, uv index variables, a planted `.pth`).

Two layers: the uv argv in `hooks/hooks.json` (`--isolated` plus every package source on
the command line, which beats the environment), and `scripts/runtime_guard.py`, which
refuses an interpreter that is not uv's own environment before the bundle is imported.
The uv runs are offline from the uv cache, except the index tests, which point the
pinned index at a closed local port and only read which address uv tried.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
from tests.plugin.conftest import (
    PLUGIN_ROOT,
    UV,
    base_env,
    declared_uv_args,
    run_hook,
    tool_event,
)

pytestmark = pytest.mark.adversarial

PYPI = "https://pypi.org/simple"
PINNED = "http://127.0.0.1:8/simple"
PLANTED = "http://127.0.0.1:9/simple"
PROBE = "import os, sys; any(str(a).endswith('ciso_hook.py') for a in sys.argv) and os._exit(0)\n"


@pytest.fixture(scope="module")
def guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_guard_under_test", PLUGIN_ROOT / "scripts" / "runtime_guard.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- the guard on fabricated layouts ---------------------------------------------------


def _layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    """(base interpreter, uv cache env, its site-packages)."""
    base = tmp_path / "base"
    (base / "Lib").mkdir(parents=True)
    (base / "Lib" / "site-packages").mkdir()
    cache = tmp_path / "uvcache"
    cache.mkdir()
    (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n")
    env = cache / "builds-v0" / ".tmpA"
    site = env / "Lib" / "site-packages"
    site.mkdir(parents=True)
    (site / "_virtualenv.pth").write_text("import _virtualenv")
    return base, env, site


def _problem(guard: ModuleType, prefix: Path, base: Path, entries: list[str], **kw: object) -> str:
    return guard.runtime_problem(
        str(prefix),
        str(base),
        entries,
        kw.get("modules", set()),
        kw.get("isolated", True),
        kw.get("version", (3, 13, 0)),
    )


def test_guard_accepts_uv_environment(guard: ModuleType, tmp_path: Path) -> None:
    base, env, site = _layout(tmp_path)
    archive = tmp_path / "uvcache" / "archive-v0" / "x" / "Lib" / "site-packages"
    archive.mkdir(parents=True)
    escaped = str(archive).replace("\\", "\\\\")
    (site / "_uv_ephemeral_overlay.pth").write_text(f'import site; site.addsitedir("{escaped}")')
    entries = [str(base / "Lib"), str(base), str(env), str(site), str(archive)]
    assert _problem(guard, env, base, entries) is None


@pytest.mark.parametrize(
    "change",
    [
        "planted_pth",
        "overlay_outside",
        "not_uv_prefix",
        "extra_entry",
        "base_site_packages",
        "cwd_entry",
        "sitecustomize",
        "not_isolated",
        "old_python",
    ],
)
def test_guard_refuses(guard: ModuleType, tmp_path: Path, change: str) -> None:
    base, env, site = _layout(tmp_path)
    entries = [str(base / "Lib"), str(env), str(site)]
    prefix = env
    kw: dict[str, object] = {}
    if change == "planted_pth":
        (site / "zz_probe.pth").write_text(PROBE)
    elif change == "overlay_outside":
        other = str(tmp_path / "elsewhere").replace("\\", "\\\\")
        (site / "_uv_ephemeral_overlay.pth").write_text(f'import site; site.addsitedir("{other}")')
    elif change == "not_uv_prefix":
        prefix = tmp_path / "project" / ".venv"
        prefix.mkdir(parents=True)
    elif change == "extra_entry":
        entries.append(str(tmp_path / "project" / "src"))
    elif change == "base_site_packages":
        entries.append(str(base / "Lib" / "site-packages"))
    elif change == "cwd_entry":
        entries.append("")
    elif change == "sitecustomize":
        kw["modules"] = {"sitecustomize"}
    elif change == "not_isolated":
        kw["isolated"] = False
    else:
        kw["version"] = (3, 12, 9)
    assert _problem(guard, prefix, base, entries, **kw) is not None


def test_hook_refuses_a_project_venv_interpreter(data: Path) -> None:
    """The project's own virtual environment (not uv's) is refused before any import."""
    done = subprocess.run(  # noqa: S603 - fixed argv, this interpreter
        [sys.executable, "-I", "-B", str(PLUGIN_ROOT / "scripts" / "ciso_hook.py")],
        input=json.dumps(tool_event("Read", {"file_path": "x"}, str(data))).encode(),
        capture_output=True,
        env=base_env(data),
        timeout=120,
        check=False,
    )
    assert done.returncode == 2
    assert b"not running in an environment uv created" in done.stderr


def test_hook_in_the_uv_runtime_is_accepted(data: Path) -> None:
    run = run_hook(tool_event("Read", {"file_path": "README.md"}, str(data)), data)
    assert (run.code, run.decision) == (0, "allow"), run.stderr


# --- the declared uv command, end to end ------------------------------------------------


def _plugin_copy(target: Path) -> Path:
    shutil.copytree(PLUGIN_ROOT, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return target


def _venv_with_probe(folder: Path) -> Path:
    assert UV is not None
    done = subprocess.run(  # noqa: S603 - fixed argv
        [UV, "venv", "--offline", "--no-config", "--python", "3.13", "--quiet", str(folder)],
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    sites = list(folder.glob("Lib/site-packages")) + list(folder.glob("lib/python3*/site-packages"))
    (sites[0] / "zz_probe.pth").write_text(PROBE, encoding="utf-8")
    return folder


def _declared(
    args: list[str], data: Path, cwd: Path, extra: dict[str, str]
) -> subprocess.CompletedProcess[bytes]:
    assert UV is not None
    env = base_env(data, {"UV_OFFLINE": "1", **extra})
    env.pop("VIRTUAL_ENV", None) if "VIRTUAL_ENV" not in extra else None
    payload = tool_event("Write", {"file_path": str(cwd / ".mcp.json"), "content": "{}"}, str(cwd))
    return subprocess.run(  # noqa: S603 - argv from the plugin's own hooks.json
        [UV, *args],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=env,
        cwd=str(cwd),
        timeout=300,
        check=False,
    )


def _verdict(done: subprocess.CompletedProcess[bytes]) -> str:
    if done.returncode != 0:
        return "error"
    if not done.stdout.strip():
        return "allow"
    return str(json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"])


needs_uv = pytest.mark.skipif(UV is None, reason="uv is not installed")


@needs_uv
def test_a_venv_above_the_plugin_folder_is_not_used(data: Path, tmp_path: Path) -> None:
    """Review H1 step 2: `~/.venv` above `~/.claude/plugins/cache/...`."""
    _venv_with_probe(tmp_path / ".venv")
    plugin = _plugin_copy(tmp_path / "a" / "b" / "plugin")
    args = declared_uv_args(root=plugin)
    assert _verdict(_declared(args, data, plugin, {})) == "deny"
    control = [a for a in args if a != "--isolated"]
    assert _verdict(_declared(control, data, plugin, {})) == "allow"  # the vector is real


@needs_uv
def test_virtual_env_variable_is_not_used(data: Path, tmp_path: Path) -> None:
    """Review H1 step 3: an activated project venv holding a `.pth`."""
    venv = _venv_with_probe(tmp_path / "project" / ".venv")
    plugin = _plugin_copy(tmp_path / "plugin")
    args = declared_uv_args(root=plugin)
    extra = {"VIRTUAL_ENV": str(venv)}
    assert _verdict(_declared(args, data, tmp_path, extra)) == "deny"
    control = [a for a in args if a != "--isolated"] + []
    control.insert(control.index("--"), "--active")
    assert _verdict(_declared(control, data, tmp_path, extra)) == "allow"


def _pinned_to_closed_port(args: list[str]) -> list[str]:
    return [PINNED if a == PYPI else a for a in args]


@needs_uv
@pytest.mark.parametrize(
    "variable",
    ["UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX", "UV_EXTRA_INDEX_URL", "UV_FIND_LINKS"],
)
def test_index_variables_do_not_choose_the_package_source(
    data: Path, tmp_path: Path, variable: str
) -> None:
    """Review H1 step 4. The index in the argv is replaced by a closed local port (:8) and
    the variable names another closed port (:9): uv must only ever try :8."""
    args = _pinned_to_closed_port(declared_uv_args())
    extra = {variable: PLANTED, "UV_NO_CACHE": "1", "UV_HTTP_RETRIES": "0", "UV_OFFLINE": ""}
    env_extra = {k: v for k, v in extra.items() if v}
    done = _declared_no_offline(args, data, tmp_path, env_extra)
    text = done.stderr.decode("utf-8", "replace")
    assert done.returncode != 0
    assert "127.0.0.1:8" in text
    assert "127.0.0.1:9" not in text


@needs_uv
def test_index_variable_would_steer_uv_without_the_pinned_flags(data: Path, tmp_path: Path) -> None:
    """Control for the test above: drop `--index` and UV_INDEX is used."""
    args = _pinned_to_closed_port(declared_uv_args())
    at = args.index("--index")
    control = args[:at] + args[at + 2 :]
    extra = {"UV_INDEX": PLANTED, "UV_NO_CACHE": "1", "UV_HTTP_RETRIES": "0"}
    done = _declared_no_offline(control, data, tmp_path, extra)
    assert "127.0.0.1:9" in done.stderr.decode("utf-8", "replace")


def _declared_no_offline(
    args: list[str], data: Path, cwd: Path, extra: dict[str, str]
) -> subprocess.CompletedProcess[bytes]:
    assert UV is not None
    env = {k: v for k, v in base_env(data, extra).items() if k != "UV_OFFLINE"}
    payload = tool_event("Read", {"file_path": "x"}, str(cwd))
    return subprocess.run(  # noqa: S603 - argv from the plugin's own hooks.json
        [UV, *args],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=env,
        cwd=str(cwd),
        timeout=300,
        check=False,
    )


def test_runtime_requirements_pin_every_package_with_hashes() -> None:
    text = (PLUGIN_ROOT / "scripts" / "runtime-requirements.txt").read_text(encoding="utf-8")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    pins = [ln.rstrip(" \\") for ln in lines if not ln.startswith("--hash")]
    assert pins == [
        "annotated-types==0.8.0",
        "pydantic==2.14.0",
        "pydantic-core==2.50.0",
        "typing-extensions==4.16.0",
        "typing-inspection==0.4.5",
    ]
    hashes = [ln for ln in lines if ln.startswith("--hash=sha256:")]
    assert len(hashes) == 4 + 16
    assert os.path.isdir(PLUGIN_ROOT / "scripts" / "no-local-packages")
