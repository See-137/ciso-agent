"""The bundled engine is a copy of the source, never a fork; the build check catches drift."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
from tests.plugin.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

BUILD = REPO_ROOT / "tools" / "build_ciso_plugin.py"


@pytest.fixture(scope="module")
def build() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_ciso_build", BUILD)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_bundle_is_current_and_imports_in_isolation() -> None:
    done = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(BUILD), "--check"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "bundle current" in done.stdout


def test_closure_needs_only_pydantic_and_has_the_entry_modules(build: ModuleType) -> None:
    modules = build.closure()
    for name in build.ENTRY_MODULES:
        assert name in modules
    assert not any(
        m.startswith(("ciso.app.container", "ciso.common.db", "ciso.api")) for m in modules
    )


def test_a_changed_copy_is_reported(build: ModuleType, tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    shutil.copytree(build.PLUGIN / "lib", plugin / "lib")
    shutil.copytree(build.PLUGIN / "rules", plugin / "rules")
    engine = plugin / "lib" / "ciso" / "governance" / "engine.py"
    engine.write_bytes(engine.read_bytes() + b"\n# drift\n")
    (plugin / "rules" / "extra.json").write_text("{}", encoding="utf-8")
    problems = build.differences(plugin, build.MANAGED)
    assert "differs from source: lib/ciso/governance/engine.py" in problems
    assert any(p.startswith("not part of the bundle") and "extra.json" in p for p in problems)


def test_a_missing_module_fails_the_isolated_import(build: ModuleType, tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    shutil.copytree(build.PLUGIN / "lib", plugin / "lib")
    (plugin / "lib" / "ciso" / "inspection" / "secret_scan.py").unlink()
    assert build.isolated_import_problem(plugin) is not None


def test_the_ruleset_is_the_deployment_ruleset_plus_the_plugin_additions(
    build: ModuleType,
) -> None:
    import json

    bundled = json.loads((build.PLUGIN / "rules" / "governance-ruleset.json").read_bytes())
    source = json.loads((REPO_ROOT / "config" / "governance-ruleset.provisional.json").read_bytes())
    for key, value in source.items():
        if key in build.PLUGIN_ADDITIONS:
            assert bundled[key][: len(value)] == value  # only added to
            assert set(build.PLUGIN_ADDITIONS[key]) <= set(bundled[key])
        elif key not in ("version", "description"):
            assert bundled[key] == value, key
    assert bundled["version"] == source["version"] + ".plugin"
    assert "**/.claude/.credentials.json" in bundled["credential_paths"]


def test_apps_zip_holds_the_skill_folder_without_scripts(build: ModuleType, tmp_path: Path) -> None:
    target = tmp_path / "ciso-skill.zip"
    build.write_zip(target)
    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        skill = archive.read("ciso/SKILL.md").decode("utf-8")
    assert "ciso/SKILL.md" in names
    assert any(n.startswith("ciso/references/") for n in names)
    assert not any("scripts" in n for n in names)
    assert skill.startswith("---\nname: ciso\n")
    assert "${" not in skill
    first = target.read_bytes()
    build.write_zip(target)
    assert target.read_bytes() == first  # reproducible
