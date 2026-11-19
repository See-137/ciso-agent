"""Queue Q7: the deployment ruleset is a reproducible derivation of the default.

`config/governance-ruleset.provisional.json` must be exactly what
`config/derive_governance_ruleset.py` writes from the packaged default plus the
deployment additions; a hand edit or a stale copy fails here.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from ciso.governance import DEFAULT_RULESET_PATH, load_ruleset

pytestmark = pytest.mark.policy

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "config" / "derive_governance_ruleset.py"
COMMITTED = ROOT / "config" / "governance-ruleset.provisional.json"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("derive_governance_ruleset", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_file_is_exactly_the_derivation() -> None:
    script = _script()
    assert script.DEFAULT_PATH == DEFAULT_RULESET_PATH
    assert COMMITTED.read_text(encoding="utf-8") == script.render()
    assert script.main(["derive", "--check"]) == 0


def test_the_derivation_is_the_default_plus_the_additions() -> None:
    default = json.loads(DEFAULT_RULESET_PATH.read_text(encoding="utf-8"))
    derived = json.loads(COMMITTED.read_text(encoding="utf-8"))
    assert derived["rules"] == default["rules"]
    assert derived["read_only_kinds"] == default["read_only_kinds"]
    assert derived["version"] == "deployment." + default["version"]
    assert default["version"] in derived["description"]
    assert "GENERATED" in derived["description"]
    assert "tests/governance/test_deployment_ruleset.py" in derived["description"]
    extra = set(derived["agent_config_paths"]) - set(default["agent_config_paths"])
    assert extra == {"**/CLAUDE.md", "**/.claude/**", "**/.mcp.json", "**/.claude.json"}
    untouched = set(default) - {"version", "description", "agent_config_paths"}
    assert all(derived[key] == default[key] for key in untouched)


def test_a_stale_file_is_detected(tmp_path: Path) -> None:
    script = _script()
    default = json.loads(DEFAULT_RULESET_PATH.read_text(encoding="utf-8"))
    default["rules"] = default["rules"][:-1]
    changed = tmp_path / "default.json"
    changed.write_text(json.dumps(default), encoding="utf-8")
    assert script.render(changed) != COMMITTED.read_text(encoding="utf-8")


def test_the_deployment_ruleset_loads() -> None:
    loaded = load_ruleset(COMMITTED)
    assert not loaded.deny_all, loaded.deny_reason
    assert loaded.document is not None
    assert "**/.claude/**" in loaded.document.agent_config_paths
