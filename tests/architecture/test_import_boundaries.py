"""Trust boundaries are enforced here, not by convention.

Blueprint 9.5: the policy engine and execution broker are a separate trust boundary from
the LLM. Blueprint 8.4: no component reaches the network except through an approved path.
These tests read the source tree, so they hold even for code no other test exercises.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "ciso"

#: package -> packages it must never import (directly).
FORBIDDEN: dict[str, frozenset[str]] = {
    "ciso.common": frozenset(
        {
            "ciso.audit",
            "ciso.vault",
            "ciso.identity",
            "ciso.killswitch",
            "ciso.policy",
            "ciso.execution",
            "ciso.registry",
            "ciso.evidence",
            "ciso.connectors",
            "ciso.workflows",
            "ciso.discovery",
            "ciso.inference",
            "ciso.findings",
            "ciso.risk",
            "ciso.orchestrator",
            "ciso.api",
            "ciso.approvals",
            "ciso.write_adapters",
            "ciso.ai_registry",
            "ciso.memory",
            "ciso.observability",
            "ciso.reporting",
            "ciso.employee",
            "ciso.ops",
            "ciso.app",
        }
    ),
    "ciso.policy": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.approvals": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.execution": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.write_adapters": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.audit": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.killswitch": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.identity": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.vault": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.inference": frozenset(
        {"ciso.execution", "ciso.connectors", "ciso.write_adapters", "ciso.api"}
    ),
    "ciso.orchestrator": frozenset(
        {
            "ciso.execution",
            "ciso.connectors",
            "ciso.write_adapters",
            "ciso.inference.external",
            "ciso.api",
        }
    ),
    "ciso.connectors": frozenset(
        {"ciso.execution", "ciso.write_adapters", "ciso.inference", "ciso.orchestrator"}
    ),
    "ciso.memory": frozenset({"ciso.execution", "ciso.write_adapters", "ciso.inference.external"}),
    "ciso.discovery": frozenset({"ciso.write_adapters", "ciso.inference.external"}),
    "ciso.findings": frozenset({"ciso.write_adapters", "ciso.inference.external"}),
    "ciso.workflows": frozenset({"ciso.inference.external", "ciso.write_adapters"}),
}

#: Modules that can open network connections. Nothing in this build may import them
#: unless its dotted module name is listed in NETWORK_ALLOWLIST.
NETWORK_MODULES = frozenset(
    {
        "socket",
        "ssl",
        "http.client",
        "urllib.request",
        "urllib3",
        "httpx",
        "requests",
        "aiohttp",
        "websockets",
        "ftplib",
        "smtplib",
        "telnetlib",
        "asyncio.streams",
    }
)
NETWORK_ALLOWLIST: frozenset[str] = frozenset()

#: Blueprint 8.4: the external model path is never part of normal routing. Only a human
#: acting through this API router, and the composition root that builds it, may hold it.
EXTERNAL_INFERENCE = "ciso.inference.external"
EXTERNAL_INFERENCE_IMPORTERS = frozenset(
    {"ciso.api.routers.external_inference", "ciso.app.container"}
)

#: Packages where code may not load other code by name at run time, because that would
#: walk around every rule in this file.
NO_DYNAMIC_IMPORT = (
    "ciso.policy",
    "ciso.approvals",
    "ciso.execution",
    "ciso.inference",
    "ciso.orchestrator",
    "ciso.connectors",
    "ciso.memory",
)

#: Names a read connector must never define. Blueprint 13.1, 19.1.
WRITE_METHOD_PREFIXES = ("execute", "write", "delete", "update", "create", "disable", "revoke")


def _modules() -> Iterator[tuple[str, Path]]:
    for path in sorted(SRC.rglob("*.py")):
        relative = path.relative_to(SRC.parent).with_suffix("")
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        yield ".".join(parts), path


def _module_name(path: Path) -> tuple[str, bool]:
    """Dotted name of a source file and whether it is a package `__init__`."""
    try:
        relative = path.resolve().relative_to(SRC.parent).with_suffix("")
    except ValueError:
        return path.stem, False
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        return ".".join(parts[:-1]), True
    return ".".join(parts), False


def _imports(path: Path, module: str | None = None, is_package: bool = False) -> set[str]:
    """Absolute dotted names a file imports. Relative imports are resolved first, so
    `from ..inference import gateway` cannot slip past a rule written with absolute names.
    """
    if module is None:
        module, is_package = _module_name(path)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package_parts = module.split(".") if is_package else module.split(".")[:-1]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                keep = len(package_parts) - (node.level - 1)
                anchor = package_parts[: max(keep, 0)]
                base = ".".join([*anchor, node.module] if node.module else anchor)
            if base:
                found.add(base)
            found.update(f"{base}.{alias.name}" if base else alias.name for alias in node.names)
    return found


def _under(name: str, package: str) -> bool:
    return name == package or name.startswith(package + ".")


def test_source_tree_was_found() -> None:
    """Guard against the checks below passing because they scanned nothing."""
    names = [name for name, _ in _modules()]
    assert "ciso.common.enums" in names
    assert len(names) >= 8


def test_trust_boundaries_hold() -> None:
    violations: list[str] = []
    for module, path in _modules():
        imported = _imports(path)
        for package, banned in FORBIDDEN.items():
            if not _under(module, package):
                continue
            for name in imported:
                for target in banned:
                    if _under(name, target):
                        violations.append(f"{module} imports {name} (forbidden for {package})")
    assert not violations, "\n".join(sorted(set(violations)))


def test_no_module_can_reach_the_network() -> None:
    violations: list[str] = []
    for module, path in _modules():
        if module in NETWORK_ALLOWLIST:
            continue
        for name in _imports(path):
            if any(_under(name, net) for net in NETWORK_MODULES):
                violations.append(f"{module} imports {name}")
    assert not violations, "\n".join(sorted(set(violations)))


def test_only_the_human_path_can_reach_external_inference() -> None:
    violations: list[str] = []
    for module, path in _modules():
        if _under(module, EXTERNAL_INFERENCE) or module in EXTERNAL_INFERENCE_IMPORTERS:
            continue
        for name in _imports(path):
            if _under(name, EXTERNAL_INFERENCE):
                violations.append(f"{module} imports {name}")
    assert not violations, "\n".join(sorted(set(violations)))


def test_guarded_packages_do_not_import_by_name_at_run_time() -> None:
    violations: list[str] = []
    for module, path in _modules():
        if not any(_under(module, package) for package in NO_DYNAMIC_IMPORT):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(name == "importlib" or name.startswith("importlib.") for name in _imports(path)):
            violations.append(f"{module} imports importlib")
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "__import__"
            ):
                violations.append(f"{module} calls __import__()")
    assert not violations, "\n".join(sorted(set(violations)))


def test_no_dynamic_code_or_shell_execution() -> None:
    """Blueprint 9.5: no arbitrary shell or generic execution reachable by the agent."""
    banned_imports = {"subprocess", "os.system", "pty", "ctypes", "importlib.import_module"}
    banned_calls = {"eval", "exec", "compile", "__import__"}
    violations: list[str] = []
    for module, path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for name in _imports(path):
            if name in banned_imports or name.split(".")[0] in {"subprocess", "pty", "ctypes"}:
                violations.append(f"{module} imports {name}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in banned_calls:
                    violations.append(f"{module} calls {func.id}()")
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr in {"system", "popen"}
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "os"
                ):
                    violations.append(f"{module} calls os.{func.attr}()")
    assert not violations, "\n".join(sorted(set(violations)))


def test_read_connectors_define_no_write_methods() -> None:
    """No file under ciso.connectors is exempt. Write adapters live in ciso.write_adapters,
    a separate package that connectors may not import.
    """
    connectors = SRC / "connectors"
    if not connectors.exists():
        pytest.skip("ciso.connectors is not built yet")
    scanned = 0
    violations: list[str] = []
    for path in sorted(connectors.rglob("*.py")):
        scanned += 1
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
                WRITE_METHOD_PREFIXES
            ):
                violations.append(f"{path.relative_to(SRC)}: {node.name}")
    assert scanned > 0, "ciso.connectors exists but holds no Python files"
    assert not violations, "\n".join(violations)


class TestTheCheckerItself:
    """Mutation checks: prove the scanner sees a violation when one exists."""

    def test_import_scanner_sees_plain_and_from_imports(self, tmp_path: Path) -> None:
        sample = tmp_path / "m.py"
        sample.write_text(
            "import socket\nfrom ciso.inference import gateway\nfrom urllib import request\n",
            encoding="utf-8",
        )
        found = _imports(sample)
        assert "socket" in found
        assert "ciso.inference" in found
        assert "ciso.inference.gateway" in found
        assert "urllib.request" in found

    def test_under_matches_package_and_children_only(self) -> None:
        assert _under("ciso.policy.engine", "ciso.policy")
        assert _under("ciso.policy", "ciso.policy")
        assert not _under("ciso.policy_extra", "ciso.policy")

    def test_relative_imports_are_resolved_to_absolute_names(self, tmp_path: Path) -> None:
        sample = tmp_path / "m.py"
        sample.write_text(
            "from ..inference import gateway\nfrom . import sibling\nfrom .x import y\n",
            encoding="utf-8",
        )
        found = _imports(sample, module="ciso.policy.engine")
        assert "ciso.inference" in found
        assert "ciso.inference.gateway" in found
        assert "ciso.policy.sibling" in found
        assert "ciso.policy.x.y" in found

    def test_relative_imports_from_a_package_init_are_resolved(self, tmp_path: Path) -> None:
        sample = tmp_path / "__init__.py"
        sample.write_text("from ..inference.external import gateway\n", encoding="utf-8")
        found = _imports(sample, module="ciso.orchestrator", is_package=True)
        assert "ciso.inference.external" in found
        assert "ciso.inference.external.gateway" in found
