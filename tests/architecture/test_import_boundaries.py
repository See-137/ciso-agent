"""Trust boundaries are enforced here, not by convention.

Blueprint 9.5: the policy engine and execution broker are a separate trust boundary from
the LLM. Blueprint 8.4: no component reaches the network except through an approved path.
These tests read the source tree, so they hold even for code no other test exercises.

How the rules fit together:

- `ALLOWED_INTERNAL` is an allowlist. Each guarded package may refer to the listed `ciso`
  packages and nothing else, so a new or unlisted package cannot carry an import across a
  boundary. Every package a trust root is allowed to use is itself a trust root with its
  own list (`test_the_allowlist_is_closed`), which is what makes the rule hold through
  any chain of imports and not only for direct ones.
- `FORBIDDEN` is the older denylist. It stays, and it is the only rule for packages that
  are not guarded (inference, the orchestrator, connectors and so on).
- `IMPORTERS` says who may refer to a sensitive package at all.
- The process, network and dynamic-import rules ban by resolved dotted name, so an alias
  does not hide a call. `scanning.py` says what that resolution can and cannot see.

"Refers to" means an import in any form, or a use through a bound name
(`import ciso as c` then `c.inference.gateway`). In a guarded package the forms that bind
the bare top package (`import ciso`, `import ciso as c`, `import ciso.common` with no
`as`) and `from ciso... import *` are refused outright, because what they reach cannot be
read from the import line. `from ciso import vault` is not refused: it names its target.

A rule about a package that does not exist yet is reported as a skip that says it scanned
0 files. It is not counted as a pass.

Not seen by any rule here: a database URL that points at a remote host, and anything the
limits section of `scanning.py` lists.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from tests.architecture.scanning import (
    DYNAMIC,
    Source,
    attribute_names,
    bare_names,
    hits,
    load,
    references,
    top_package_bindings,
    under,
)

pytestmark = pytest.mark.unit

SRC = Path(__file__).resolve().parents[2] / "src" / "ciso"
TOP = "ciso"


def _words(text: str) -> list[str]:
    """A long list of names, written as one space-separated string."""
    return text.split()


#: (files the rule looked at, what it found).
Report = tuple[int, list[str]]

_COMMON = "shared contracts: schemas, enums, errors, ids, clock, database metadata"

#: Guarded package -> the `ciso` packages it may refer to, each with the reason.
#: Measured from the tree on 2026-11-18; nothing is listed that is not imported today.
#: A package always may refer to itself.
ALLOWED_INTERNAL: dict[str, dict[str, str]] = {
    "ciso.common": {},
    "ciso.policy": {"ciso.common": _COMMON},
    "ciso.approvals": {"ciso.common": _COMMON},
    "ciso.execution": {
        "ciso.common": _COMMON,
        "ciso.policy": "the broker asks the policy engine and reads envelopes and the catalog",
        "ciso.approvals": "the broker checks and consumes approvals (ADR-0010, G3)",
    },
    "ciso.write_adapters": {"ciso.common": _COMMON},
    "ciso.audit": {
        "ciso.common": _COMMON,
        "ciso.vault": "the anchor key is a secret reference resolved through the vault",
    },
    "ciso.killswitch": {
        "ciso.common": _COMMON,
        "ciso.vault": "the state integrity key and the break-glass secret come from the vault",
    },
    "ciso.identity": {"ciso.common": _COMMON},
    "ciso.vault": {"ciso.common": _COMMON},
    # AI-activity governance (docs/skill/spec-draft.md). Each judges or records what other
    # people's agents do, so no model output may steer it.
    "ciso.agents": {"ciso.common": _COMMON},
    "ciso.governance": {"ciso.common": _COMMON},
    "ciso.inspection": {
        "ciso.common": _COMMON,
        "ciso.vault": "secret detection reuses the vault's token-shape patterns",
    },
    "ciso.findings": {"ciso.common": _COMMON},
    # Not a trust root, but the one path that can leave the building (blueprint 8.4).
    "ciso.inference.external": {
        "ciso.common": _COMMON,
        "ciso.approvals": "every external request is bound to a consumed human approval (G3)",
        "ciso.inference": "its parent package: the untrusted-output record type",
        "ciso.vault": "the approval-binding key is a secret reference",
    },
}

#: The packages no model output may steer. The allowlist is closed over this set.
TRUST_ROOTS = frozenset(ALLOWED_INTERNAL) - {"ciso.inference.external"}

#: package -> packages it must never refer to.
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
    # Approvals serve both the broker and the external inference gate (G3), so they
    # depend on neither, nor on the policy engine whose decisions they are bound to.
    "ciso.approvals": frozenset(
        {"ciso.inference", "ciso.orchestrator", "ciso.api", "ciso.execution", "ciso.policy"}
    ),
    "ciso.execution": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.write_adapters": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.audit": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.killswitch": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.identity": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.vault": frozenset({"ciso.inference", "ciso.orchestrator", "ciso.api"}),
    "ciso.inference": frozenset(
        {"ciso.execution", "ciso.connectors", "ciso.write_adapters", "ciso.api"}
    ),
    # The model side holds no approval store, no secret resolver and no kill switch.
    "ciso.orchestrator": frozenset(
        {
            "ciso.execution",
            "ciso.connectors",
            "ciso.write_adapters",
            "ciso.inference.external",
            "ciso.api",
            "ciso.approvals",
            "ciso.vault",
            "ciso.killswitch",
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

#: Top-level packages with neither an allowlist nor a denylist row, and why that is right.
#: A package under `src/ciso` that is in none of the three tables fails the build.
UNGUARDED: dict[str, str] = {
    "ciso.app": "the composition root: it builds every service, so it imports every package",
    "ciso.api": "the HTTP surface: it reaches services only through the container in ciso.app",
    "ciso.ops": "operator tooling for backup, restore and lifecycle; never on a request path",
    "ciso.observability": "logs, metrics and health probes; imports ciso.common only",
}

#: Sensitive package -> who else may refer to it. The package itself always may.
IMPORTERS: dict[str, frozenset[str]] = {
    # Blueprint 8.4: the external model path is never part of normal routing. Only a human
    # acting through this API router, and the composition root that builds it, hold it.
    "ciso.inference.external": frozenset(
        {"ciso.api.routers.external_inference", "ciso.app.container"}
    ),
    # The tool-invoking surface. Whoever holds the registry can call a tool without the
    # broker, so only the composition root and a router named for it may. That router
    # (`ciso.api.routers.execution`) is not in the tree or the plan yet; it is named here
    # so the router that needs the broker has exactly one permitted home.
    "ciso.execution": frozenset({"ciso.app", "ciso.api.routers.execution"}),
    "ciso.write_adapters": frozenset({"ciso.execution", "ciso.app"}),
    # Whoever holds the approval service can approve. The broker and the external gate
    # check and consume; the two routers are where a human decides.
    "ciso.approvals": frozenset(
        {
            "ciso.execution",
            "ciso.inference.external",
            "ciso.api.routers.approvals",
            "ciso.api.routers.external_inference",
            "ciso.app",
        }
    ),
    # The container holds every service object, so importing it is importing all of them.
    "ciso.app": frozenset({"ciso.api"}),
    "ciso.api": frozenset(),
}

#: Packages on the model side of the boundary. Each is checked by name against the
#: surfaces below, and reported as skipped while it does not exist.
MODEL_SIDE = (
    "ciso.orchestrator",
    "ciso.inference",
    "ciso.connectors",
    "ciso.workflows",
    "ciso.memory",
    "ciso.discovery",
    "ciso.findings",
)
GUARDED_SURFACES = ("ciso.execution", "ciso.write_adapters", "ciso.approvals")

#: Names that start a process, run a shell or run code from text. Blueprint 9.5.
PROCESS_NAMES = frozenset(
    _words(
        "subprocess pty ctypes multiprocessing code codeop nt posix _posixsubprocess _winapi "
        "os.system os.popen os.exec* os.spawn* os.posix_spawn* os.fork* os.startfile "
        "asyncio.subprocess asyncio.create_subprocess_* anyio.open_process anyio.run_process "
        "concurrent.futures.ProcessPoolExecutor concurrent.futures.process"
    )
)
#: Builtins that run text as code. Refused wherever the bare name is read, called or not.
CODE_BUILTINS = frozenset({"eval", "exec", "compile"})
#: Attribute names refused on any receiver, for a module or loop that was passed in.
PROCESS_ATTRIBUTES = frozenset(
    {
        "popen",
        "startfile",
        "create_subprocess_exec",
        "create_subprocess_shell",
        "subprocess_exec",
        "subprocess_shell",
    }
)

#: Names that can open a network connection or listen for one. Blueprint 8.4.
NETWORK_NAMES = frozenset(
    _words(
        "socket _socket ssl _ssl http urllib urllib3 httpx requests aiohttp websockets grpc "
        "ftplib smtplib smtpd telnetlib imaplib poplib nntplib xmlrpc socketserver asyncore "
        "asynchat webbrowser multiprocessing.connection asyncio.streams "
        "asyncio.open_connection asyncio.start_server asyncio.open_unix_connection "
        "asyncio.start_unix_server anyio.connect_tcp anyio.connect_unix "
        "anyio.create_tcp_listener anyio.create_unix_listener anyio.create_udp_socket "
        "anyio.create_connected_udp_socket"
    )
)
NETWORK_ATTRIBUTES = frozenset(
    _words(
        "create_connection create_unix_connection create_server create_unix_server "
        "create_datagram_endpoint connect_accepted_socket sock_connect open_connection "
        "open_unix_connection start_server start_unix_server connect_tcp"
    )
)
#: Modules exempt from the network rule. Empty: nothing in this build talks to a network.
NETWORK_ALLOWLIST: frozenset[str] = frozenset()

#: Libraries that own an event loop or a listening server -> the only modules that may
#: refer to them. Measured from the tree; `asyncio` has no user at all.
LOOP_LIBRARIES: dict[str, frozenset[str]] = {
    "asyncio": frozenset(),
    "anyio": frozenset({"ciso.api.app"}),
    "uvicorn": frozenset({"ciso.api.__main__"}),
    "fastapi": frozenset({"ciso.api"}),
    "starlette": frozenset({"ciso.api"}),
}

#: Names that load code by name at run time, which would walk around every rule above.
DYNAMIC_IMPORT_NAMES = frozenset(
    {
        "importlib",
        "builtins",
        "pkgutil",
        "runpy",
        "zipimport",
        "imp",
        "sys.modules",
        "sys.meta_path",
        "sys.path_hooks",
    }
)
DYNAMIC_IMPORT_ATTRIBUTES = frozenset({"import_module", "__import__"})
#: Modules exempt from the dynamic-import rule. Empty: the rule covers all of `src`,
#: because an unguarded package that loads by name could be used as a go-between.
DYNAMIC_IMPORT_ALLOWLIST: frozenset[str] = frozenset()

#: Names a read connector must never define. Blueprint 13.1, 19.1. A tripwire (ADR-0011):
#: it catches an honest mistake, not a determined author. Names with a leading
#: underscore are not checked, so a connector can keep private bookkeeping helpers.
WRITE_METHOD_PREFIXES = tuple(
    _words(
        "execute write delete update create disable revoke apply rollback send_ post_ put_ "
        "patch_ set_ add_ insert upsert save modify edit_ remove purge drop_ grant assign "
        "approve reject reset rotate enable isolate quarantine block unblock lock unlock "
        "suspend terminate kill restart close_ run invoke trigger submit deploy install "
        "uninstall upload push restore move_ rename merge tag_ untag"
    )
)
#: The read-connector operations blueprint 13.1 names. They must stay definable.
READ_OPERATIONS = tuple(
    _words(
        "discover_sources health_check list_assets get_asset list_changes subscribe_events "
        "list_findings get_configuration map_identity map_ownership sync_cursor checkpoint"
    )
)


def _where(source: Source, line: int) -> str:
    return f"{source.module}:{line}"


def guard_of(module: str) -> str | None:
    """The `ALLOWED_INTERNAL` row a module falls under: the longest matching package."""
    rows = [package for package in ALLOWED_INTERNAL if under(module, package)]
    return max(rows, key=len) if rows else None


def _internal_target(name: str) -> str | None:
    """The `ciso` name a reference points at, or None if it points outside `ciso`.

    A wildcard reference (`ciso.common.*`) is judged by the module it is taken from.
    """
    if not under(name, TOP):
        return None
    parts = name.split(".")
    return ".".join(parts[:-1]) if parts[-1] in ("*", DYNAMIC) else name


def allowlist_report(sources: tuple[Source, ...], package: str) -> Report:
    """References from a guarded package to any `ciso` package not on its allowlist."""
    allowed = (package, *ALLOWED_INTERNAL[package])
    scanned = 0
    violations: list[str] = []
    for source in sources:
        if guard_of(source.module) != package:
            continue
        scanned += 1
        for hidden in top_package_bindings(source, TOP):
            violations.append(
                f"{_where(source, hidden.line)} `{hidden.name}` hides what it reaches; "
                f"import the module you need by its full name"
            )
        for ref in references(source):
            target = _internal_target(ref.name)
            if target is None or (target == TOP and ref.name == TOP):
                continue  # not ours, or the base of `from ciso import x` (x is judged)
            if not any(under(target, name) for name in allowed):
                violations.append(
                    f"{_where(source, ref.line)} refers to {ref.name} "
                    f"(not on the allowlist for {package})"
                )
    return scanned, sorted(set(violations))


def forbidden_report(sources: tuple[Source, ...], package: str) -> Report:
    """References from a package to anything on its denylist."""
    scanned = 0
    violations: list[str] = []
    for source in sources:
        if not under(source.module, package):
            continue
        scanned += 1
        for ref in references(source):
            target = _internal_target(ref.name)
            if target is not None and any(under(target, bad) for bad in FORBIDDEN[package]):
                violations.append(
                    f"{_where(source, ref.line)} refers to {ref.name} (forbidden for {package})"
                )
    return scanned, sorted(set(violations))


def importer_report(sources: tuple[Source, ...], target: str) -> Report:
    """References to a sensitive package from a module that is not one of its importers."""
    permitted = (target, *IMPORTERS[target])
    scanned = 0
    violations: list[str] = []
    for source in sources:
        if any(under(source.module, name) for name in permitted):
            continue
        scanned += 1
        for ref in references(source):
            found = _internal_target(ref.name)
            if found is not None and under(found, target):
                violations.append(
                    f"{_where(source, ref.line)} refers to {ref.name} "
                    f"(only {sorted(permitted)} may)"
                )
    return scanned, sorted(set(violations))


def unclassified_packages(sources: tuple[Source, ...]) -> list[str]:
    """Top-level packages that no table in this file has a row for."""
    known = {*ALLOWED_INTERNAL, *FORBIDDEN, *UNGUARDED}
    tops = {".".join(s.module.split(".")[:2]) for s in sources if "." in s.module}
    return sorted(tops - known)


def _banned_report(
    sources: tuple[Source, ...],
    names: frozenset[str],
    attributes: frozenset[str],
    builtins: frozenset[str],
    exempt: frozenset[str],
) -> Report:
    scanned = 0
    violations: list[str] = []
    for source in sources:
        if source.module in exempt:
            continue
        scanned += 1
        for ref in references(source):
            pattern = hits(ref.name, names)
            if pattern is not None:
                violations.append(f"{_where(source, ref.line)} uses {ref.name} (banned: {pattern})")
        for ref in attribute_names(source):
            if ref.name in attributes:
                violations.append(
                    f"{_where(source, ref.line)} uses .{ref.name} (banned on any object)"
                )
        for ref in bare_names(source):
            if ref.name in builtins:
                violations.append(f"{_where(source, ref.line)} uses the builtin {ref.name}")
    return scanned, sorted(set(violations))


def process_report(sources: tuple[Source, ...]) -> Report:
    return _banned_report(sources, PROCESS_NAMES, PROCESS_ATTRIBUTES, CODE_BUILTINS, frozenset())


def network_report(sources: tuple[Source, ...]) -> Report:
    return _banned_report(
        sources, NETWORK_NAMES, NETWORK_ATTRIBUTES, frozenset(), NETWORK_ALLOWLIST
    )


def dynamic_import_report(sources: tuple[Source, ...]) -> Report:
    return _banned_report(
        sources,
        DYNAMIC_IMPORT_NAMES,
        DYNAMIC_IMPORT_ATTRIBUTES,
        frozenset({"__import__"}),
        DYNAMIC_IMPORT_ALLOWLIST,
    )


def loop_library_report(sources: tuple[Source, ...]) -> Report:
    """References to an event-loop or server library from a module not named for it."""
    violations: list[str] = []
    for source in sources:
        for ref in references(source):
            for library, users in LOOP_LIBRARIES.items():
                if under(ref.name, library) and not any(under(source.module, u) for u in users):
                    violations.append(
                        f"{_where(source, ref.line)} uses {ref.name} (only {sorted(users)} may)"
                    )
    return len(sources), sorted(set(violations))


def write_like(name: str) -> bool:
    return name.startswith(WRITE_METHOD_PREFIXES)


def connector_write_report(sources: tuple[Source, ...]) -> Report:
    """Functions, methods and class-body assignments in `ciso.connectors` named for a write."""
    scanned = 0
    violations: list[str] = []
    for source in sources:
        if not under(source.module, "ciso.connectors"):
            continue
        scanned += 1
        for node in ast.walk(source.tree):
            names: list[str] = []
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                names.append(node.name)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    targets = item.targets if isinstance(item, ast.Assign) else []
                    names.extend(t.id for t in targets if isinstance(t, ast.Name))
            violations.extend(
                f"{_where(source, node.lineno)} defines {name}"
                for name in names
                if write_like(name)
            )
    return scanned, sorted(set(violations))


def require_scanned(scanned: int, package: str, root: Path = SRC) -> None:
    """A rule that looked at nothing proves nothing: skip with the reason, or fail."""
    if scanned > 0:
        return
    if (root / Path(*package.split(".")[1:])).exists():
        pytest.fail(f"{package} exists but the rule scanned 0 files")
    pytest.skip(f"{package} is not built yet: the rule scanned 0 files and proves nothing")


@pytest.fixture(scope="module")
def tree() -> tuple[Source, ...]:
    return load(SRC)


def test_source_tree_was_found(tree: tuple[Source, ...]) -> None:
    """Guard against the checks below passing because they scanned nothing."""
    names = [source.module for source in tree]
    assert "ciso.common.enums" in names
    assert len(names) >= 8


@pytest.mark.parametrize("package", sorted(ALLOWED_INTERNAL))
def test_guarded_packages_import_only_what_is_allowlisted(
    tree: tuple[Source, ...], package: str
) -> None:
    scanned, violations = allowlist_report(tree, package)
    require_scanned(scanned, package)
    assert not violations, "\n".join(violations)


def test_the_allowlist_is_closed() -> None:
    """Whatever a trust root may use is itself a trust root with its own allowlist, so
    no chain of permitted imports leads out of the guarded set."""
    for package in sorted(TRUST_ROOTS):
        for target in ALLOWED_INTERNAL[package]:
            assert target in TRUST_ROOTS, f"{package} may import {target}, which has no allowlist"
    assert len(TRUST_ROOTS) == 13


def test_every_top_level_package_has_a_rule(tree: tuple[Source, ...]) -> None:
    assert len(tree) >= 8
    assert unclassified_packages(tree) == []


@pytest.mark.parametrize("package", sorted(FORBIDDEN))
def test_trust_boundaries_hold(tree: tuple[Source, ...], package: str) -> None:
    scanned, violations = forbidden_report(tree, package)
    require_scanned(scanned, package)
    assert not violations, "\n".join(violations)


@pytest.mark.parametrize("target", sorted(IMPORTERS))
def test_only_named_importers_reach_a_sensitive_package(
    tree: tuple[Source, ...], target: str
) -> None:
    """Covers the external model path (blueprint 8.4), the tool-invoking surface, the
    write-adapter contract, approvals, and the composition root that holds them all."""
    scanned, violations = importer_report(tree, target)
    assert scanned > 0, f"no module outside the importers of {target} was scanned"
    assert not violations, "\n".join(violations)


@pytest.mark.parametrize("package", MODEL_SIDE)
def test_model_side_packages_hold_no_tool_adapter_or_approval(
    tree: tuple[Source, ...], package: str
) -> None:
    """The same importer rule, asked of each model-side package by name, so a package
    that is not built yet shows up as a skip instead of a silent pass."""
    own = tuple(source for source in tree if under(source.module, package))
    require_scanned(len(own), package)
    scanned = 0
    violations: list[str] = []
    for target in GUARDED_SURFACES:
        count, found = importer_report(own, target)
        scanned += count
        violations.extend(found)
    assert scanned > 0
    assert not violations, "\n".join(violations)


def test_no_module_can_reach_the_network(tree: tuple[Source, ...]) -> None:
    scanned, violations = network_report(tree)
    assert scanned >= 8
    assert not violations, "\n".join(violations)


def test_event_loop_and_server_libraries_have_named_users(tree: tuple[Source, ...]) -> None:
    scanned, violations = loop_library_report(tree)
    assert scanned >= 8
    assert not violations, "\n".join(violations)


def test_no_module_imports_by_name_at_run_time(tree: tuple[Source, ...]) -> None:
    scanned, violations = dynamic_import_report(tree)
    assert scanned >= 8
    assert not violations, "\n".join(violations)


def test_no_dynamic_code_or_shell_execution(tree: tuple[Source, ...]) -> None:
    """Blueprint 9.5: no arbitrary shell or generic execution reachable by the agent."""
    scanned, violations = process_report(tree)
    assert scanned >= 8
    assert not violations, "\n".join(violations)


def test_read_connectors_define_no_write_methods(tree: tuple[Source, ...]) -> None:
    """No file under ciso.connectors is exempt. Write adapters live in ciso.write_adapters,
    a separate package that connectors may not import.
    """
    scanned, violations = connector_write_report(tree)
    require_scanned(scanned, "ciso.connectors")
    assert not violations, "\n".join(violations)
