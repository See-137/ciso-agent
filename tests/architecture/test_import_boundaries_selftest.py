"""Planted violations for `test_import_boundaries.py`: every detector there must report
one when it is there, and must stay quiet on ordinary code.

Each case is the smallest source that shows one spelling of one evasion. A case that
names a module path is written to a tmp `ciso` package tree and loaded from disk the way
the real tree is; the rest are parsed from text under a module name.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.architecture.scanning import (
    Source,
    bare_names,
    hits,
    imports,
    parse,
    plant,
    references,
    under,
)
from tests.architecture.test_import_boundaries import (
    READ_OPERATIONS,
    allowlist_report,
    connector_write_report,
    dynamic_import_report,
    forbidden_report,
    guard_of,
    importer_report,
    loop_library_report,
    network_report,
    process_report,
    require_scanned,
    unclassified_packages,
)

pytestmark = pytest.mark.unit


def _planted(tmp_path: Path, module: str, text: str) -> tuple[Source, ...]:
    """A tmp `ciso` tree holding one planted module (and its package files)."""
    return plant(tmp_path, {module.replace(".", "/") + ".py": text})


class TestTheCheckerItself:
    """Planted violations: every detector must report one when it is there."""

    def test_import_scanner_sees_plain_and_from_imports(self, tmp_path: Path) -> None:
        text = "import socket\nfrom ciso.inference import gateway\nfrom urllib import request\n"
        found = {ref.name for ref in imports(_planted(tmp_path, "ciso.m", text)[0])}
        assert {"socket", "ciso.inference", "ciso.inference.gateway", "urllib.request"} <= found

    def test_under_matches_package_and_children_only(self) -> None:
        assert under("ciso.policy.engine", "ciso.policy")
        assert under("ciso.policy", "ciso.policy")
        assert not under("ciso.policy_extra", "ciso.policy")

    def test_relative_imports_are_resolved_to_absolute_names(self) -> None:
        text = "from ..inference import gateway\nfrom . import sibling\nfrom .x import y\n"
        found = {ref.name for ref in imports(parse(text, "ciso.policy.engine"))}
        assert {"ciso.inference", "ciso.inference.gateway"} <= found
        assert {"ciso.policy.sibling", "ciso.policy.x.y"} <= found

    def test_relative_imports_from_a_package_init_are_resolved(self) -> None:
        source = parse("from ..inference.external import gateway\n", "ciso.orchestrator", True)
        found = {ref.name for ref in imports(source)}
        assert {"ciso.inference.external", "ciso.inference.external.gateway"} <= found

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("import os as o\no.system('id')\n", "os.system"),
            ("from os import popen as p\np('id')\n", "os.popen"),
            ("import os\nrun = os.system\nagain = run\nagain('id')\n", "os.system"),
            ("import os, sys\na, b = os, sys\nb.modules\n", "sys.modules"),
            ("import os\ngetattr(os, 'system')('id')\n", "os.system"),
            ("import os\ngetattr(os, 'sys' + 'tem')('id')\n", "os.<dynamic>"),
            ("import os\nvars(os)['system']('id')\n", "os.<dynamic>"),
            ("import os\nos.__dict__['system']('id')\n", "os.<dynamic>"),
            ("from os import *\n", "os.*"),
            ("import ciso as c\nc.inference.gateway.X\n", "ciso.inference.gateway.X"),
            ("def f():\n    import importlib as i\n    return i.util\n", "importlib.util"),
            ("from os import path\npath.join('a')\n", "os.path.join"),
            (
                "from concurrent import futures as f\nf.ProcessPoolExecutor()\n",
                "concurrent.futures.ProcessPoolExecutor",
            ),
        ],
    )
    def test_aliases_are_resolved_to_the_real_name(self, text: str, expected: str) -> None:
        assert expected in {ref.name for ref in references(parse(text, "ciso.m"))}

    def test_a_name_that_only_looks_like_a_module_is_not_resolved(self) -> None:
        text = "def f(code, os):\n    return code.strip() + os.sep\n"
        source = parse(text, "ciso.m")
        assert references(source) == []
        assert {ref.name for ref in bare_names(source)} == {"code", "os"}

    def test_pattern_matching(self) -> None:
        names = frozenset({"subprocess", "os.exec*", "sys.modules"})
        assert hits("subprocess.run", names) == "subprocess"
        assert hits("os.execv", names) == "os.exec*"
        assert hits("os.*", names) == "os.exec*"
        assert hits("sys.<dynamic>", names) == "sys.modules"
        assert hits("os.environ", names) is None
        assert hits("os.path.*", names) is None
        assert hits("subprocess_extra", names) is None

    # -- H2: allowlist ------------------------------------------------------------

    @pytest.mark.parametrize(
        ("module", "text", "expected"),
        [
            # A re-export through a package with no rule, the root, or workflows.
            ("ciso.execution.x", "from ciso.ops.bridge import gateway\n", "ciso.ops.bridge"),
            ("ciso.execution.x", "from ciso.app.container import Container\n", "ciso.app"),
            ("ciso.execution.x", "from ciso.workflows import engine\n", "ciso.workflows"),
            # The attribute walk from the top package, in each spelling.
            ("ciso.execution.x", "import ciso\ng = ciso.inference.gateway\n", "`import ciso`"),
            ("ciso.execution.x", "import ciso as c\ng = c.inference.gateway\n", "ciso.inference"),
            ("ciso.policy.x", "import ciso.common\n", "`import ciso.common` hides"),
            ("ciso.policy.x", "import ciso as c\n", "`import ciso` hides"),
            ("ciso.policy.x", "from ciso.common import *\n", "import *` hides"),
            ("ciso.audit.x", "from ciso import inference\n", "ciso.inference"),
            ("ciso.audit.x", "from .. import inference\n", "ciso.inference"),
            ("ciso.vault.x", "import ciso.common as k\ng = getattr(k, 'x').y\n", None),
            # A package nobody has listed.
            ("ciso.identity.x", "import ciso.agents.tools as t\n", "ciso.agents.tools"),
            ("ciso.killswitch.x", "from ciso.observability import logs\n", "ciso.observability"),
            # Review H2 item 6.
            ("ciso.execution.x", "import ciso.connectors as c\n", "ciso.connectors"),
            ("ciso.execution.x", "from ciso.memory import store\n", "ciso.memory"),
            (
                "ciso.approvals.x",
                "from ciso.write_adapters import contract\n",
                "ciso.write_adapters",
            ),
            ("ciso.approvals.x", "from ciso.workflows import queue\n", "ciso.workflows"),
            (
                "ciso.write_adapters.x",
                "from ciso.policy.catalog import OperationSpec\n",
                "ciso.policy",
            ),
            ("ciso.common.x", "from ciso.vault import store\n", "ciso.vault"),
            (
                "ciso.inference.external.x",
                "from ciso.orchestrator import loop\n",
                "ciso.orchestrator",
            ),
            ("ciso.inference.external.x", "from ciso.workflows import queue\n", "ciso.workflows"),
            ("ciso.inference.external.x", "from ciso.memory import store\n", "ciso.memory"),
        ],
    )
    def test_an_import_off_the_allowlist_is_seen(
        self, tmp_path: Path, module: str, text: str, expected: str | None
    ) -> None:
        package = guard_of(module)
        assert package is not None
        scanned, violations = allowlist_report(_planted(tmp_path, module, text), package)
        assert scanned == 1
        if expected is None:
            assert violations == []
        else:
            assert any(expected in line for line in violations), violations

    def test_the_allowed_imports_pass(self, tmp_path: Path) -> None:
        text = (
            "from __future__ import annotations\n"
            "import json\n"
            "from ciso.common.schemas import Model\n"
            "from ciso.policy.envelope import ActionEnvelope\n"
            "from ciso.approvals import ApprovalService\n"
            "from ciso import common\n"
            "from . import tools\n"
            "from .records import Run\n"
            "kind = common.enums.ActorType\n"
        )
        sources = _planted(tmp_path, "ciso.execution.x", text)
        assert allowlist_report(sources, "ciso.execution") == (1, [])
        assert forbidden_report(sources, "ciso.execution") == (1, [])

    def test_a_package_with_no_rule_is_seen(self, tmp_path: Path) -> None:
        sources = _planted(tmp_path, "ciso.unregistered.x", "from ciso.inference import gateway\n")
        assert unclassified_packages(sources) == ["ciso.unregistered"]
        assert unclassified_packages(_planted(tmp_path / "b", "ciso.policy.x", "")) == []

    # -- H2: denylist and importers ---------------------------------------------------

    @pytest.mark.parametrize(
        ("module", "text", "expected"),
        [
            (
                "ciso.orchestrator.x",
                "from ciso.approvals.store import ApprovalStore\n",
                "ciso.approvals",
            ),
            ("ciso.orchestrator.x", "import ciso.vault as v\n", "ciso.vault"),
            ("ciso.orchestrator.x", "from ciso import killswitch\n", "ciso.killswitch"),
            (
                "ciso.orchestrator.x",
                "import ciso\nt = ciso.execution.tools\n",
                "ciso.execution.tools",
            ),
            ("ciso.connectors.x", "from ..write_adapters import contract\n", "ciso.write_adapters"),
            ("ciso.policy.x", "from ciso.inference import gateway\n", "ciso.inference"),
        ],
    )
    def test_a_forbidden_import_is_seen(
        self, tmp_path: Path, module: str, text: str, expected: str
    ) -> None:
        package = ".".join(module.split(".")[:2])
        scanned, violations = forbidden_report(_planted(tmp_path, module, text), package)
        assert scanned == 1
        assert any(expected in line for line in violations), violations

    @pytest.mark.parametrize(
        ("target", "module", "text"),
        [
            (
                "ciso.execution",
                "ciso.api.routers.chat",
                "from ciso.execution.tools import ToolRegistry\n",
            ),
            (
                "ciso.execution",
                "ciso.workflows.x",
                "from ciso.execution.tools import ToolRegistry\n",
            ),
            (
                "ciso.execution",
                "ciso.memory.x",
                "import ciso\nr = ciso.execution.tools.ToolRegistry\n",
            ),
            ("ciso.execution", "ciso.agents.x", "from ciso.execution import ToolRegistry\n"),
            ("ciso.write_adapters", "ciso.api.routers.chat", "import ciso.write_adapters\n"),
            ("ciso.write_adapters", "ciso.agents.x", "import ciso.write_adapters as w\n"),
            (
                "ciso.approvals",
                "ciso.orchestrator.x",
                "from ciso.approvals.store import ApprovalStore\n",
            ),
            (
                "ciso.approvals",
                "ciso.inference.gateway",
                "from ciso.approvals import ApprovalService\n",
            ),
            ("ciso.approvals", "ciso.connectors.x", "from ciso import approvals\n"),
            ("ciso.approvals", "ciso.workflows.x", "from ..approvals import service\n"),
            ("ciso.approvals", "ciso.memory.x", "import ciso.approvals.service as s\n"),
            (
                "ciso.approvals",
                "ciso.discovery.x",
                "from ciso.approvals.service import ApprovalService\n",
            ),
            ("ciso.approvals", "ciso.findings.x", "from ciso.approvals import Approval\n"),
            (
                "ciso.approvals",
                "ciso.api.routers.system",
                "from ciso.approvals import ApprovalService\n",
            ),
            (
                "ciso.inference.external",
                "ciso.orchestrator.x",
                "from ciso.inference.external import gateway\n",
            ),
            (
                "ciso.inference.external",
                "ciso.inference.gateway",
                "from .external import gateway\n",
            ),
            ("ciso.app", "ciso.workflows.x", "from ciso.app.container import Container\n"),
            ("ciso.app", "ciso.execution.x", "from ciso.app.container import Container\n"),
            ("ciso.api", "ciso.ops.x", "from ciso.api.deps import require\n"),
        ],
    )
    def test_an_importer_that_is_not_named_is_seen(
        self, tmp_path: Path, target: str, module: str, text: str
    ) -> None:
        scanned, violations = importer_report(_planted(tmp_path, module, text), target)
        assert scanned == 1
        assert len(violations) >= 1
        assert all(target in line for line in violations)

    @pytest.mark.parametrize(
        ("target", "module", "text"),
        [
            ("ciso.execution", "ciso.app.container", "from ciso.execution import Broker\n"),
            ("ciso.execution", "ciso.api.routers.execution", "from ciso.execution import Broker\n"),
            ("ciso.execution", "ciso.execution.broker", "from ciso.execution.tools import Tool\n"),
            (
                "ciso.write_adapters",
                "ciso.execution.x",
                "from ciso.write_adapters import contract\n",
            ),
            ("ciso.approvals", "ciso.execution.gates", "from ciso.approvals import Approval\n"),
            (
                "ciso.approvals",
                "ciso.inference.external.gateway",
                "from ciso.approvals import Approval\n",
            ),
            (
                "ciso.approvals",
                "ciso.api.routers.approvals",
                "from ciso.approvals import Approval\n",
            ),
            (
                "ciso.approvals",
                "ciso.api.routers.external_inference",
                "import ciso.approvals as a\n",
            ),
            (
                "ciso.approvals",
                "ciso.app.container",
                "from ciso.approvals import ApprovalService\n",
            ),
            ("ciso.approvals", "ciso.approvals.service", "from ciso.approvals.store import S\n"),
            ("ciso.app", "ciso.api.deps", "from ciso.app.container import Container\n"),
        ],
    )
    def test_a_named_importer_passes(
        self, tmp_path: Path, target: str, module: str, text: str
    ) -> None:
        scanned, violations = importer_report(_planted(tmp_path, module, text), target)
        assert (scanned, violations) == (0, [])
        # The same file under a name that is not listed is counted and refused.
        other = _planted(
            tmp_path / "other", "ciso.reporting.x", text.replace("from .", "from ciso.")
        )
        assert importer_report(other, target)[0] == 1

    def test_a_rule_that_scanned_nothing_is_a_skip_not_a_pass(self, tmp_path: Path) -> None:
        sources = _planted(tmp_path, "ciso.policy.x", "")
        scanned, violations = forbidden_report(sources, "ciso.connectors")
        assert (scanned, violations) == (0, [])
        with pytest.raises(pytest.skip.Exception, match="scanned 0 files"):
            require_scanned(scanned, "ciso.connectors", tmp_path / "ciso")
        # A package that exists but yields no files is a failure, not a skip.
        (tmp_path / "ciso" / "connectors").mkdir()
        with pytest.raises(pytest.fail.Exception, match="exists but the rule scanned 0"):
            require_scanned(scanned, "ciso.connectors", tmp_path / "ciso")
        require_scanned(1, "ciso.connectors", tmp_path / "ciso")

    # -- H3: process, network, dynamic import ---------------------------------------

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("import subprocess\n", "subprocess"),
            ("from subprocess import run as r\n", "subprocess.run"),
            ("import os\nos.system('id')\n", "os.system"),
            ("from os import popen\npopen('id')\n", "os.popen"),
            ("from os import system as s\n", "os.system"),
            ("import os as o\no.system('id')\n", "os.system"),
            ("import os\nos.execv('/bin/sh', ['sh'])\n", "os.execv"),
            ("from os import execle\n", "os.execle"),
            ("import os\nos.spawnv(0, 'x', [])\n", "os.spawnv"),
            ("from os import spawnlp\n", "os.spawnlp"),
            ("import os\nos.posix_spawn('x', [], {})\n", "os.posix_spawn"),
            ("import os\nos.fork()\n", "os.fork"),
            ("import os\nos.startfile('x')\n", "os.startfile"),
            ("import os\nf = os.system\nf('id')\n", "os.system"),
            ("import os\ngetattr(os, 'system')('id')\n", "os.system"),
            ("import os\ngetattr(os, 'sys' + 'tem')('id')\n", "os.<dynamic>"),
            ("from os import *\n", "os.*"),
            ("import nt\nnt.system('id')\n", "nt"),
            (
                "import asyncio\nasync def f():\n    await asyncio.create_subprocess_shell('id')\n",
                "create_subprocess_shell",
            ),
            (
                "import asyncio as a\nasync def f():\n    await a.create_subprocess_exec('id')\n",
                "asyncio.create_subprocess_exec",
            ),
            ("from asyncio import subprocess\n", "asyncio.subprocess"),
            ("async def f(loop):\n    await loop.subprocess_exec(P, 'id')\n", ".subprocess_exec"),
            ("def f(mod):\n    mod.popen('id')\n", ".popen"),
            (
                "import multiprocessing\nmultiprocessing.Process(target=f).start()\n",
                "multiprocessing",
            ),
            ("from concurrent.futures import ProcessPoolExecutor\n", "ProcessPoolExecutor"),
            (
                "from concurrent import futures\nfutures.ProcessPoolExecutor()\n",
                "futures.ProcessPoolExecutor",
            ),
            (
                "import anyio\nasync def f():\n    await anyio.run_process('id')\n",
                "anyio.run_process",
            ),
            ("import code\ncode.interact()\n", "code"),
            ("from codeop import compile_command\n", "codeop"),
            ("import pty\n", "pty"),
            ("import ctypes\n", "ctypes"),
            ("eval('1')\n", "builtin eval"),
            ("run = exec\nrun('1')\n", "builtin exec"),
            ("compile('1', 'x', 'eval')\n", "builtin compile"),
        ],
    )
    def test_a_process_or_code_execution_spelling_is_seen(self, text: str, expected: str) -> None:
        scanned, violations = process_report((parse(text, "ciso.planted"),))
        assert scanned == 1
        assert any(expected in line for line in violations), violations

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("import socket\n", "socket"),
            ("from socket import create_connection as c\n", "socket.create_connection"),
            ("import ssl\n", "ssl"),
            ("import urllib\n", "urllib"),
            ("from urllib import request\n", "urllib.request"),
            ("import http.client\n", "http.client"),
            ("import http.server\n", "http.server"),
            ("import socketserver\n", "socketserver"),
            ("import xmlrpc.client\n", "xmlrpc.client"),
            ("import imaplib\n", "imaplib"),
            ("import poplib\n", "poplib"),
            ("import smtplib\n", "smtplib"),
            ("import httpx\n", "httpx"),
            ("import requests\n", "requests"),
            ("from multiprocessing.connection import Client\n", "multiprocessing.connection"),
            (
                "import asyncio\nasync def f():\n    await asyncio.open_connection('h', 443)\n",
                "asyncio.open_connection",
            ),
            ("from asyncio import start_server as s\n", "asyncio.start_server"),
            ("import asyncio as a\nopen_it = a.open_connection\n", "asyncio.open_connection"),
            ("import asyncio\ngetattr(asyncio, name)\n", "asyncio.<dynamic>"),
            (
                "async def f(loop):\n    await loop.create_connection(P, 'h', 443)\n",
                ".create_connection",
            ),
            ("async def f(loop):\n    await loop.create_server(P, 'h', 443)\n", ".create_server"),
            (
                "async def f(loop):\n    await getattr(loop, 'sock_connect')(s, a)\n",
                ".sock_connect",
            ),
            (
                "import anyio\nasync def f():\n    await anyio.connect_tcp('h', 443)\n",
                "anyio.connect_tcp",
            ),
        ],
    )
    def test_a_network_spelling_is_seen(self, text: str, expected: str) -> None:
        scanned, violations = network_report((parse(text, "ciso.planted"),))
        assert scanned == 1
        assert any(expected in line for line in violations), violations

    @pytest.mark.parametrize(
        ("module", "text", "seen"),
        [
            ("ciso.workflows.x", "import asyncio\n", True),
            ("ciso.api.app", "from asyncio import sleep\n", True),
            ("ciso.api.deps", "import anyio\n", True),
            ("ciso.api.app", "import anyio\nanyio.to_thread.run_sync(f)\n", False),
            ("ciso.app.container", "import uvicorn\n", True),
            ("ciso.api.__main__", "import uvicorn\nuvicorn.run(app)\n", False),
            ("ciso.orchestrator.x", "from fastapi import FastAPI\n", True),
            ("ciso.api.routers.system", "from fastapi import APIRouter\n", False),
        ],
    )
    def test_an_event_loop_library_outside_its_named_users_is_seen(
        self, module: str, text: str, seen: bool
    ) -> None:
        scanned, violations = loop_library_report((parse(text, module),))
        assert scanned == 1
        assert bool(violations) is seen, violations

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("import importlib\n", "importlib"),
            (
                "import importlib as i\ni.import_module('ciso.inference')\n",
                "importlib.import_module",
            ),
            ("from importlib import import_module\n", "importlib.import_module"),
            ("from importlib import import_module as load\nload('x')\n", "importlib.import_module"),
            ("import importlib.util\n", "importlib.util"),
            ("from importlib.util import spec_from_file_location\n", "importlib.util"),
            ("def f(lib):\n    return lib.import_module('ciso.inference')\n", ".import_module"),
            ("__import__('ciso.inference.gateway')\n", "builtin __import__"),
            ("load = __import__\n", "builtin __import__"),
            (
                "import builtins\nbuiltins.__import__('ciso.inference.gateway')\n",
                "builtins.__import__",
            ),
            ("import builtins as b\nb.eval('1')\n", "builtins.eval"),
            ("from builtins import __import__ as load\n", "builtins.__import__"),
            ("import sys\nm = sys.modules['ciso.inference.gateway']\n", "sys.modules"),
            ("import sys\nm = sys.modules.get('ciso.orchestrator')\n", "sys.modules"),
            ("from sys import modules\n", "sys.modules"),
            ("import sys as s\nloaded = s.modules\n", "sys.modules"),
            ("import sys\ngetattr(sys, 'mod' + 'ules')\n", "sys.<dynamic>"),
            ("import pkgutil\npkgutil.resolve_name('ciso.inference.gateway')\n", "pkgutil"),
            ("import runpy\nrunpy.run_module('ciso.inference.gateway')\n", "runpy"),
            ("from runpy import run_path\n", "runpy.run_path"),
        ],
    )
    def test_a_dynamic_import_spelling_is_seen(self, text: str, expected: str) -> None:
        scanned, violations = dynamic_import_report((parse(text, "ciso.observability.planted"),))
        assert scanned == 1
        assert any(expected in line for line in violations), violations

    def test_ordinary_code_is_not_reported(self) -> None:
        text = (
            "import json, os, re, shutil, sys\n"
            "from concurrent.futures import Future, wait\n"
            "from pathlib import Path\n"
            "PATTERN = re.compile('x')\n"
            "def f(code: str, handle, settings, name, self):\n"
            "    os.fsync(handle.fileno())\n"
            "    shutil.rmtree(Path(code))\n"
            "    sys.stdout.write(json.loads(code))\n"
            "    self.system = os.environ.get('X', os.name)\n"
            "    return getattr(settings, name), os.urandom(4), sys.exit, type(self)\n"
        )
        source = (parse(text, "ciso.planted"),)
        assert process_report(source) == (1, [])
        assert network_report(source) == (1, [])
        assert dynamic_import_report(source) == (1, [])
        assert loop_library_report(source) == (1, [])

    # -- L6: read connectors ----------------------------------------------------------

    @pytest.mark.parametrize(
        "name",
        [
            "execute_action",
            "apply",
            "rollback",
            "send_ticket",
            "post_comment",
            "put_tag",
            "patch_rule",
            "remove_user",
            "set_state",
            "isolate_host",
            "block_ip",
            "run",
            "invoke",
            "close_ticket",
            "reset_password",
            "create_ticket",
            "grant_role",
            "rotate_key",
            "enable_account",
        ],
    )
    def test_a_write_named_connector_method_is_seen(self, name: str) -> None:
        text = f"class C:\n    def list_assets(self): ...\n    async def {name}(self): ...\n"
        scanned, violations = connector_write_report((parse(text, "ciso.connectors.x"),))
        assert scanned == 1
        assert violations == [f"ciso.connectors.x:3 defines {name}"]

    def test_a_write_method_bound_by_assignment_is_seen(self) -> None:
        text = "def _helper(self): ...\nclass C:\n    send_ticket = _helper\n"
        scanned, violations = connector_write_report((parse(text, "ciso.connectors.x"),))
        assert (scanned, violations) == (1, ["ciso.connectors.x:2 defines send_ticket"])

    def test_the_blueprint_read_operations_stay_allowed(self) -> None:
        body = "".join(f"    def {name}(self): ...\n" for name in READ_OPERATIONS)
        text = f"class C:\n{body}    def close(self): ...\n    def _update_cursor(self): ...\n"
        assert connector_write_report((parse(text, "ciso.connectors.x"),)) == (1, [])
        # Outside ciso.connectors the rule does not apply and counts nothing.
        other = parse("def send_ticket(): ...\n", "ciso.execution.x")
        assert connector_write_report((other,)) == (0, [])
