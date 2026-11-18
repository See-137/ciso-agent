"""The write-adapter contract stays a contract (blueprint 13.1, 19.1; ADR-0010, ADR-0011).

Three rules, all read from the source tree:

1. Nothing in `src` implements `WriteAdapter`. The protocol's own definition in
   `ciso.write_adapters.contract` is the one exception. An implementation is any of:
   - a class that names `WriteAdapter` as a base: directly, as an attribute
     (`contract.WriteAdapter`), subscripted, through an import alias, or through a name
     assigned from it (`Base = contract.WriteAdapter`), and any class below such a class;
   - a class that ends up with all of `apply`, `verify` and `rollback`, counting `def`s,
     assignments in the class body (`apply = _a`, lambdas), assignments after the body
     (`Cls.apply = fn`, `setattr(Cls, "apply", fn)`) and what it inherits from classes
     defined anywhere in `src` (matched by class name);
   - a module whose top level defines all three names;
   - any `type(name, bases, namespace)` or `new_class(...)` call. A class built by a
     call cannot be inspected, so the call itself is refused in `src`.
2. `ciso.connectors` never imports `ciso.write_adapters`.
3. `ciso.write_adapters` imports only itself, `ciso.common`, pydantic and the few
   standard-library modules in `ALLOWED_STDLIB`.

What a static scan still cannot see:

- names computed at run time: `getattr(module, "Write" + "Adapter")` as a base,
  `setattr(Cls, name, fn)` with a computed name, a namespace dict built elsewhere;
- methods attached through another name for the class (`K = Cls; K.apply = fn`), by a
  decorator, a metaclass, `__init_subclass__` or `__getattr__`;
- `type` or `new_class` reached through another name (`make = type`);
- classes made by a factory in a library (`dataclasses.make_dataclass` and the like) or by
  `exec`/`eval` (those two are refused by `test_import_boundaries.py`);
- an object that is not a class or module but carries the three callables, such as a
  namespace object or a dict of functions;
- a `Tool` in `ciso.execution` (`run`, `verify`, `rollback`) whose body writes to a real
  system. That needs no adapter at all. What stands in its way is the ban on network and
  process modules in `test_import_boundaries.py`, not this file.

Inheritance is matched by class name across `src`, so two classes with one name are
treated as one. That can over-report; it does not hide anything.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import ConfigDict, Field

from ciso.common.enums import AuthorityLevel
from ciso.common.schemas import Model
from ciso.write_adapters import (
    AdapterManifest,
    AdapterOperation,
    WriteRequest,
    WriteVerification,
)

pytestmark = pytest.mark.unit

SRC = Path(__file__).resolve().parents[2] / "src" / "ciso"
CONTRACT = "WriteAdapter"
CONTRACT_MODULE = "ciso.write_adapters.contract"
PACKAGE = "ciso.write_adapters"
ADAPTER_METHODS = frozenset({"apply", "verify", "rollback"})
ALLOWED_THIRD_PARTY = frozenset({"pydantic", "pydantic_core"})
#: Standard-library modules the contract package may import: what it imports today.
ALLOWED_STDLIB = frozenset({"__future__", "enum", "re", "typing"})
ALLOWED_INTERNAL = ("ciso.common", PACKAGE)


def _module_name(path: Path, root: Path = SRC) -> tuple[str, bool]:
    relative = path.resolve().relative_to(root.resolve().parent).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        return ".".join(parts[:-1]), True
    return ".".join(parts), False


def _under(name: str, package: str) -> bool:
    return name == package or name.startswith(package + ".")


def _import_bases(tree: ast.AST, module: str, is_package: bool) -> set[str]:
    """Absolute names of the modules a file imports from, relative imports resolved."""
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
            # `from ciso import write_adapters` names the package in the alias.
            found.update(f"{base}.{alias.name}" if base else alias.name for alias in node.names)
    return found


def _mentions(expr: ast.AST, names: set[str]) -> bool:
    """True if an expression names one of `names` as a name, attribute or string."""
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in names:
            return True
        if isinstance(node, ast.Attribute) and node.attr in names:
            return True
        if isinstance(node, ast.Constant) and node.value in names:
            return True
    return False


def _name_assignments(tree: ast.AST) -> list[tuple[str, ast.expr]]:
    found: list[tuple[str, ast.expr]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            found.extend((t.id, node.value) for t in node.targets if isinstance(t, ast.Name))
        elif (
            isinstance(node, ast.AnnAssign | ast.NamedExpr)
            and node.value is not None
            and isinstance(node.target, ast.Name)
        ):
            found.append((node.target.id, node.value))
    return found


def _contract_aliases(tree: ast.AST) -> set[str]:
    """Local names that refer to the contract class: `import ... as` and assignments."""
    names = {CONTRACT}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(a.asname or a.name for a in node.names if a.name == CONTRACT)
    assignments = _name_assignments(tree)
    grew = True
    while grew:
        grew = False
        for name, value in assignments:
            if name not in names and _mentions(value, names):
                names.add(name)
                grew = True
    return names


def _base_names(base: ast.expr) -> set[str]:
    """Every plain or attribute name inside a base-class expression."""
    found: set[str] = set()
    for node in ast.walk(base):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
    return found


@dataclass(frozen=True)
class _Class:
    module: str
    name: str
    bases: frozenset[str]
    methods: frozenset[str]
    named: bool


def _defined(body: list[ast.stmt]) -> set[str]:
    """Names a class body or module body binds with `def` or by assignment."""
    found: set[str] = set()
    for item in body:
        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
            found.add(item.name)
        elif isinstance(item, ast.Assign):
            found.update(t.id for t in item.targets if isinstance(t, ast.Name))
        elif (
            isinstance(item, ast.AnnAssign)
            and item.value is not None
            and isinstance(item.target, ast.Name)
        ):
            found.add(item.target.id)
    return found


def _owner_name(owner: ast.expr) -> str:
    """`Cls` for `Cls` and for `module.Cls`; empty for anything else."""
    if isinstance(owner, ast.Name):
        return owner.id
    return owner.attr if isinstance(owner, ast.Attribute) else ""


def _attached_later(tree: ast.AST) -> dict[str, set[str]]:
    """Class name -> names attached after the body: `Cls.apply = fn`, `setattr(Cls, ...)`."""
    found: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute):
                    found.setdefault(_owner_name(target.value), set()).add(target.attr)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            found.setdefault(_owner_name(node.args[0]), set()).add(node.args[1].value)
    return found


def _classes(tree: ast.AST, module: str) -> list[_Class]:
    aliases = _contract_aliases(tree)
    later = _attached_later(tree)
    found: list[_Class] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if module == CONTRACT_MODULE and node.name == CONTRACT:
            continue  # the protocol's own definition
        bases: set[str] = set()
        for base in node.bases:
            bases |= _base_names(base)
        methods = _defined(node.body) | later.get(node.name, set())
        found.append(
            _Class(module, node.name, frozenset(bases), frozenset(methods), bool(bases & aliases))
        )
    return found


def _built_at_run_time(tree: ast.AST, module: str) -> list[str]:
    """`type(name, bases, namespace)` and `new_class(...)` calls, under any receiver."""
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _owner_name(node.func)
        three_part_type = name == "type" and len(node.args) + len(node.keywords) >= 3
        if three_part_type or name == "new_class":
            found.append(f"{module}:{node.lineno} builds a class at run time with {name}()")
    return found


def _lineage(cls: _Class, by_name: dict[str, list[_Class]]) -> list[_Class]:
    """A class and every class in the file set it inherits from, matched by name."""
    seen: list[_Class] = []
    stack = [cls]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.append(current)
        for base in current.bases:
            stack.extend(by_name.get(base, []))
    return seen


def implementations_in(files: list[tuple[str, ast.AST]]) -> list[str]:
    """Everything in a set of parsed files that implements or subclasses the contract."""
    classes = [cls for module, tree in files for cls in _classes(tree, module)]
    by_name: dict[str, list[_Class]] = {}
    for cls in classes:
        by_name.setdefault(cls.name, []).append(cls)
    wanted = sorted(ADAPTER_METHODS)
    found: list[str] = []
    for cls in classes:
        family = _lineage(cls, by_name)
        gathered: set[str] = set()
        for member in family:
            gathered |= member.methods
        if any(member.named for member in family):
            found.append(f"{cls.module}.{cls.name} subclasses {CONTRACT}")
        elif cls.methods >= ADAPTER_METHODS:
            found.append(f"{cls.module}.{cls.name} defines {wanted}")
        elif gathered >= ADAPTER_METHODS:
            found.append(f"{cls.module}.{cls.name} gathers {wanted} from its bases")
    for module, tree in files:
        if isinstance(tree, ast.Module) and _defined(tree.body) >= ADAPTER_METHODS:
            found.append(f"{module} defines {wanted} at module level")
        found.extend(_built_at_run_time(tree, module))
    return found


def implementations(tree: ast.AST, module: str) -> list[str]:
    """The same check for one parsed file on its own."""
    return implementations_in([(module, tree)])


def disallowed_imports(tree: ast.AST, module: str, is_package: bool) -> list[str]:
    """Imports that `ciso.write_adapters` may not make."""
    bad: list[str] = []
    for name in sorted(_import_bases(tree, module, is_package)):
        top = name.split(".")[0]
        if top in ALLOWED_STDLIB or top in ALLOWED_THIRD_PARTY:
            continue
        if any(_under(name, allowed) for allowed in ALLOWED_INTERNAL):
            continue
        bad.append(name)
    return bad


def _parsed(root: Path) -> list[tuple[str, bool, ast.AST]]:
    out: list[tuple[str, bool, ast.AST]] = []
    for path in sorted(root.rglob("*.py")):
        module, is_package = _module_name(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        out.append((module, is_package, tree))
    return out


def test_no_class_in_src_implements_the_write_adapter_contract() -> None:
    files = _parsed(SRC)
    assert len(files) >= 8, "the source tree was not found"
    assert CONTRACT_MODULE in {module for module, _, _ in files}
    contract_seen = sum(
        1
        for module, _, tree in files
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == CONTRACT and module == CONTRACT_MODULE
    )
    violations = implementations_in([(module, tree) for module, _, tree in files])
    assert contract_seen == 1, "the WriteAdapter protocol itself was not found"
    assert not violations, "\n".join(violations)


def test_the_contract_declares_the_methods_the_scanner_looks_for() -> None:
    """If the protocol's methods are renamed, the structural rule must follow."""
    tree = ast.parse((SRC / "write_adapters" / "contract.py").read_text(encoding="utf-8"))
    declared = {
        item.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == CONTRACT
        for item in node.body
        if isinstance(item, ast.FunctionDef)
    }
    assert declared >= ADAPTER_METHODS | {"manifest"}


def test_connectors_never_import_write_adapters() -> None:
    connectors = SRC / "connectors"
    if not connectors.exists():
        pytest.skip("ciso.connectors is not built yet")
    files = _parsed(connectors)
    assert len(files) > 0, "ciso.connectors exists but holds no Python files"
    violations = [
        f"{module} imports {name}"
        for module, is_package, tree in files
        for name in sorted(_import_bases(tree, module, is_package))
        if _under(name, PACKAGE)
    ]
    assert not violations, "\n".join(violations)


def test_write_adapters_import_only_common_stdlib_and_pydantic() -> None:
    files = _parsed(SRC / "write_adapters")
    assert len(files) >= 2, "ciso.write_adapters was not found"
    assert all(_under(module, PACKAGE) for module, _, _ in files)
    violations = [
        f"{module} imports {name}"
        for module, is_package, tree in files
        for name in disallowed_imports(tree, module, is_package)
    ]
    assert not violations, "\n".join(violations)


class TestTheScannerItself:
    """Planted violations: each rule must see one when it is there."""

    @staticmethod
    def _tree(tmp_path: Path, source: str) -> ast.AST:
        sample = tmp_path / "planted.py"
        sample.write_text(source, encoding="utf-8")
        return ast.parse(sample.read_text(encoding="utf-8"))

    @pytest.mark.parametrize(
        "source",
        [
            "class Real(WriteAdapter):\n    pass\n",
            "from ciso.write_adapters import contract\nclass Real(contract.WriteAdapter): ...\n",
            "from ciso.write_adapters import WriteAdapter as W\nclass Real(W): ...\n",
            "class Real(Base, WriteAdapter[int]): ...\n",
            "def make():\n    class Hidden(WriteAdapter): ...\n    return Hidden\n",
        ],
    )
    def test_a_subclass_is_seen(self, tmp_path: Path, source: str) -> None:
        found = implementations(self._tree(tmp_path, source), "ciso.planted")
        assert len(found) == 1
        assert "subclasses WriteAdapter" in found[0]

    def test_a_structural_implementation_is_seen(self, tmp_path: Path) -> None:
        source = (
            "class Quiet:\n"
            "    def apply(self, request, credentials): ...\n"
            "    async def verify(self, request, credentials): ...\n"
            "    def rollback(self, request, receipt, credentials): ...\n"
        )
        found = implementations(self._tree(tmp_path, source), "ciso.planted")
        assert found == ["ciso.planted.Quiet defines ['apply', 'rollback', 'verify']"]

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            # The three methods split over two classes.
            (
                "class Half:\n    def apply(self, r, c): ...\n    def verify(self, r, c): ...\n"
                "class Real(Half):\n    def manifest(self): ...\n"
                "    def rollback(self, r, x, c): ...\n",
                "ciso.planted.Real gathers",
            ),
            # Methods bound by assignment in the class body, as names and as lambdas.
            (
                "def _a(s): ...\ndef _v(s): ...\ndef _r(s): ...\n"
                "class Real:\n    apply = _a\n    verify = _v\n    rollback = _r\n",
                "ciso.planted.Real defines",
            ),
            (
                "class Real:\n    apply = lambda s, r, c: None\n"
                "    verify = lambda s, r, c: None\n    rollback = lambda s, r, x, c: None\n",
                "ciso.planted.Real defines",
            ),
            (
                "class Real:\n    apply: object = _a\n    verify: object = _v\n"
                "    def rollback(self): ...\n",
                "ciso.planted.Real defines",
            ),
            # Methods attached after the class body.
            (
                "class Real:\n    def manifest(self): ...\n"
                "Real.apply = _a\nReal.verify = _v\nReal.rollback = _r\n",
                "ciso.planted.Real defines",
            ),
            (
                "class Real:\n    def apply(self): ...\n"
                "setattr(Real, 'verify', _v)\nsetattr(Real, 'rollback', _r)\n",
                "ciso.planted.Real defines",
            ),
            (
                "from ciso.x import other\n"
                "class Real:\n    def apply(self): ...\n    def verify(self): ...\n"
                "def late():\n    other.Real.rollback = _r\n",
                "ciso.planted.Real defines",
            ),
            # The base reached through an assigned name.
            (
                "from ciso.write_adapters import contract\nBase = contract.WriteAdapter\n"
                "class Real(Base): ...\n",
                "ciso.planted.Real subclasses",
            ),
            (
                "from ciso.write_adapters import *\nB = WriteAdapter\nC = B\nclass Real(C): ...\n",
                "ciso.planted.Real subclasses",
            ),
            (
                "from ciso.write_adapters import WriteAdapter as W\nB: type = W\n"
                "class Real(B): ...\n",
                "ciso.planted.Real subclasses",
            ),
            (
                "import ciso.write_adapters as w\nBase = getattr(w, 'WriteAdapter')\n"
                "class Real(Base): ...\n",
                "ciso.planted.Real subclasses",
            ),
            # A class below a subclass.
            (
                "class Mid(WriteAdapter): ...\nclass Real(Mid): ...\n",
                "ciso.planted.Real subclasses",
            ),
            # A class built by a call.
            (
                "Real = type('Real', (), {'apply': f, 'verify': f, 'rollback': f})\n",
                "ciso.planted:1 builds a class at run time with type()",
            ),
            ("Real = type('Real', (WriteAdapter,), {})\n", "with type()"),
            ("import builtins\nReal = builtins.type('Real', (), dict(ns))\n", "with type()"),
            ("Real = type('Real', (), ns, flag=True)\n", "with type()"),
            ("import types\nReal = types.new_class('Real', (WriteAdapter,))\n", "new_class()"),
            ("from types import new_class\nReal = new_class('Real')\n", "new_class()"),
            # A module that is itself the adapter.
            (
                "def apply(r, c): ...\nasync def verify(r, c): ...\nrollback = apply\n",
                "ciso.planted defines",
            ),
        ],
    )
    def test_an_implementation_assembled_in_pieces_is_seen(
        self, tmp_path: Path, source: str, expected: str
    ) -> None:
        found = implementations(self._tree(tmp_path, source), "ciso.planted")
        assert any(expected in line for line in found), found

    def test_methods_inherited_from_another_file_are_seen(self, tmp_path: Path) -> None:
        half = self._tree(
            tmp_path, "class Half:\n    def apply(self): ...\n    def verify(self): ...\n"
        )
        real = self._tree(
            tmp_path,
            "from ciso.x.half import Half\nclass Real(Half):\n    def rollback(self): ...\n",
        )
        found = implementations_in([("ciso.x.half", half), ("ciso.x.real", real)])
        assert found == ["ciso.x.real.Real gathers ['apply', 'rollback', 'verify'] from its bases"]

    def test_ordinary_classes_and_calls_are_not_reported(self, tmp_path: Path) -> None:
        source = (
            "class A:\n    def apply(self): ...\n    verify_after: bool = True\n"
            "class B(A):\n    def verify(self): ...\n    rollback: object\n"
            "class C:\n    def rollback(self): ...\n"
            "B.other = 1\nkind = type(exc)\nname = type(exc).__name__\n"
            "def apply(x): ...\ndef verify(x): ...\n"
        )
        assert implementations(self._tree(tmp_path, source), "ciso.planted") == []

    def test_two_of_three_methods_is_not_an_implementation(self, tmp_path: Path) -> None:
        source = "class Partial:\n    def verify(self): ...\n    def rollback(self): ...\n"
        assert implementations(self._tree(tmp_path, source), "ciso.planted") == []

    def test_only_the_real_protocol_definition_is_exempt(self, tmp_path: Path) -> None:
        source = (
            "class WriteAdapter(Protocol):\n"
            "    def apply(self): ...\n"
            "    def verify(self): ...\n"
            "    def rollback(self): ...\n"
        )
        tree = self._tree(tmp_path, source)
        assert implementations(tree, CONTRACT_MODULE) == []
        assert len(implementations(tree, "ciso.connectors.sneaky")) == 1

    @pytest.mark.parametrize(
        "source",
        [
            "import ciso.write_adapters\n",
            "from ciso.write_adapters.contract import WriteAdapter\n",
            "from ciso import write_adapters\n",
            "from ..write_adapters import contract\n",
        ],
    )
    def test_a_connector_import_of_write_adapters_is_seen(
        self, tmp_path: Path, source: str
    ) -> None:
        names = _import_bases(self._tree(tmp_path, source), "ciso.connectors.fixture", False)
        assert any(_under(name, PACKAGE) for name in names)

    @pytest.mark.parametrize(
        ("source", "bad"),
        [
            ("from ciso.policy.catalog import OperationSpec\n", "ciso.policy.catalog"),
            ("import ciso.execution\n", "ciso.execution"),
            ("from ..inference import gateway\n", "ciso.inference"),
            ("import sqlalchemy\n", "sqlalchemy"),
            ("from ciso import vault\n", "ciso.vault"),
            # The standard library is not allowed wholesale (review H3).
            ("import os\n", "os"),
            ("import sqlite3\n", "sqlite3"),
            ("import asyncio\n", "asyncio"),
            ("import multiprocessing\n", "multiprocessing"),
            ("import urllib\n", "urllib"),
            ("from urllib import request\n", "urllib.request"),
            ("import shutil\n", "shutil"),
            ("import pickle\n", "pickle"),
            ("import marshal\n", "marshal"),
            ("import pathlib\n", "pathlib"),
            ("import json\n", "json"),
        ],
    )
    def test_a_forbidden_import_in_write_adapters_is_seen(
        self, tmp_path: Path, source: str, bad: str
    ) -> None:
        tree = self._tree(tmp_path, source)
        assert bad in disallowed_imports(tree, CONTRACT_MODULE, False)

    def test_the_allowed_imports_pass(self, tmp_path: Path) -> None:
        source = (
            "from __future__ import annotations\n"
            "import re\n"
            "from typing import Protocol\n"
            "from pydantic import ConfigDict\n"
            "from ciso.common.schemas import Model\n"
            "from ciso.write_adapters.contract import WriteAdapter\n"
            "from . import contract\n"
        )
        tree = self._tree(tmp_path, source)
        assert disallowed_imports(tree, "ciso.write_adapters", True) == []


class _Args(Model):
    ticket: str = Field(max_length=64)


def _operation(name: str = "ticket.create", args: type[Model] = _Args) -> AdapterOperation:
    return AdapterOperation(
        name=name, authority_level=AuthorityLevel.L2_COORDINATE, args_model=args, reversible=True
    )


class TestTheContractModels:
    """The declarations an adapter makes are checked before any adapter exists."""

    def test_a_well_formed_manifest_is_accepted(self) -> None:
        manifest = AdapterManifest(
            adapter_id="ticketing",
            operations=(_operation(),),
            credential_refs=("secret://ticketing_write",),
        )
        found = manifest.operation("ticket.create")
        assert found is not None
        assert found.authority_level is AuthorityLevel.L2_COORDINATE
        assert manifest.operation("ticket.delete") is None

    @pytest.mark.parametrize("ref", ["hunter2", "https://vault.example.test/x", "secret://A-b"])
    def test_credentials_must_be_secret_references(self, ref: str) -> None:
        with pytest.raises(ValueError, match="secret://"):
            AdapterManifest(
                adapter_id="ticketing", operations=(_operation(),), credential_refs=(ref,)
            )

    def test_operations_are_declared_once_and_not_empty(self) -> None:
        for operations in ((), (_operation(), _operation())):
            with pytest.raises(ValueError, match="at least one operation"):
                AdapterManifest(adapter_id="ticketing", operations=operations, credential_refs=())

    @pytest.mark.parametrize("adapter_id", ["", "Ticketing", "a/b", "ticketing\n"])
    def test_adapter_ids_are_strict(self, adapter_id: str) -> None:
        with pytest.raises(ValueError, match="bad adapter id"):
            AdapterManifest(adapter_id=adapter_id, operations=(_operation(),), credential_refs=())

    @pytest.mark.parametrize("name", ["run", "Ticket.create", "ticket.create\n", "sh -c x"])
    def test_operation_names_are_dotted(self, name: str) -> None:
        with pytest.raises(ValueError, match="dotted"):
            _operation(name)
        with pytest.raises(ValueError, match="dotted"):
            WriteRequest(
                request_id="r1",
                idempotency_key="k1",
                operation=name,
                target_resource="asset:a1",
                arguments=_Args(ticket="t"),
            )

    def test_an_open_argument_schema_is_refused(self) -> None:
        class Loose(Model):
            model_config = ConfigDict(extra="allow")

        class Thawed(Model):
            model_config = ConfigDict(frozen=False)

        for model in (Loose, Thawed):
            with pytest.raises(ValueError, match="forbid extra fields"):
                _operation(args=model)

    def test_a_request_needs_a_plain_key_and_an_entity_ref_target(self) -> None:
        good = {
            "request_id": "r1",
            "idempotency_key": "k1",
            "operation": "ticket.create",
            "target_resource": "asset:a1",
            "arguments": _Args(ticket="t"),
        }
        assert WriteRequest(**good).idempotency_key == "k1"
        with pytest.raises(ValueError, match="idempotency"):
            WriteRequest(**{**good, "idempotency_key": "k 1; drop"})
        with pytest.raises(ValueError, match="entity ref"):
            WriteRequest(**{**good, "target_resource": "https://example.test/a"})

    def test_a_truthy_non_boolean_is_not_a_match(self) -> None:
        assert WriteVerification(matches=True).matches is True
        with pytest.raises(ValueError, match="matches"):
            WriteVerification(matches="yes")  # type: ignore[arg-type]
