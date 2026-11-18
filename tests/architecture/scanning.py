"""Static source scanning shared by the architecture tests.

The rules in `test_import_boundaries.py` are written against dotted names
(`os.system`, `ciso.inference.gateway`). This module turns a source file into the dotted
names it refers to, however they are spelled:

- `import x`, `import x as y`, `from x import y as z`, relative imports (resolved);
- a use through a local alias: `import os as o` then `o.system` is `os.system`, and
  `from os import popen as p` then `p(...)` is `os.popen`;
- an alias made by plain assignment: `run = os.system`, `a, b = os, sys`;
- `getattr(os, "system")` is `os.system`; `getattr(os, anything_else)`, `vars(os)` and
  `os.__dict__` are reported as `os.<dynamic>`; `from os import *` as `os.*`. A wildcard
  name matches every rule that bans something inside that module (see `hits`).

What this cannot see (it reads text, it does not run it):

- a module that arrives as a function argument, a return value, a container element or an
  attribute of an object (`self.mod.system`): only names bound by an import or by a plain
  assignment from such a name are followed. `attribute_names` exists so a rule can still
  ban a distinctive attribute on any receiver;
- names built from strings at run time and then passed to `eval`, `exec`, `__import__`,
  `importlib` or `sys.modules` (the rules ban those entry points instead);
- scope: bindings are collected per file, not per function, so a rule can over-report
  when one name means two things in one file. It never under-reports for that reason.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

#: Last component of a name whose real last component cannot be read from the source.
DYNAMIC = "<dynamic>"
_WILD = ("*", DYNAMIC)


@dataclass(frozen=True)
class Source:
    """One parsed file: its dotted module name and its syntax tree."""

    module: str
    is_package: bool
    tree: ast.Module


@dataclass(frozen=True)
class Ref:
    """A dotted name a file refers to, and the line it does so on."""

    name: str
    line: int


def under(name: str, package: str) -> bool:
    return name == package or name.startswith(package + ".")


def parse(text: str, module: str, is_package: bool = False) -> Source:
    return Source(module, is_package, ast.parse(text, filename=module))


def load(root: Path) -> tuple[Source, ...]:
    """Every Python file under `root`, named relative to the directory above it."""
    found: list[Source] = []
    for path in sorted(root.rglob("*.py")):
        parts = list(path.relative_to(root.parent).with_suffix("").parts)
        is_package = parts[-1] == "__init__"
        if is_package:
            parts = parts[:-1]
        found.append(parse(path.read_text(encoding="utf-8"), ".".join(parts), is_package))
    return tuple(found)


def plant(base: Path, files: dict[str, str]) -> tuple[Source, ...]:
    """Write a small `ciso` package tree under `base` and load it, for planted violations.

    Keys are paths relative to `base`, for example `ciso/execution/x.py`.
    """
    for relative, text in files.items():
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return load(base / "ciso")


def _from_base(node: ast.ImportFrom, source: Source) -> str:
    if node.level == 0:
        return node.module or ""
    parts = source.module.split(".")
    package = parts if source.is_package else parts[:-1]
    anchor = package[: max(len(package) - (node.level - 1), 0)]
    return ".".join([*anchor, node.module] if node.module else anchor)


def imports(source: Source) -> list[Ref]:
    """Absolute dotted names a file imports. `from a import b` gives `a` and `a.b`."""
    found: list[Ref] = []
    for node in ast.walk(source.tree):
        if isinstance(node, ast.Import):
            found.extend(Ref(alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _from_base(node, source)
            if base:
                found.append(Ref(base, node.lineno))
            found.extend(
                Ref(f"{base}.{alias.name}" if base else alias.name, node.lineno)
                for alias in node.names
            )
    return found


def top_package_bindings(source: Source, top: str) -> list[Ref]:
    """Imports that bind the bare name of the top package, or hide what they take from it.

    `import ciso`, `import ciso as c` and `import ciso.common` (no `as`) all leave a name
    bound to the top package, from which any loaded sub-package is one attribute away.
    `from ciso... import *` hides its targets altogether.
    """
    found: list[Ref] = []
    for node in ast.walk(source.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == top or (under(alias.name, top) and alias.asname is None):
                    found.append(Ref(f"import {alias.name}", node.lineno))
        elif isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            base = _from_base(node, source)
            if under(base, top):
                found.append(Ref(f"from {base} import *", node.lineno))
    return found


def _assignments(tree: ast.Module) -> list[tuple[str, ast.expr]]:
    pairs: list[tuple[ast.expr, ast.expr]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            pairs.extend((target, node.value) for target in node.targets)
        elif isinstance(node, ast.AnnAssign | ast.NamedExpr) and node.value is not None:
            pairs.append((node.target, node.value))
    found: list[tuple[str, ast.expr]] = []
    for target, value in pairs:
        if isinstance(target, ast.Name):
            found.append((target.id, value))
        elif (
            isinstance(target, ast.Tuple | ast.List)
            and isinstance(value, ast.Tuple | ast.List)
            and len(target.elts) == len(value.elts)
        ):
            found.extend(
                (name.id, item)
                for name, item in zip(target.elts, value.elts, strict=True)
                if isinstance(name, ast.Name)
            )
    return found


def _resolve(expr: ast.expr, bound: dict[str, str], strict: bool) -> str | None:
    """Dotted name of a name, attribute chain or `getattr` call, aliases followed.

    With `strict`, the chain must start at a bound name; otherwise None.
    """
    parts: list[str] = []
    while True:
        if isinstance(expr, ast.Attribute):
            parts.append(DYNAMIC if expr.attr == "__dict__" else expr.attr)
            expr = expr.value
        elif isinstance(expr, ast.Subscript):
            expr = expr.value  # `vars(os)["system"]`, `os.__dict__["system"]`
        elif (call := _call_to(expr, bound, "getattr")) is not None and len(call.args) >= 2:
            name = call.args[1]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                parts.append(name.value)
            else:
                parts.append(DYNAMIC)
            expr = call.args[0]
        elif (call := _call_to(expr, bound, "vars")) is not None and len(call.args) == 1:
            parts.append(DYNAMIC)
            expr = call.args[0]
        else:
            break
    if not isinstance(expr, ast.Name):
        return None
    head = bound.get(expr.id)
    if head is None:
        if strict:
            return None
        head = expr.id
    names = [head, *reversed(parts)]
    if DYNAMIC in names:
        names = names[: names.index(DYNAMIC) + 1]
    return ".".join(names)


def _call_to(expr: ast.expr, bound: dict[str, str], builtin: str) -> ast.Call | None:
    """The call node if `expr` calls the named builtin (plain, aliased or as an attribute)."""
    if not isinstance(expr, ast.Call):
        return None
    func = expr.func
    if isinstance(func, ast.Name):
        named = bound.get(func.id, func.id) in {builtin, f"builtins.{builtin}"}
    else:
        named = isinstance(func, ast.Attribute) and func.attr == builtin
    return expr if named else None


def bindings(source: Source) -> dict[str, str]:
    """Local name -> the dotted name it stands for, from imports and plain assignments."""
    bound: dict[str, str] = {}
    for node in ast.walk(source.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bound[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    bound[head] = head
        elif isinstance(node, ast.ImportFrom):
            base = _from_base(node, source)
            for alias in node.names:
                if alias.name != "*":
                    bound[alias.asname or alias.name] = (
                        f"{base}.{alias.name}" if base else alias.name
                    )
    assignments = _assignments(source.tree)
    changed = True
    while changed:
        changed = False
        for name, value in assignments:
            if name in bound:
                continue
            resolved = _resolve(value, bound, strict=True)
            if resolved is not None:
                bound[name] = resolved
                changed = True
    return bound


def references(source: Source) -> list[Ref]:
    """Every dotted name a file imports or uses through a bound name.

    A bound name read on its own adds nothing: the import or the assignment that bound it
    is already in the list under the same dotted name.
    """
    bound = bindings(source)
    found = imports(source)
    for node in ast.walk(source.tree):
        if isinstance(node, ast.Attribute | ast.Call | ast.Subscript):
            resolved = _resolve(node, bound, strict=True)
            if resolved is not None:
                found.append(Ref(resolved, node.lineno))
    return found


def bare_names(source: Source) -> list[Ref]:
    """Names read without being imported or assigned from an import: builtins, locals."""
    bound = bindings(source)
    return [
        Ref(node.id, node.lineno)
        for node in ast.walk(source.tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in bound
    ]


def attribute_names(source: Source) -> list[Ref]:
    """Every attribute name read on any receiver, plus literal `getattr(x, "name")`."""
    found: list[Ref] = []
    for node in ast.walk(source.tree):
        if isinstance(node, ast.Attribute):
            found.append(Ref(node.attr, node.lineno))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            found.append(Ref(node.args[1].value, node.lineno))
    return found


def hits(name: str, patterns: frozenset[str]) -> str | None:
    """The pattern a dotted name falls under, or None.

    A pattern is a dotted name, optionally with `*` in it (`os.exec*`). It matches the
    name itself and anything below it. A wildcard name (`os.*`, `os.<dynamic>`) matches
    every pattern that lies inside its module, because it could be any of them.
    """
    parts = name.split(".")
    if parts[-1] in _WILD:
        base = ".".join(parts[:-1])
        for pattern in sorted(patterns):
            if under(pattern, base) or under(base, pattern.split("*")[0].rstrip(".")):
                return pattern
        return None
    prefixes = [".".join(parts[: count + 1]) for count in range(len(parts))]
    for pattern in sorted(patterns):
        if any(fnmatchcase(prefix, pattern) for prefix in prefixes):
            return pattern
    return None
