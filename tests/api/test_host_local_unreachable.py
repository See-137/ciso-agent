"""Host-local bootstrap and token recovery are never reachable from the API (ADR-0004, F2).

Two independent checks: the source of every module in `ciso.api` never names the
host-local service, and no endpoint the built app serves refers to it in its code.
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import Iterator
from pathlib import Path
from types import CodeType

import pytest
from fastapi.routing import APIRoute
from tests.api.helpers import Api

pytestmark = pytest.mark.unit

API_SRC = Path(__file__).resolve().parents[2] / "src" / "ciso" / "api"
FORBIDDEN = frozenset(
    {"HostLocalAdmin", "host_local", "bootstrap_first_admin", "recover_admin_token", "hostlocal"}
)


def _names(tree: ast.AST) -> Iterator[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, ast.alias):
            yield from node.name.split(".")
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield from node.module.split(".")


def _code_names(code: CodeType) -> Iterator[str]:
    yield from code.co_names
    for const in code.co_consts:
        if isinstance(const, CodeType):
            yield from _code_names(const)


def test_no_api_module_names_the_host_local_service() -> None:
    files = sorted(API_SRC.rglob("*.py"))
    assert len(files) >= 5, "API sources not found"
    hits = {
        f"{path.relative_to(API_SRC)}: {name}"
        for path in files
        for name in _names(ast.parse(path.read_text(encoding="utf-8")))
        if name in FORBIDDEN
    }
    assert hits == set()


def test_no_served_endpoint_refers_to_the_host_local_service(api: Api) -> None:
    routes = [r for r in api.app.routes if isinstance(r, APIRoute)]
    assert len(routes) >= 8, "no routes inspected"
    hits: set[str] = set()
    for route in routes:
        endpoint = inspect.unwrap(route.endpoint)
        names = set(_code_names(endpoint.__code__))
        names |= set(endpoint.__code__.co_freevars)
        hits |= {f"{route.path}: {n}" for n in names & FORBIDDEN}
    assert hits == set()
    # The container does hold it, so the absence above is a property of the routes.
    assert api.container.host_local is not None
