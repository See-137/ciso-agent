"""Test doubles and scanners shared by the inference tests.

Kept out of conftest.py so that fixtures and tests import the same class objects (the
gateway matches provider classes exactly).
"""

from __future__ import annotations

import ast
import threading
import time
from collections.abc import Callable
from typing import Any

from tests.fakes.core import FakeAudit

from ciso.common.errors import FailClosed
from ciso.common.protocols import AuditEvent, AuditReceipt
from ciso.common.schemas import sha256_hex
from ciso.inference import EndpointKind, LocalProvider, ProviderRequest, ProviderResponse
from ciso.inference.stub import STUB_DESCRIPTOR

MARKER = "DISTINCTIVE-PROMPT-MARKER-7731"
OUTPUT_MARKER = "DISTINCTIVE-OUTPUT-MARKER-5512"


class SpyProvider(LocalProvider):
    """Configurable provider that records every call. Registered by the conftest fixture."""

    name = "spy"
    endpoint_kind = EndpointKind.IN_PROCESS
    model_id = "stub-local"
    model_version = "1"

    def __init__(
        self,
        text: str = '{"ok": true}',
        *,
        raises: Exception | None = None,
        echo_prompt_in_error: bool = False,
        elapsed: float = 0.1,
        confidence: float | None = 0.9,
        gate: threading.Event | None = None,
        gate_first_call_only: bool = False,
        raw: Any = None,
        model_id: str | None = None,
    ) -> None:
        if model_id is not None:
            self.model_id = model_id
        self.calls: list[ProviderRequest] = []
        self._text = text
        self._raises = raises
        self._echo = echo_prompt_in_error
        self._elapsed = elapsed
        self._confidence = confidence
        self._gate = gate
        self._first_only = gate_first_call_only
        self._raw = raw

    def artifact_sha256(self) -> str:
        return sha256_hex(STUB_DESCRIPTOR)

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        self.calls.append(request)
        if self._gate is not None and (not self._first_only or len(self.calls) == 1):
            self._gate.wait(10.0)
        if self._echo:
            raise RuntimeError(f"provider failed on: {request.prompt}")
        if self._raises is not None:
            raise self._raises
        if self._raw is not None:
            return self._raw  # type: ignore[no-any-return]
        return ProviderResponse(
            text=self._text,
            input_tokens=11,
            output_tokens=7,
            elapsed_seconds=self._elapsed,
            confidence=self._confidence,
        )


class RogueProvider(SpyProvider):
    """A LocalProvider subclass that is never registered."""


class RemoteProvider(SpyProvider):
    """Registered by the fixture, but declares an endpoint the gateway must refuse."""

    endpoint_kind = EndpointKind.REMOTE


class FlippingProvider(SpyProvider):
    """Reports a different model version on every read after the first."""

    def __init__(self) -> None:
        super().__init__()
        self.reads = 0

    @property  # type: ignore[override]
    def model_version(self) -> str:
        self.reads += 1
        return "1" if self.reads == 1 else "2"


class Impostor:
    """Looks like a provider structurally; is not a LocalProvider."""

    name = "impostor"
    model_id = "stub-local"
    model_version = "1"
    endpoint = "https://api.example.invalid"

    def complete(self, request: ProviderRequest) -> ProviderResponse:  # pragma: no cover
        raise AssertionError("must never be called")


class StepClock:
    """Monotonic source that advances `step` on every read."""

    def __init__(self, step: float) -> None:
        self._now = 0.0
        self._step = step

    def __call__(self) -> float:
        value = self._now
        self._now += self._step
        return value


class FlakyAudit(FakeAudit):
    """Fails on the n-th append (1-based) and records the rest."""

    def __init__(self, fail_on: int) -> None:
        super().__init__()
        self._fail_on = fail_on
        self._count = 0

    def append(self, event: AuditEvent) -> AuditReceipt:
        self._count += 1
        if self._count == self._fail_on:
            raise FailClosed("audit path unavailable")
        return super().append(event)


def wait_until(predicate: Callable[[], bool], seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


FORBIDDEN_WORDS = (
    "external",
    "fallback",
    "secondary",
    "backup",
    "failover",
    "alternate",
    "retry",
    "providers",
)

ALLOWED_SELF_ATTRS = frozenset(
    {
        "_provider",
        "_provider_name",
        "_model_id",
        "_model_version",
        "_redactor",
        "_audit",
        "_clock",
        "_engine",
        "_manifest",
        "_timeout",
        "_max_abandoned",
        "_secrets",
        "_digest_key_ref",
        "_monotonic",
        "_lock",
        "_outstanding",
    }
)


def _docstring_ids(tree: ast.AST) -> set[int]:
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                found.add(id(body[0].value))
    return found


def scan_gateway_source(source: str) -> list[str]:
    """Findings that suggest a second route in gateway source. Empty means clean.

    Looks at identifiers and string literals (never docstrings or comments), at the
    attributes `InferenceGateway.__init__` assigns, and at its parameter list.
    """
    tree = ast.parse(source)
    skip = _docstring_ids(tree)
    findings: list[str] = []

    def check(word: str) -> None:
        lowered = word.lower()
        findings.extend(f"word {w!r} in {word!r}" for w in FORBIDDEN_WORDS if w in lowered)

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in skip:
                check(node.value)
        elif isinstance(node, ast.Name):
            check(node.id)
        elif isinstance(node, ast.Attribute):
            check(node.attr)
        elif isinstance(node, ast.arg):
            check(node.arg)
        elif isinstance(node, ast.alias):
            check(node.name)
        elif isinstance(node, ast.ImportFrom):
            check(node.module or "")
        elif isinstance(node, ast.FunctionDef | ast.ClassDef):
            check(node.name)

    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        if cls.name != "InferenceGateway":
            continue
        inits = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"]
        for init in inits:
            if init.args.vararg is not None or init.args.kwarg is not None:
                findings.append("__init__ takes *args or **kwargs")
            typed = [
                a.arg
                for a in init.args.args + init.args.kwonlyargs
                if a.annotation is not None and "Provider" in ast.unparse(a.annotation)
            ]
            if typed != ["provider"]:
                findings.append(f"provider-typed parameters: {typed}")
            for sub in ast.walk(init):
                if (
                    isinstance(sub, ast.Attribute)
                    and isinstance(sub.value, ast.Name)
                    and sub.value.id == "self"
                    and isinstance(sub.ctx, ast.Store)
                    and sub.attr not in ALLOWED_SELF_ATTRS
                ):
                    findings.append(f"unexpected attribute self.{sub.attr}")
    return findings
