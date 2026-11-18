"""The credential accessor a tool is handed (plan gap G20; blueprint 9.5 least privilege).

A tool declares `secret://<name>` references at registration. The registry hands it a
`ScopedCredentials` that resolves those references and no others.

What this does and does not stop: the handed object has no instance attributes at all
(`__slots__ = ()`, no `__dict__`), so the real accessor and the allowed set cannot be
read or replaced through any attribute of it; they live in the closure of its `get`.
Code running in the same Python process can still read closure cells
(`get.__func__.__closure__`) or walk the garbage collector. This wrapper prevents
accidents and plain attribute access; it is not a security boundary against hostile
in-process code. Process isolation (ADR-0010) is the real boundary.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from ciso.common.errors import AuthorizationError
from ciso.common.protocols import RevealableSecret


@runtime_checkable
class CredentialAccessor(Protocol):
    def get(self, ref: str) -> RevealableSecret:
        """Resolve `secret://<name>` or raise. The broker passes an accessor that checks
        the kill switch first (plan gap G20)."""
        ...


class ScopedCredentials:
    """Lets a tool resolve only the references it declared at registration.

    `ScopedCredentials(inner, allowed)` returns an object whose only behaviour is `get`.
    It keeps nothing in attributes: see the module docstring for the limits.
    """

    __slots__ = ()

    def __new__(cls, inner: CredentialAccessor, allowed: Iterable[str]) -> ScopedCredentials:
        permitted = frozenset(allowed)

        class _Scoped(ScopedCredentials):
            __slots__ = ()

            def get(self, ref: str) -> RevealableSecret:
                if ref not in permitted:
                    raise AuthorizationError("the tool did not declare this credential reference")
                return inner.get(ref)

        _Scoped.__name__ = _Scoped.__qualname__ = "ScopedCredentials"
        return object.__new__(_Scoped)

    def __init__(self, inner: CredentialAccessor, allowed: Iterable[str]) -> None:
        """Nothing is stored: both arguments are held only by the closure of `get`."""

    def get(self, ref: str) -> RevealableSecret:
        raise AuthorizationError("the tool did not declare this credential reference")

    def __repr__(self) -> str:
        return "ScopedCredentials()"
