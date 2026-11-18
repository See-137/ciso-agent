"""Masked secret values and the environment-backed secret store.

Blueprint 11.1: store secret references and metadata only, never raw credentials. Blueprint
13.4: secrets are redacted from logs and model contexts. A caller holds a `secret://<name>`
reference and resolves it at the last moment; what comes back is a `SecretValue` that will
not print, serialise, pickle or compare against a plain string.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar, Final, NoReturn, Protocol, final

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

from ciso.common.clock import Clock, ensure_utc
from ciso.common.errors import FailClosed, NotFound, ValidationFailed

logger = logging.getLogger(__name__)

#: Environment variable prefix for the development provider: `secret://db_password` is read
#: from `CISO_SECRET_DB_PASSWORD`.
ENV_PREFIX: Final = "CISO_SECRET_"
SECRET_SCHEME: Final = "secret://"  # noqa: S105 - a URI scheme, not a credential
_NAME = re.compile(r"[a-z0-9_]+")


def _refuse_serialisation(_value: Any) -> NoReturn:
    raise TypeError("SecretValue is not serialisable; store its secret:// reference instead")


@final
class SecretValue:
    """A secret string that hides itself.

    `repr`, `str` and `format` show `MASK`. `json.dumps`, `pickle` and Pydantic dumps raise.
    `copy`/`deepcopy` return another `SecretValue`. `==` is true only against another
    `SecretValue` holding the same value and compares in constant time; comparing with a
    plain string is always false. Instances are unhashable, so they cannot be dict keys.

    `expires_at` is optional. An expiring secret needs the injected `clock`; once
    `clock.now() >= expires_at`, `reveal()` raises `FailClosed`.
    """

    MASK: ClassVar[str] = "**********"
    __slots__ = ("_clock", "_expires_at", "_value")
    __hash__ = None  # type: ignore[assignment]

    def __init__(
        self, value: str, *, expires_at: datetime | None = None, clock: Clock | None = None
    ) -> None:
        if not isinstance(value, str):
            raise ValidationFailed("a secret value must be a string")
        if not value.strip():
            raise ValidationFailed("a secret value must not be empty")
        if expires_at is not None:
            if clock is None:
                raise ValidationFailed("an expiring secret needs a clock")
            try:
                expires_at = ensure_utc(expires_at)
            except ValueError:
                raise ValidationFailed("expires_at must be timezone-aware") from None
        self._value = value
        self._expires_at = expires_at
        self._clock = clock

    @property
    def expires_at(self) -> datetime | None:
        return self._expires_at

    def reveal(self) -> str:
        """The secret itself. Call at the last possible moment; never log the result."""
        expires_at = self._expires_at
        if expires_at is not None and (self._clock is None or self._clock.now() >= expires_at):
            raise FailClosed("secret has expired")
        return self._value

    def __repr__(self) -> str:
        return f"SecretValue('{self.MASK}')"

    def __str__(self) -> str:
        return self.MASK

    def __format__(self, format_spec: str) -> str:
        return format(self.MASK, format_spec)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretValue):
            return NotImplemented
        return hmac.compare_digest(self._value.encode("utf-8"), other._value.encode("utf-8"))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __copy__(self) -> SecretValue:
        return SecretValue(self._value, expires_at=self._expires_at, clock=self._clock)

    def __deepcopy__(self, memo: dict[int, Any]) -> SecretValue:
        return self.__copy__()

    def __reduce_ex__(self, protocol: Any) -> NoReturn:
        raise TypeError("SecretValue cannot be pickled")

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretValue cannot be pickled")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Pydantic accepts only a `SecretValue` instance and refuses to dump it."""
        return core_schema.is_instance_schema(
            cls,
            serialization=core_schema.plain_serializer_function_ser_schema(_refuse_serialisation),
        )


class SecretRegistry(Protocol):
    def register(self, value: str) -> bool: ...


def parse_ref(ref: str) -> str:
    """Return the name in `secret://<name>`. Raises `ValidationFailed` without echoing input.

    Names are lower-case letters, digits and underscores only.
    """
    if not isinstance(ref, str):
        raise ValidationFailed("a secret reference must be a string")
    if not ref.startswith(SECRET_SCHEME):
        if "://" in ref:
            raise ValidationFailed("unsupported secret reference scheme; expected secret://")
        raise ValidationFailed("a secret reference must start with secret://")
    name = ref[len(SECRET_SCHEME) :]
    if not _NAME.fullmatch(name):
        raise ValidationFailed("a secret name may contain only a-z, 0-9 and _")
    return name


class EnvSecretStore:
    """Development secret provider that reads `CISO_SECRET_<NAME>` from an environment mapping.

    `get("secret://db_password")` reads exactly `CISO_SECRET_DB_PASSWORD`; there is no
    fallback to any other variable. An unknown name, or a value that is empty or only
    whitespace, raises `NotFound`; the store never returns an empty value. A malformed
    reference raises `ValidationFailed`. If a `redactor` is given, every resolved value is
    registered with it so later log lines and audit details are scrubbed. Values shorter
    than the redactor's floor cannot be registered; a warning naming the reference (never
    the value) is logged. Nothing is written to disk.
    """

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        redactor: SecretRegistry | None = None,
    ) -> None:
        self._environ: Mapping[str, str] = os.environ if environ is None else environ
        self._redactor = redactor

    def get(self, ref: str) -> SecretValue:
        name = parse_ref(ref)
        raw = self._environ.get(ENV_PREFIX + name.upper())
        if raw is None:
            raise NotFound(f"secret not found: secret://{name}")
        if not raw.strip():
            raise NotFound(f"secret is empty: secret://{name}")
        if self._redactor is not None and not self._redactor.register(raw):
            logger.warning(
                "secret://%s is too short to be redacted from text; avoid logging near it",
                name,
            )
        return SecretValue(raw)
