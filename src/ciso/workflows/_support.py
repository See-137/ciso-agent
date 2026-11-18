"""Small helpers for the queue: input checks, knob checks and database error mapping."""

from __future__ import annotations

import functools
import math
from collections.abc import Callable

from sqlalchemy.exc import SQLAlchemyError

from ciso.common.errors import FailClosed, ValidationFailed


def check_text(name: str, value: object, max_len: int) -> str:
    """A non-empty string that fits its column."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{name} must be a non-empty string")
    if len(value) > max_len:
        raise ValidationFailed(f"{name} is longer than {max_len} characters")
    return value


def check_seconds(name: str, value: float | None) -> None:
    """A knob in seconds: finite, positive, a real number (not a bool). `None` is allowed."""
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValidationFailed(f"{name} must be a number or None")
    if not math.isfinite(value) or value <= 0:
        raise ValidationFailed(f"{name} must be finite and positive, or None to refuse")


def check_count(name: str, value: int | None) -> None:
    """A knob that counts things: an integer of at least 1. `None` is allowed."""
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationFailed(f"{name} must be an integer or None")
    if value < 1:
        raise ValidationFailed(f"{name} must be at least 1, or None to refuse")


def closed_on_db_error[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    """Turn a driver or database failure into `FailClosed`, as the audit log does."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as exc:
            raise FailClosed(f"queue database unavailable: {type(exc).__name__}") from exc

    return wrapper


def describe_error(error: BaseException, limit: int) -> str:
    """Error type plus a short message. Never the payload."""
    return f"{type(error).__name__}: {error}"[:limit]
