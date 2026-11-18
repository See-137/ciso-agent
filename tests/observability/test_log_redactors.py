"""The redacting JSON handler with several redactors and with pre-redacted exception text
(NFR-012; M1 fix pass item 4)."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest

from ciso.observability import RedactingJsonHandler, configure_logging, remove_logging
from ciso.vault import RedactingLogFilter, SecretRedactor

pytestmark = pytest.mark.unit

FIRST = "first-container-secret-0001"
SECOND = "second-container-secret-0002"


def redactor_for(*values: str) -> SecretRedactor:
    redactor = SecretRedactor()
    for value in values:
        assert redactor.register(value) is True
    return redactor


def lines(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    before = (root.level, list(root.handlers))
    yield
    for handler in root.handlers:
        if handler not in before[1]:
            root.removeHandler(handler)
            handler.close()
    root.setLevel(before[0])


def test_configure_logging_returns_the_precise_handler_type() -> None:
    handler = configure_logging(redactor_for(FIRST), logging.INFO, stream=io.StringIO())
    assert type(handler) is RedactingJsonHandler
    assert configure_logging.__annotations__["return"] in ("RedactingJsonHandler",)


def test_a_second_call_adds_its_redactor_to_the_existing_handler() -> None:
    stream = io.StringIO()
    first, second = redactor_for(FIRST), redactor_for(SECOND)
    handler = configure_logging(first, logging.INFO, stream=stream)
    again = configure_logging(second, logging.INFO, stream=io.StringIO())
    assert again is handler
    assert handler.redactors == (first, second)
    logging.getLogger("ciso.test").warning("a=%s b=%s", FIRST, SECOND, extra={"x": SECOND})
    output = stream.getvalue()
    assert FIRST not in output
    assert SECOND not in output
    (record,) = lines(stream)
    assert record["message"] == "a=[REDACTED] b=[REDACTED]"
    assert record["x"] == "[REDACTED]"


def test_the_same_redactor_twice_is_held_once() -> None:
    first = redactor_for(FIRST)
    handler = configure_logging(first, logging.INFO, stream=io.StringIO())
    configure_logging(first, logging.INFO)
    assert handler.redactors == (first,)


def test_an_added_redactor_can_be_removed_but_the_base_one_cannot() -> None:
    first, second = redactor_for(FIRST), redactor_for(SECOND)
    handler = configure_logging(first, logging.INFO, stream=io.StringIO())
    handler.add_redactor(second)
    assert handler.remove_redactor(second) is True
    assert handler.remove_redactor(second) is False
    assert handler.remove_redactor(first) is False  # never left without a redactor
    assert handler.redactors == (first,)


def test_redacted_exception_text_from_a_filter_is_emitted() -> None:
    stream = io.StringIO()
    redactor = redactor_for(FIRST)
    handler = configure_logging(redactor, logging.INFO, stream=stream)
    handler.addFilter(RedactingLogFilter(redactor))
    try:
        raise RuntimeError(f"boom {FIRST}")
    except RuntimeError:
        logging.getLogger("ciso.test").exception("failed")
    (record,) = lines(stream)
    assert "RuntimeError: boom [REDACTED]" in record["exc_info"]
    assert "Traceback" in record["exc_info"]
    assert FIRST not in stream.getvalue()


def test_exception_text_without_exc_info_is_still_redacted_by_the_handler() -> None:
    stream = io.StringIO()
    handler = configure_logging(redactor_for(FIRST), logging.INFO, stream=stream)
    record = logging.LogRecord("ciso.test", logging.ERROR, "f", 1, "failed", None, None)
    record.exc_text = f"Traceback ...\nRuntimeError: {FIRST}"
    handler.handle(record)
    (line,) = lines(stream)
    assert line["exc_info"] == "Traceback ...\nRuntimeError: [REDACTED]"


def test_remove_logging_still_detaches() -> None:
    handler = configure_logging(redactor_for(FIRST), logging.INFO, stream=io.StringIO())
    remove_logging(handler)
    assert handler not in logging.getLogger().handlers
