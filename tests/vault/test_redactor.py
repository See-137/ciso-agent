"""SecretRedactor and RedactingLogFilter (blueprint 11.1, 13.4; FR-031; NFR-007)."""

from __future__ import annotations

import io
import logging
import sys
import threading
from collections.abc import Iterator

import pytest

from ciso.common.errors import ValidationFailed
from ciso.common.protocols import Redactor
from ciso.vault import (
    MIN_REGISTERED_LENGTH,
    REDACTION_MARKER,
    RedactingLogFilter,
    SecretRedactor,
)

pytestmark = pytest.mark.privacy

# Test-only values. Nothing here is a real credential; shapes are assembled at run time.
SECRET = "unit-test-value-0001-not-real"
SECRET_2 = "another-test-value-0002"
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJ0ZXN0In0" + "." + "c2lnbmF0dXJlLXRlc3Q"
OPAQUE = "abcDEF123ghiJKL456mno"
PEM_BODY = "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8\nAgEAAkEAtestonlytestonly=="
PEM = "-----BEGIN PRIVATE KEY-----\n" + PEM_BODY + "\n-----END PRIVATE KEY-----"
PEM_TYPED = "-----BEGIN XYZ PRIVATE KEY-----\n" + PEM_BODY + "\n-----END XYZ PRIVATE KEY-----"
M = REDACTION_MARKER


@pytest.fixture
def red() -> SecretRedactor:
    r = SecretRedactor()
    assert r.register(SECRET) is True
    return r


def test_marker_and_floor_constants() -> None:
    assert M == "[REDACTED]"
    assert MIN_REGISTERED_LENGTH == 8
    assert SecretRedactor().marker == M


def test_satisfies_redactor_protocol() -> None:
    assert isinstance(SecretRedactor(), Redactor)


# --- registered values ---------------------------------------------------------------


def test_registered_value_removed(red: SecretRedactor) -> None:
    out = red.redact(f"connecting with {SECRET} now; again {SECRET}.")
    assert SECRET not in out
    assert out == f"connecting with {M} now; again {M}."


def test_unregistered_text_untouched(red: SecretRedactor) -> None:
    text = "nothing sensitive here, value-0001 is only part of it"
    assert red.redact(text) == text


def test_short_values_are_refused() -> None:
    r = SecretRedactor()
    assert r.register("abc") is False
    assert r.register("x" * (MIN_REGISTERED_LENGTH - 1)) is False
    assert r.register("        ") is False
    assert r.register("") is False
    assert r.redact("abc in abcdef") == "abc in abcdef"
    assert r.register("y" * MIN_REGISTERED_LENGTH) is True
    assert r.redact("y" * MIN_REGISTERED_LENGTH) == M


def test_short_value_refusal_is_documented() -> None:
    doc = SecretRedactor.register.__doc__ or ""
    assert str(MIN_REGISTERED_LENGTH) in doc or "MIN_REGISTERED_LENGTH" in doc


def test_marker_and_marker_fragments_are_refused() -> None:
    r = SecretRedactor()
    assert r.register(M) is False
    assert r.register("REDACTED") is False
    assert r.register("D]tail-of-something") is False
    assert r.register("something-before[RED") is False
    assert r.register(f"wrap{M}wrap") is False
    assert r.redact(f"a {M} b") == f"a {M} b"


def test_register_rejects_non_string() -> None:
    with pytest.raises(ValidationFailed):
        SecretRedactor().register(12345678)  # type: ignore[arg-type]


def test_overlapping_registered_values_fully_removed() -> None:
    r = SecretRedactor()
    long_value = "AAAABBBBCCCC"
    overlapping = "XXAAAABB"
    assert r.register(overlapping)
    assert r.register(long_value)
    out = r.redact("pre XXAAAABBBBCCCC post")
    assert out == f"pre {M} post"
    for fragment in ("XX", "AAAA", "BBBB", "CCCC"):
        assert fragment not in out


def test_nested_registered_values_longest_wins() -> None:
    r = SecretRedactor()
    assert r.register("inner-value")
    assert r.register("outer-inner-value-outer")
    assert r.redact("x outer-inner-value-outer y") == f"x {M} y"


def test_redact_rejects_non_string() -> None:
    with pytest.raises(ValidationFailed):
        SecretRedactor().redact(b"bytes")  # type: ignore[arg-type]


# --- token shapes --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        (f"Authorization: Bearer {OPAQUE}", OPAQUE),
        (f"header bearer {OPAQUE} sent", OPAQUE),
        (f"Authorization: Basic {OPAQUE}", OPAQUE),
        (f'{{"Authorization": "Token {OPAQUE}"}}', OPAQUE),
        (f"jwt is {JWT} ok", JWT),
        (f"key:\n{PEM}\nend", "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8"),
        (f"key:\n{PEM_TYPED}\nend", "AgEAAkEAtestonlytestonly"),
        (f"api_key={OPAQUE}", OPAQUE),
        (f"API-KEY = {OPAQUE}", OPAQUE),
        (f"apikey: {OPAQUE}", OPAQUE),
        (f"password={OPAQUE}&user=bob", OPAQUE),
        (f"passwd: '{OPAQUE}'", OPAQUE),
        (f"secret={OPAQUE}", OPAQUE),
        (f"token={OPAQUE}", OPAQUE),
        (f"client_secret={OPAQUE}", OPAQUE),
        (f"db_password={OPAQUE}", OPAQUE),
        (f"access_token={OPAQUE}", OPAQUE),
        (f'{{"api_key": "{OPAQUE}"}}', OPAQUE),
        (f'{{"client_secret":"{OPAQUE}", "n": 1}}', OPAQUE),
        (f"{{'password': '{OPAQUE}'}}", OPAQUE),
        (f'password="{OPAQUE} with spaces"', "with spaces"),
    ],
)
def test_token_shapes_are_redacted(text: str, leaked: str) -> None:
    out = SecretRedactor().redact(text)
    assert leaked not in out
    assert M in out


def test_assignment_keeps_key_and_quotes() -> None:
    r = SecretRedactor()
    assert r.redact(f"api_key={OPAQUE} next=1") == f"api_key={M} next=1"
    assert r.redact(f'{{"token": "{OPAQUE}", "n": 1}}') == f'{{"token": "{M}", "n": 1}}'
    assert r.redact(f"Authorization: Bearer {OPAQUE}") == f"Authorization: {M}"


def test_unterminated_pem_block_is_redacted_to_end() -> None:
    text = "log:\n-----BEGIN PRIVATE KEY-----\n" + PEM_BODY + "\n(truncated"
    out = SecretRedactor().redact(text)
    assert "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8" not in out
    assert out.startswith("log:\n")


@pytest.mark.parametrize(
    "text",
    [
        "Rotate the password and the API token every quarter; a token is not a password.",
        "The secret to good logs is structure.",
        "max_tokens=512 tokenizer=bpe temperature=0.2",
        "password policy: minimum length is enforced",
        "user=bob action=login outcome=success",
        "The bearer of this note is trusted.",
        "eyJ alone is not a token",
        "-----BEGIN PUBLIC KEY----- is fine to log",
    ],
)
def test_ordinary_text_left_alone(text: str) -> None:
    assert SecretRedactor().redact(text) == text


# --- idempotence ---------------------------------------------------------------------

IDEMPOTENCE_CORPUS = [
    f"Authorization: Bearer {OPAQUE}",
    f"token=abc{SECRET}",
    f"token={SECRET}xyz and password=[{OPAQUE}]",
    f'{{"api_key": "pre{SECRET}post"}}',
    f"{JWT}.{SECRET}",
    f"{PEM} {SECRET} {PEM_TYPED}",
    f"secret={M}",
    f"bearer {M}",
    f"x{SECRET}{SECRET}y",
    "plain text",
]


@pytest.mark.parametrize("text", IDEMPOTENCE_CORPUS)
def test_redaction_is_idempotent(red: SecretRedactor, text: str) -> None:
    once = red.redact(text)
    assert red.redact(once) == once
    assert SECRET not in once


# --- structures ----------------------------------------------------------------------


def test_redact_value_walks_nested_structures(red: SecretRedactor) -> None:
    value = {
        "msg": f"uses {SECRET}",
        "items": [f"a {SECRET}", ("t", f"api_key={OPAQUE}"), 42, None, 1.5, True],
        SECRET: "secret used as key",
        "nested": {"deep": [{"jwt": JWT}]},
        7: "int key",
    }
    out = red.redact_value(value)
    text = repr(out)
    assert SECRET not in text
    assert OPAQUE not in text
    assert JWT not in text
    assert out["msg"] == f"uses {M}"
    assert out[M] == "secret used as key"
    assert isinstance(out["items"][1], tuple)
    assert out["items"][2:] == [42, None, 1.5, True]
    assert out[7] == "int key"


def test_redact_value_does_not_mutate_input(red: SecretRedactor) -> None:
    inner = [f"a {SECRET}"]
    value = {"k": inner, "s": SECRET}
    out = red.redact_value(value)
    assert value == {"k": [f"a {SECRET}"], "s": SECRET}
    assert inner == [f"a {SECRET}"]
    assert out is not value
    assert out["k"] is not inner


def test_redact_value_scalars(red: SecretRedactor) -> None:
    assert red.redact_value(SECRET) == M
    assert red.redact_value(5) == 5
    assert red.redact_value(None) is None
    assert red.redact_value(frozenset({SECRET})) == frozenset({M})


# --- thread safety -------------------------------------------------------------------


def test_register_while_redacting_is_safe() -> None:
    r = SecretRedactor()
    values = [f"concurrent-value-{i:04d}" for i in range(200)]
    text = " ".join(values)
    errors: list[BaseException] = []
    stop = threading.Event()

    def reader() -> None:
        try:
            while not stop.is_set():
                r.redact(text)
        except BaseException as exc:  # pragma: no cover - only on failure
            errors.append(exc)

    readers = [threading.Thread(target=reader) for _ in range(4)]
    for t in readers:
        t.start()
    for v in values:
        assert r.register(v)
    stop.set()
    for t in readers:
        t.join(timeout=30)
    assert errors == []
    assert not any(t.is_alive() for t in readers)
    out = r.redact(text)
    assert out == " ".join([M] * len(values))


# --- log filter ----------------------------------------------------------------------


@pytest.fixture
def stream_logger(red: SecretRedactor) -> Iterator[tuple[logging.Logger, io.StringIO]]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingLogFilter(red))
    # A standalone logger, outside the manager, so only this handler sees the records.
    logger = logging.Logger("tests.vault.redacting", logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    yield logger, stream
    logger.removeHandler(handler)
    handler.close()


def test_log_filter_redacts_message_and_args(
    stream_logger: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = stream_logger
    logger.info(f"direct {SECRET}")
    logger.info("arg %s and %s", SECRET, f"Bearer {OPAQUE}")
    logger.info("dict %s", {"password": OPAQUE, "v": SECRET})
    logger.info("named %(x)s", {"x": SECRET})
    out = stream.getvalue()
    assert SECRET not in out
    assert OPAQUE not in out
    assert out.count(M) >= 5
    assert "direct" in out
    assert "named" in out


def test_log_filter_redacts_exception_text(
    stream_logger: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = stream_logger
    try:
        raise RuntimeError(f"failed with {SECRET}")
    except RuntimeError:
        logger.exception("boom")
    out = stream.getvalue()
    assert "RuntimeError" in out
    assert "Traceback" in out
    assert SECRET not in out
    assert M in out


def test_log_filter_redacts_stack_info(
    stream_logger: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = stream_logger
    logger.info("with stack %s", "x", stack_info=True)
    assert "Stack (most recent call last)" in stream.getvalue()


def test_log_filter_survives_malformed_records(
    stream_logger: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = stream_logger
    logger.info("two %s %s but one arg", SECRET)
    logger.info("bad %d", SECRET)
    logger.info(12345, SECRET)
    logger.info({"msg": SECRET})
    out = stream.getvalue()
    assert SECRET not in out
    assert "two" in out
    assert "bad" in out
    assert "12345" in out
    assert out.count("\n") == 4


def test_log_filter_does_not_mutate_original_record(red: SecretRedactor) -> None:
    record = logging.LogRecord("n", logging.INFO, __file__, 1, "v=%s", (SECRET,), None)
    result = RedactingLogFilter(red).filter(record)
    assert isinstance(result, logging.LogRecord)
    assert result is not record
    assert result.getMessage() == f"v={M}"
    assert record.args == (SECRET,)


def test_log_filter_with_caplog(red: SecretRedactor, caplog: pytest.LogCaptureFixture) -> None:
    caplog.handler.addFilter(RedactingLogFilter(red))
    try:
        with caplog.at_level(logging.INFO, logger="tests.vault.caplog"):
            logging.getLogger("tests.vault.caplog").info("value %s", SECRET)
    finally:
        caplog.handler.filters.clear()
    assert SECRET not in caplog.text
    assert f"value {M}" in caplog.text


def test_concurrent_registers_lose_nothing() -> None:
    """Several threads registering at once must not drop each other's values."""
    r = SecretRedactor()
    batches = [[f"batch-{b:02d}-value-{i:04d}" for i in range(100)] for b in range(8)]
    barrier = threading.Barrier(len(batches))
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [
            threading.Thread(target=lambda vs=vs: (barrier.wait(), [r.register(v) for v in vs]))
            for vs in batches
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
    finally:
        sys.setswitchinterval(old_interval)
    every = [v for vs in batches for v in vs]
    assert r.redact(" ".join(every)) == " ".join([M] * len(every))
