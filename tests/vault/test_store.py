"""SecretValue masking and EnvSecretStore resolution (blueprint 11.1, 13.4; NFR-007)."""

from __future__ import annotations

import copy
import hmac
import json
import operator
import pickle
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict
from pydantic_core import PydanticSerializationError

from ciso.common.clock import FixedClock
from ciso.common.errors import FailClosed, NotFound, ValidationFailed
from ciso.common.protocols import RevealableSecret, SecretResolver
from ciso.vault import ENV_PREFIX, EnvSecretStore, SecretRedactor, SecretValue

pytestmark = pytest.mark.unit

# Test-only values. Nothing here is a real credential.
VALUE = "unit-test-value-0001-not-real"
OTHER = "unit-test-value-0002-not-real"


def _assert_clean(text: str) -> None:
    assert VALUE not in text
    assert OTHER not in text


# --- SecretValue masking -------------------------------------------------------------


def test_reveal_returns_the_value() -> None:
    assert SecretValue(VALUE).reveal() == VALUE


def test_repr_str_and_format_are_masked() -> None:
    secret = SecretValue(VALUE)
    rendered = [
        repr(secret),
        str(secret),
        f"{secret}",
        f"{secret!r}",
        f"{secret:>40}",
        f"{secret}",
        "%s" % secret,  # noqa: UP031
        "%r" % (secret,),  # noqa: UP031
    ]
    for text in rendered:
        _assert_clean(text)
    assert str(secret) == SecretValue.MASK
    assert SecretValue.MASK in repr(secret)


def test_container_repr_is_masked() -> None:
    secret = SecretValue(VALUE)
    _assert_clean(repr([secret, {"k": secret}, (secret,)]))


def test_json_dumps_raises_without_leaking() -> None:
    with pytest.raises(TypeError) as excinfo:
        json.dumps({"key": SecretValue(VALUE)})
    _assert_clean(str(excinfo.value))


def test_pickle_raises_without_leaking() -> None:
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(SecretValue(VALUE), protocol=protocol)
        _assert_clean(str(excinfo.value))


def test_copy_and_deepcopy_stay_masked() -> None:
    secret = SecretValue(VALUE)
    for duplicate in (copy.copy(secret), copy.deepcopy(secret), copy.deepcopy({"s": secret})["s"]):
        assert isinstance(duplicate, SecretValue)
        assert not isinstance(duplicate, str)
        _assert_clean(repr(duplicate) + str(duplicate))
        assert duplicate.reveal() == VALUE


def test_copy_keeps_expiry(clock: FixedClock) -> None:
    secret = SecretValue(VALUE, expires_at=clock.now() + timedelta(minutes=1), clock=clock)
    duplicate = copy.deepcopy(secret)
    clock.advance(minutes=2)
    with pytest.raises(FailClosed):
        duplicate.reveal()


class _Holder(BaseModel):
    model_config = ConfigDict(frozen=True)
    name: str
    credential: SecretValue


def test_pydantic_model_refuses_to_dump() -> None:
    holder = _Holder(name="svc", credential=SecretValue(VALUE))
    _assert_clean(repr(holder))
    _assert_clean(str(holder))
    for dump in (holder.model_dump, holder.model_dump_json, lambda: holder.model_dump(mode="json")):
        with pytest.raises(PydanticSerializationError) as excinfo:
            dump()
        _assert_clean(str(excinfo.value))


def test_pydantic_model_rejects_plain_string() -> None:
    with pytest.raises(ValueError, match="SecretValue") as excinfo:
        _Holder(name="svc", credential=VALUE)
    # Pydantic echoes input values in its errors; the guard is that a plain string is refused.
    assert "credential" in str(excinfo.value)


def test_pydantic_model_accepts_secret_value() -> None:
    holder = _Holder(name="svc", credential=SecretValue(VALUE))
    assert holder.credential.reveal() == VALUE


# --- equality and hashing -------------------------------------------------------------


def test_equality_only_between_secret_values() -> None:
    assert SecretValue(VALUE) == SecretValue(VALUE)
    assert SecretValue(VALUE) != SecretValue(OTHER)
    assert SecretValue(VALUE) != VALUE
    assert operator.eq(VALUE, SecretValue(VALUE)) is False
    assert SecretValue(VALUE) != VALUE.encode()


def test_equality_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return bool(real(a, b))

    monkeypatch.setattr(hmac, "compare_digest", spy)
    assert SecretValue(VALUE) == SecretValue(VALUE)
    assert len(calls) == 1


def test_secret_value_is_unhashable() -> None:
    with pytest.raises(TypeError):
        hash(SecretValue(VALUE))
    with pytest.raises(TypeError):
        _ = {SecretValue(VALUE)}


def test_construct_rejects_non_string_and_empty() -> None:
    with pytest.raises(ValidationFailed):
        SecretValue(123)  # type: ignore[arg-type]
    with pytest.raises(ValidationFailed):
        SecretValue("")
    with pytest.raises(ValidationFailed):
        SecretValue("   ")


def test_satisfies_revealable_protocol() -> None:
    assert isinstance(SecretValue(VALUE), RevealableSecret)


# --- expiry ---------------------------------------------------------------------------


def test_reveal_before_expiry_works(clock: FixedClock) -> None:
    secret = SecretValue(VALUE, expires_at=clock.now() + timedelta(seconds=30), clock=clock)
    assert secret.reveal() == VALUE
    assert secret.expires_at == clock.now() + timedelta(seconds=30)


def test_reveal_after_expiry_fails_closed(clock: FixedClock) -> None:
    secret = SecretValue(VALUE, expires_at=clock.now() + timedelta(seconds=30), clock=clock)
    clock.advance(seconds=30)
    with pytest.raises(FailClosed) as excinfo:
        secret.reveal()
    _assert_clean(str(excinfo.value))
    assert "expired" in str(excinfo.value)


def test_expiry_without_clock_is_refused() -> None:
    with pytest.raises(ValidationFailed):
        SecretValue(VALUE, expires_at=datetime(2030, 1, 1, tzinfo=UTC))


def test_naive_expiry_is_refused(clock: FixedClock) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        SecretValue(VALUE, expires_at=datetime(2030, 1, 1), clock=clock)  # noqa: DTZ001
    _assert_clean(str(excinfo.value))


def test_no_expiry_never_expires(clock: FixedClock) -> None:
    secret = SecretValue(VALUE, clock=clock)
    clock.advance(days=3650)
    assert secret.reveal() == VALUE
    assert secret.expires_at is None


# --- EnvSecretStore -------------------------------------------------------------------


def _store(env: dict[str, str], redactor: SecretRedactor | None = None) -> EnvSecretStore:
    return EnvSecretStore(environ=env, redactor=redactor)


def test_prefix_constant() -> None:
    assert ENV_PREFIX == "CISO_SECRET_"


def test_resolves_from_prefixed_upper_case_variable() -> None:
    secret = _store({"CISO_SECRET_DB_PASSWORD": VALUE}).get("secret://db_password")
    assert isinstance(secret, SecretValue)
    assert secret.reveal() == VALUE


def test_store_satisfies_secret_resolver_protocol() -> None:
    assert isinstance(_store({}), SecretResolver)


def test_default_environ_is_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CISO_SECRET_VAULT_TEST_ONLY", VALUE)
    assert EnvSecretStore().get("secret://vault_test_only").reveal() == VALUE


@pytest.mark.parametrize(
    "ref",
    [
        "db_password",  # no scheme
        "secrets://db_password",  # unknown scheme
        "env://db_password",  # unknown scheme
        "SECRET://db_password",  # scheme is case-sensitive
        "secret://",  # empty name
        "secret://DB_PASSWORD",  # upper case name
        "secret://db-password",  # hyphen not allowed
        "secret://db password",  # space
        "secret://db_password/extra",  # path
        "secret://../db_password",
        " secret://db_password",
        "secret://db_password\n",
        "",
    ],
)
def test_malformed_refs_raise_validation_failed(ref: str) -> None:
    store = _store({"CISO_SECRET_DB_PASSWORD": VALUE})
    with pytest.raises(ValidationFailed) as excinfo:
        store.get(ref)
    _assert_clean(str(excinfo.value))


def test_non_string_ref_raises_validation_failed() -> None:
    with pytest.raises(ValidationFailed):
        _store({}).get(42)  # type: ignore[arg-type]


def test_malformed_ref_does_not_echo_input() -> None:
    """A caller that passes a raw value by mistake must not see it in the error."""
    with pytest.raises(ValidationFailed) as excinfo:
        _store({}).get(VALUE)
    _assert_clean(str(excinfo.value))


def test_unknown_name_raises_not_found() -> None:
    with pytest.raises(NotFound) as excinfo:
        _store({"CISO_SECRET_OTHER_NAME": VALUE}).get("secret://db_password")
    _assert_clean(str(excinfo.value))
    assert "db_password" in str(excinfo.value)


@pytest.mark.parametrize("empty", ["", " ", "\t\n"])
def test_empty_or_whitespace_value_raises_not_found(empty: str) -> None:
    with pytest.raises(NotFound):
        _store({"CISO_SECRET_DB_PASSWORD": empty}).get("secret://db_password")


@pytest.mark.parametrize(
    "env",
    [
        {"DB_PASSWORD": VALUE},
        {"SECRET_DB_PASSWORD": VALUE},
        {"ciso_secret_db_password": VALUE},
        {"CISO_SECRET_DB_PASSWORD_": VALUE},
        {"CISO_SECRET_DB": VALUE},
        {"CISO_SECRET_": VALUE},
    ],
)
def test_never_falls_back_to_another_variable(env: dict[str, str]) -> None:
    with pytest.raises(NotFound):
        _store(env).get("secret://db_password")


def test_resolved_values_are_registered_with_redactor() -> None:
    redactor = SecretRedactor()
    store = _store({"CISO_SECRET_A": VALUE, "CISO_SECRET_B": OTHER}, redactor)
    store.get("secret://a")
    assert redactor.redact(f"x {VALUE} y {OTHER}") == f"x {redactor.marker} y {OTHER}"
    store.get("secret://b")
    assert redactor.redact(f"x {VALUE} y {OTHER}") == f"x {redactor.marker} y {redactor.marker}"


def test_store_without_redactor_still_resolves() -> None:
    assert _store({"CISO_SECRET_A": VALUE}).get("secret://a").reveal() == VALUE


def test_short_resolved_value_is_returned_and_flagged(caplog: pytest.LogCaptureFixture) -> None:
    redactor = SecretRedactor()
    with caplog.at_level("WARNING", logger="ciso.vault.store"):
        secret = _store({"CISO_SECRET_PIN": "1234"}, redactor).get("secret://pin")
    assert secret.reveal() == "1234"
    assert any("pin" in rec.getMessage() for rec in caplog.records)
    assert all("1234" not in rec.getMessage() for rec in caplog.records)


def test_store_writes_nothing_to_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _store({"CISO_SECRET_A": VALUE}, SecretRedactor()).get("secret://a")
    assert list(tmp_path.iterdir()) == []
