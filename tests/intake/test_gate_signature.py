"""Standard Webhooks signature verification for the central gate (`central_gate_v1`).

Known vectors come from the Standard Webhooks reference library tests; the header rules
from https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint.md
("Verify the signature")."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from tests.fakes.core import FakeRedactor, FakeSecrets
from tests.intake.conftest import (
    GATE_NOW,
    GATE_SECRET,
    OLD_GATE_SECRET,
    OLD_SECRET_REF,
    SECRET_REF,
    SW_BINARY_SIGNATURE,
    SW_MSG_ID,
    SW_PAYLOAD,
    SW_SECRET,
    SW_SIGNATURE,
    SW_TIMESTAMP,
    TOLERANCE,
    gate_prompt_frame,
    sign,
    signed,
)

from ciso.common.clock import FixedClock
from ciso.common.errors import AuthenticationError, FailClosed
from ciso.intake import (
    MAX_GATE_BODY_BYTES,
    BoundedSeenMessages,
    CentralGate,
    IntakeRefused,
    RefusalCode,
    SignatureRefused,
    verify_standard_webhook,
)

pytestmark = pytest.mark.unit

SW_AT = datetime.fromtimestamp(SW_TIMESTAMP, tz=UTC)


def sw_headers(signature: str = SW_SIGNATURE) -> dict[str, str]:
    return {
        "webhook-id": SW_MSG_ID,
        "webhook-timestamp": str(SW_TIMESTAMP),
        "webhook-signature": signature,
    }


def verify(headers: dict[str, str], body: bytes, *, now: datetime = SW_AT) -> str:
    return verify_standard_webhook(
        headers, body, secrets=(SW_SECRET,), now=now, tolerance_seconds=TOLERANCE
    ).message_id


def refusal(headers: dict[str, str], body: bytes, **kwargs: datetime) -> RefusalCode:
    with pytest.raises(SignatureRefused) as info:
        verify(headers, body, **kwargs)
    return info.value.code


# --- known vectors --------------------------------------------------------------------


def test_reference_vector_verifies() -> None:
    assert verify(sw_headers(), SW_PAYLOAD) == SW_MSG_ID


def test_reference_binary_vector_verifies() -> None:
    assert verify(sw_headers(SW_BINARY_SIGNATURE), bytes(range(256))) == SW_MSG_ID


def test_the_test_helper_reproduces_the_reference_vector() -> None:
    assert sign(SW_SECRET, SW_MSG_ID, SW_TIMESTAMP, SW_PAYLOAD) == SW_SIGNATURE


def test_one_changed_body_byte_fails() -> None:
    assert refusal(sw_headers(), SW_PAYLOAD.replace(b"2", b"3", 1)) is RefusalCode.BAD_SIGNATURE


def test_changed_id_or_timestamp_fails() -> None:
    headers = sw_headers()
    headers["webhook-id"] = "msg_other"
    assert refusal(headers, SW_PAYLOAD) is RefusalCode.BAD_SIGNATURE
    headers = sw_headers()
    headers["webhook-timestamp"] = str(SW_TIMESTAMP + 1)
    assert refusal(headers, SW_PAYLOAD) is RefusalCode.BAD_SIGNATURE


def test_wrong_secret_fails() -> None:
    other = "whsec_" + base64.b64encode(b"z" * 24).decode()
    with pytest.raises(SignatureRefused) as info:
        verify_standard_webhook(
            sw_headers(), SW_PAYLOAD, secrets=(other,), now=SW_AT, tolerance_seconds=TOLERANCE
        )
    assert info.value.code is RefusalCode.BAD_SIGNATURE


def test_any_matching_signature_in_the_list_is_accepted() -> None:
    headers = sw_headers(f"v1,AAAA v2a,BBBB {SW_SIGNATURE}")
    assert verify(headers, SW_PAYLOAD) == SW_MSG_ID


def test_only_v1_entries_count() -> None:
    signature = SW_SIGNATURE.replace("v1,", "v2a,")
    assert refusal(sw_headers(signature), SW_PAYLOAD) is RefusalCode.NO_SUPPORTED_SIGNATURE


def test_too_many_signature_entries_are_refused() -> None:
    signature = " ".join(["v1,AAAA"] * 40 + [SW_SIGNATURE])
    assert refusal(sw_headers(signature), SW_PAYLOAD) is RefusalCode.INVALID_SIGNATURE_HEADER


def test_header_names_are_case_insensitive() -> None:
    headers = {key.upper(): value for key, value in sw_headers().items()}
    assert verify(headers, SW_PAYLOAD) == SW_MSG_ID


def test_conflicting_duplicate_headers_are_refused() -> None:
    headers = sw_headers()
    headers["Webhook-Id"] = "msg_other"
    assert refusal(headers, SW_PAYLOAD) is RefusalCode.AMBIGUOUS_HEADER


@pytest.mark.parametrize("missing", ["webhook-id", "webhook-timestamp", "webhook-signature"])
def test_unsigned_request_is_refused(missing: str) -> None:
    headers = sw_headers()
    del headers[missing]
    assert refusal(headers, SW_PAYLOAD) is RefusalCode.UNSIGNED_REQUEST


@pytest.mark.parametrize("stamp", ["", "abc", "1614265330.5", "-1614265330", "1" * 20])
def test_malformed_timestamp_is_refused(stamp: str) -> None:
    headers = sw_headers()
    headers["webhook-timestamp"] = stamp
    assert refusal(headers, SW_PAYLOAD) is RefusalCode.TIMESTAMP_INVALID


def test_timestamp_at_the_tolerance_edge_is_accepted() -> None:
    assert verify(sw_headers(), SW_PAYLOAD, now=SW_AT + timedelta(seconds=TOLERANCE)) == SW_MSG_ID
    assert verify(sw_headers(), SW_PAYLOAD, now=SW_AT - timedelta(seconds=TOLERANCE)) == SW_MSG_ID


@pytest.mark.parametrize("skew", [TOLERANCE + 1, -(TOLERANCE + 1)])
def test_timestamp_outside_tolerance_is_refused(skew: int) -> None:
    now = SW_AT + timedelta(seconds=skew)
    assert refusal(sw_headers(), SW_PAYLOAD, now=now) is RefusalCode.TIMESTAMP_OUT_OF_TOLERANCE


def test_unset_tolerance_refuses() -> None:
    with pytest.raises(SignatureRefused) as info:
        verify_standard_webhook(
            sw_headers(), SW_PAYLOAD, secrets=(SW_SECRET,), now=SW_AT, tolerance_seconds=None
        )
    assert info.value.code is RefusalCode.TOLERANCE_UNSET


@pytest.mark.parametrize(
    "secret",
    [
        "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",  # no whsec_ prefix
        "whsec_not base64!",
        "whsec_" + base64.b64encode(b"k" * 23).decode(),  # below 24 bytes
        "whsec_" + base64.b64encode(b"k" * 65).decode(),  # above 64 bytes
        "whsec_" + base64.urlsafe_b64encode(b"\xfb\xff" * 16).decode(),  # URL-safe alphabet
    ],
)
def test_misconfigured_secret_is_refused(secret: str) -> None:
    with pytest.raises(SignatureRefused) as info:
        verify_standard_webhook(
            sw_headers(), SW_PAYLOAD, secrets=(secret,), now=SW_AT, tolerance_seconds=TOLERANCE
        )
    assert info.value.code is RefusalCode.SIGNING_SECRET_INVALID


def test_refusals_are_authentication_errors_that_name_no_secret() -> None:
    with pytest.raises(SignatureRefused) as info:
        verify(sw_headers("v1,AAAA"), SW_PAYLOAD)
    assert isinstance(info.value, AuthenticationError)
    assert isinstance(info.value, IntakeRefused)
    assert SW_SECRET.removeprefix("whsec_") not in str(info.value)


# --- the gate: secret by reference, replay, rotation ----------------------------------


def make_gate(
    secrets: FakeSecrets,
    *,
    tolerance: int | None = TOLERANCE,
    seen: BoundedSeenMessages | None = None,
    previous: str | None = None,
) -> CentralGate:
    return CentralGate(
        secrets=secrets,
        secret_ref=SECRET_REF,
        previous_secret_ref=previous,
        clock=FixedClock(GATE_NOW),
        redactor=FakeRedactor(),
        seen=seen if seen is not None else BoundedSeenMessages(capacity=8),
        tolerance_seconds=tolerance,
    )


def test_gate_accepts_a_signed_frame(gate: CentralGate) -> None:
    frame = gate.receive(*signed(gate_prompt_frame()))
    assert frame.request_id == "req_abc123"


def test_gate_refuses_a_replayed_message(gate: CentralGate) -> None:
    headers, body = signed(gate_prompt_frame())
    gate.receive(headers, body)
    with pytest.raises(SignatureRefused) as info:
        gate.receive(headers, body)
    assert info.value.code is RefusalCode.REPLAYED_MESSAGE


def test_a_bad_signature_does_not_consume_the_message_id(gate: CentralGate) -> None:
    headers, body = signed(gate_prompt_frame())
    forged = dict(headers, **{"webhook-signature": "v1,AAAA"})
    with pytest.raises(SignatureRefused):
        gate.receive(forged, body)
    assert gate.receive(headers, body).request_id == "req_abc123"


def test_gate_without_tolerance_refuses(gate_secrets: FakeSecrets) -> None:
    gate = make_gate(gate_secrets, tolerance=None)
    with pytest.raises(SignatureRefused) as info:
        gate.receive(*signed(gate_prompt_frame()))
    assert info.value.code is RefusalCode.TOLERANCE_UNSET


@pytest.mark.parametrize("bad", [0, -5])
def test_non_positive_tolerance_is_a_construction_error(
    gate_secrets: FakeSecrets, bad: int
) -> None:
    with pytest.raises(ValueError, match="tolerance"):
        make_gate(gate_secrets, tolerance=bad)


def test_unknown_secret_reference_refuses() -> None:
    gate = make_gate(FakeSecrets({}))
    with pytest.raises(SignatureRefused) as info:
        gate.receive(*signed(gate_prompt_frame()))
    assert info.value.code is RefusalCode.SIGNING_SECRET_UNAVAILABLE


def test_the_secret_is_resolved_by_reference_per_request(gate_secrets: FakeSecrets) -> None:
    gate = make_gate(gate_secrets)
    gate.receive(*signed(gate_prompt_frame()))
    assert gate_secrets.requested == [SECRET_REF]


def test_previous_secret_is_accepted_only_when_configured(gate_secrets: FakeSecrets) -> None:
    headers, body = signed(gate_prompt_frame(), secret=OLD_GATE_SECRET)
    with pytest.raises(SignatureRefused) as info:
        make_gate(gate_secrets).receive(headers, body)
    assert info.value.code is RefusalCode.BAD_SIGNATURE
    rotated = make_gate(gate_secrets, previous=OLD_SECRET_REF)
    assert rotated.receive(headers, body).request_id == "req_abc123"
    assert make_gate(gate_secrets, previous=OLD_SECRET_REF).receive(
        *signed(gate_prompt_frame(), secret=GATE_SECRET)
    )


def test_replay_memory_without_capacity_refuses(gate_secrets: FakeSecrets) -> None:
    gate = make_gate(gate_secrets, seen=BoundedSeenMessages())
    with pytest.raises(SignatureRefused) as info:
        gate.receive(*signed(gate_prompt_frame()))
    assert info.value.code is RefusalCode.REPLAY_MEMORY_UNAVAILABLE


def test_full_replay_memory_refuses_rather_than_forgets(gate_secrets: FakeSecrets) -> None:
    gate = make_gate(gate_secrets, seen=BoundedSeenMessages(capacity=1))
    first = gate_prompt_frame()
    gate.receive(*signed(first))
    second = gate_prompt_frame()
    second["request_id"] = "req_second"
    with pytest.raises(SignatureRefused) as info:
        gate.receive(*signed(second))
    assert info.value.code is RefusalCode.REPLAY_MEMORY_UNAVAILABLE


def test_replay_memory_forgets_ids_whose_window_has_passed() -> None:
    memory = BoundedSeenMessages(capacity=1)
    assert memory.remember("a", now=GATE_NOW, until=GATE_NOW + timedelta(seconds=10))
    assert not memory.remember("a", now=GATE_NOW, until=GATE_NOW + timedelta(seconds=10))
    later = GATE_NOW + timedelta(seconds=11)
    assert memory.remember("b", now=later, until=later + timedelta(seconds=10))


def test_replay_memory_capacity_must_be_positive() -> None:
    with pytest.raises(ValueError, match="capacity"):
        BoundedSeenMessages(capacity=0)
    with pytest.raises(FailClosed):
        BoundedSeenMessages().remember("a", now=GATE_NOW, until=GATE_NOW)


def test_oversized_body_is_refused_before_hashing(gate: CentralGate) -> None:
    body = b" " * (MAX_GATE_BODY_BYTES + 1)
    headers = {"webhook-id": "m", "webhook-timestamp": "1", "webhook-signature": "v1,AAAA"}
    with pytest.raises(IntakeRefused) as info:
        gate.receive(headers, body)
    assert info.value.code is RefusalCode.BODY_TOO_LARGE


def test_body_request_id_must_equal_the_signed_id(gate: CentralGate) -> None:
    frame = gate_prompt_frame()
    headers, body = signed(json.dumps(frame).encode(), msg_id="req_different")
    with pytest.raises(IntakeRefused) as info:
        gate.receive(headers, body)
    assert info.value.code is RefusalCode.REQUEST_ID_MISMATCH
