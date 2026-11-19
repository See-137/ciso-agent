"""Why the intake refused a report.

A refusal names a closed reason code and nothing else: no field value, key name from the
input, header value or secret, because refusals reach logs and audit records. Callers map
a refusal to "stop the action"; the intake never turns bad input into an allow.
"""

from __future__ import annotations

from enum import StrEnum

from ciso.common.errors import AuthenticationError, ValidationFailed


class RefusalCode(StrEnum):
    # Envelope and JSON shape (both formats).
    REQUEST_TOO_LARGE = "request_too_large"
    NOT_JSON = "not_json"
    UNKNOWN_FIELD = "unknown_field"
    MISSING_FIELD = "missing_field"
    INVALID_FIELD = "invalid_field"
    UNSUPPORTED_FORMAT = "unsupported_format"
    UNKNOWN_EVENT = "unknown_event"
    EVENT_MISMATCH = "event_mismatch"
    CLAIM_MARKED_VERIFIED = "claim_marked_verified"
    CLAIM_KIND_RESERVED = "claim_kind_reserved"
    MISSING_CORRELATION_ID = "missing_correlation_id"
    MALFORMED_TOOL_INPUT = "malformed_tool_input"
    #: The request's `device` is not the device the token authenticated (review H4, Q8).
    DEVICE_MISMATCH = "device_mismatch"
    # Central gate delivery and signature.
    BODY_TOO_LARGE = "body_too_large"
    UNSIGNED_REQUEST = "unsigned_request"
    AMBIGUOUS_HEADER = "ambiguous_header"
    INVALID_SIGNATURE_HEADER = "invalid_signature_header"
    TIMESTAMP_INVALID = "timestamp_invalid"
    TIMESTAMP_OUT_OF_TOLERANCE = "timestamp_out_of_tolerance"
    TOLERANCE_UNSET = "tolerance_unset"
    SIGNING_SECRET_UNAVAILABLE = "signing_secret_unavailable"  # noqa: S105 (a code name)
    SIGNING_SECRET_INVALID = "signing_secret_invalid"  # noqa: S105 (a code name)
    NO_SUPPORTED_SIGNATURE = "no_supported_signature"
    BAD_SIGNATURE = "bad_signature"
    REPLAYED_MESSAGE = "replayed_message"
    REPLAY_MEMORY_UNAVAILABLE = "replay_memory_unavailable"
    # Central gate frame.
    REQUEST_ID_MISMATCH = "request_id_mismatch"
    UNKNOWN_FRAME_TYPE = "unknown_frame_type"
    MALFORMED_FRAME = "malformed_frame"
    TOO_MANY_TOOL_CALLS = "too_many_tool_calls"


class IntakeRefused(ValidationFailed):
    """The report was not accepted. `code` says why; the message carries only the code."""

    def __init__(self, code: RefusalCode) -> None:
        super().__init__(f"intake refused: {code.value}")
        self.code = code

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.code.value!r})"


class SignatureRefused(IntakeRefused, AuthenticationError):
    """The central gate delivery could not be authenticated (signature, time, replay)."""


def refuse(code: RefusalCode) -> IntakeRefused:
    """Build a refusal. Raise it with `from None` so no input value rides on the chain."""
    return IntakeRefused(code)
