"""Error types. Callers catch the narrow type; anything unexpected must stop a write."""

from __future__ import annotations


class CisoError(Exception):
    """Base for every error this platform raises on purpose."""


class ValidationFailed(CisoError, ValueError):
    """Input did not match its schema or a stated invariant.

    Also a `ValueError`, so a Pydantic validator that raises it reports a normal
    validation error, and callers can catch one type for every bad-input case.
    """


class NotFound(CisoError):
    pass


class Conflict(CisoError):
    """The request collides with existing state (duplicate, wrong status, stale version)."""


class AuthenticationError(CisoError):
    pass


class AuthorizationError(CisoError):
    """The principal is known but not allowed to do this."""


class PolicyDenied(AuthorizationError):
    """The policy engine returned deny or hold."""


class ApprovalRequired(AuthorizationError):
    """A human approval is needed and is missing, expired or bound to a different payload."""


class FailClosed(CisoError):
    """A control the operation depends on could not be consulted, so the operation stops.

    Blueprint 9.5: policy engine, identity, approval system or audit path unavailable.
    """


class KillSwitchEngaged(FailClosed):
    pass


class ScopeViolation(AuthorizationError):
    """A target is outside every approved scope. Blueprint 7.3."""


class IntegrityFailure(CisoError):
    """Stored data failed a hash, signature or chain check."""


class InferenceUnavailable(CisoError):
    """The local model could not answer. This never triggers an external call."""


class ExternalInferenceBlocked(AuthorizationError):
    """An external model request was refused. Blueprint 8.4."""


class PreconditionFailed(CisoError):
    """A precondition named in an action envelope is no longer true."""


class VerificationMismatch(CisoError):
    """The target system does not show the result the tool claimed."""
