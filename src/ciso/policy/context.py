"""Facts the policy engine may ask for at evaluation time.

Other modules implement `PolicyContext` (registry, channel registry, playbook store).
Who the actor is comes from the `PrincipalResolver` the engine is built with, not from
here. A context never decides; it only answers, and the engine is strict about answers:

- a yes is exactly `True`; any other value, truthy or not, counts as no;
- a method that raises, or returns the wrong type, makes the engine deny
  (blueprint 9.5, `FailClosed` semantics).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from pydantic import ConfigDict

from ciso.common.enums import FreshnessState
from ciso.common.principal import Principal
from ciso.common.schemas import Model, UtcDatetime
from ciso.policy.envelope import ActionEnvelope, EnvelopeScope


class PlaybookStatus(Model):
    """The state of the playbook record behind an L3 operation for one target (OD-15).

    Strictly typed: `approved` and `enabled` must be real booleans. A playbook with no
    expiry does not count as unexpired: an L3 run needs approved, enabled and an expiry
    in the future.
    """

    model_config = ConfigDict(strict=True)

    playbook_ref: str
    approved: bool
    enabled: bool
    expires_at: UtcDatetime | None = None


class PolicyContext(Protocol):
    def is_within_scope(self, principal: Principal, envelope: ActionEnvelope) -> bool:
        """True only when an approved scope record covers the envelope's target for this
        principal. This is in addition to the engine's own role-grant check, which uses
        `Principal.covering_roles` against the envelope's attributes."""
        ...

    def is_channel_approved(self, channel: str) -> bool:
        """True only for a channel a security_admin approved (G13)."""
        ...

    def playbook_status(self, operation: str, scope: EnvelopeScope) -> PlaybookStatus | None:
        """The playbook record that authorises `operation` on this target scope, or None.
        A playbook approved for one target must not be returned for another."""
        ...

    def fact_freshness(self, refs: tuple[str, ...]) -> Mapping[str, FreshnessState]:
        """Freshness per supporting-evidence ref. A ref missing from the answer, or an
        answer that is not a `FreshnessState`, counts as not current."""
        ...
