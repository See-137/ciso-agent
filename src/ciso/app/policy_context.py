"""The conservative policy context the composition root wires until real sources exist."""

from __future__ import annotations

from collections.abc import Mapping

from ciso.common.enums import FreshnessState
from ciso.common.principal import Principal
from ciso.policy import ActionEnvelope, EnvelopeScope, PlaybookStatus


class DefaultPolicyContext:
    """Conservative `PolicyContext` until registry, scopes, channels and playbooks exist.

    Every answer is the refusing one: no approved channel, no playbook, no approved scope,
    no fresh facts. Whether the actor exists and is active is not asked here: the policy
    engine resolves the actor through its own `PrincipalResolver`.
    """

    def is_within_scope(self, principal: Principal, envelope: ActionEnvelope) -> bool:
        return False

    def is_channel_approved(self, channel: str) -> bool:
        return False

    def playbook_status(self, operation: str, scope: EnvelopeScope) -> PlaybookStatus | None:
        return None

    def fact_freshness(self, refs: tuple[str, ...]) -> Mapping[str, FreshnessState]:
        return {}
