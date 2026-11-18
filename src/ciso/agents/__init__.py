"""Identity and agent registry (docs/skill/spec-draft.md, milestone S1).

Ties a session to a person and an agent record. An unknown agent is recorded as unknown,
never as trusted. May import only `ciso.common` (tests/architecture).
"""

from ciso.agents.admin import AgentAdmin
from ciso.agents.models import (
    AgentFact,
    AgentRecord,
    AgentsConflict,
    AgentsNotFound,
    AgentsRefused,
    AgentStatus,
    AttributionReason,
    IdentityBinding,
    RefusalCode,
    Registration,
    SeenClaim,
    SessionRecord,
)
from ciso.agents.registry import AgentRegistry

__all__ = [
    "AgentAdmin",
    "AgentFact",
    "AgentRecord",
    "AgentRegistry",
    "AgentStatus",
    "AgentsConflict",
    "AgentsNotFound",
    "AgentsRefused",
    "AttributionReason",
    "IdentityBinding",
    "RefusalCode",
    "Registration",
    "SeenClaim",
    "SessionRecord",
]
