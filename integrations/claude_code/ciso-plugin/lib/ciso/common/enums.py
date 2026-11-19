"""Vocabulary shared by every module. Values are the wire format: do not rename."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class InformationState(StrEnum):
    """Blueprint 7.5. How far a fact can be trusted."""

    VERIFIED = "verified"
    DECLARED = "declared"
    INFERRED = "inferred"
    DISPUTED = "disputed"
    UNKNOWN = "unknown"


class FreshnessState(StrEnum):
    """Blueprint 6.5."""

    CURRENT = "current"
    STALE = "stale"
    EXPIRED = "expired"
    MISSING = "missing"
    UNKNOWN = "unknown"


class ReconciliationState(StrEnum):
    """Blueprint 6.5."""

    MATCHED = "matched"
    SUPERSEDED = "superseded"
    CONFLICTING = "conflicting"
    AWAITING_OWNER_VALIDATION = "awaiting_owner_validation"
    UNRESOLVED = "unresolved"


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    THIRD_PARTY = "third_party"
    CUSTOMER_OWNED = "customer_owned"
    UNKNOWN = "unknown"

    @property
    def never_scannable(self) -> bool:
        """Blueprint 7.3: these are never in scope by inference, whatever references them."""
        return self in {Environment.THIRD_PARTY, Environment.CUSTOMER_OWNED}


class AuthorityLevel(IntEnum):
    """Blueprint 9.1. Higher means more consequence."""

    L0_OBSERVE = 0
    L1_INVESTIGATE = 1
    L2_COORDINATE = 2
    L3_EXECUTE = 3
    L4_HIGH_IMPACT = 4


class SecurityDomain(StrEnum):
    """Blueprint 13.3 `domain`."""

    ENTERPRISE = "enterprise"
    PRODUCT_AI = "product_ai"
    EMPLOYEE_AI = "employee_ai"
    CISO_PLATFORM = "ciso_platform"


class ActorType(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    AGENT = "agent"
    #: A caller that has not been authenticated. Used in audit records of refused
    #: sign-ins; an anonymous actor never holds a role.
    ANONYMOUS = "anonymous"


class Role(StrEnum):
    """Blueprint 9.3 role templates. People are mapped to roles later, through the IdP."""

    SECURITY_ADMIN = "security_admin"
    SYSTEM_OWNER = "system_owner"
    EXECUTIVE_RISK_OWNER = "executive_risk_owner"
    EMPLOYEE = "employee"
    AUDITOR = "auditor"


#: Roles that only a human may hold. Services and agents can never approve or administer.
HUMAN_ONLY_ROLES: frozenset[Role] = frozenset(
    {Role.SECURITY_ADMIN, Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER, Role.AUDITOR}
)


#: Roles that may decide an approval (blueprint 9.3). The administrator configures the
#: platform and may request, but does not approve; the auditor is read-only. Provisional
#: until the owner confirms the routing (ADR-0021).
APPROVER_ROLES: frozenset[Role] = frozenset({Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER})


class KillCapability(StrEnum):
    """Blueprint 11.2. What the operator emergency stop can block."""

    WRITES = "writes"
    EXTERNAL_INFERENCE = "external_inference"
    ACTIVE_SCANS = "active_scans"
    L3_RUNS = "l3_runs"


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    HOLD = "hold"
    REQUIRE_APPROVAL = "require_approval"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILED = "failed"
    ATTEMPT = "attempt"
