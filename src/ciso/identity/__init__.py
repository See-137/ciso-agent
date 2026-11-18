"""Bootstrap identity: actors, role templates, attribute scope and local tokens.

Blueprint 9.3, FR-002, FR-003, FR-024, NFR-004. The company identity provider is an open
decision (OD-03); `ExternalIdentityAdapter` is the interface an SSO integration would
implement. Import `tables` before creating the operational schema. `HostLocalAdmin`
(bootstrap, lockout recovery) is never reachable from the API.
"""

from ciso.identity.authn import Authenticator, ExternalIdentityAdapter, ExternalSubject
from ciso.identity.hostlocal import BootstrapResult, HostLocalAdmin
from ciso.identity.roles import (
    PERMISSIONS,
    ROLE_TEMPLATES,
    SCOPE_ATTRIBUTES,
    RoleScope,
    RoleTemplate,
    permissions_for,
    scope_matches,
    template_for,
)
from ciso.identity.service import Actor, ActorStatus, IdentityService, RoleAssignment
from ciso.identity.tokens import PRODUCTION_SCRYPT, IssuedToken, ScryptParams, TokenMinter

__all__ = [
    "PERMISSIONS",
    "PRODUCTION_SCRYPT",
    "ROLE_TEMPLATES",
    "SCOPE_ATTRIBUTES",
    "Actor",
    "ActorStatus",
    "Authenticator",
    "BootstrapResult",
    "ExternalIdentityAdapter",
    "ExternalSubject",
    "HostLocalAdmin",
    "IdentityService",
    "IssuedToken",
    "RoleAssignment",
    "RoleScope",
    "RoleTemplate",
    "ScryptParams",
    "TokenMinter",
    "permissions_for",
    "scope_matches",
    "template_for",
]
