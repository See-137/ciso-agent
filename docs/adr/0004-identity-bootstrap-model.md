# ADR-0004: Identity (bootstrap model; OIDC/SSO adapter as an interface)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (host-local bootstrap and recovery, last-admin guard, caller re-resolution, token revocation, credential issuer)
Blueprint refs: §5.1 #2, §9.2, §9.3, §17.2 (identity provider / SSO dependency), §18 Phase 1, §19.4 #1, FR-002, FR-003, FR-024, NFR-004, NFR-005, OD-03, Appendix C #14; plan gap G30

## Context
The BP requires authenticated central access, separate human, service and agent identities, and attribution of every request (§5.1 #2). Roles are defined now and people are assigned later; real identities "should later come from the organization's identity provider" (§9.3). The identity system is unknown (OD-03). BP examples to ask about are Entra ID, Google, Okta, AD, multiple providers or another setup; none is assumed here. Phase 1 allows "identity integration or a secure bootstrap identity model". NFR-004 requires strong authentication for humans and no shared admin identity.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Bootstrap identity model: local actors, one-time random tokens stored as scrypt hashes, role templates from BP §9.3; SSO adapter as an interface only | Works with no identity provider; lets RBAC/ABAC, approvals and audit be built and tested now | No SSO, no MFA, no automatic deprovisioning; a second identity list to maintain by hand | Does not meet NFR-004 "strong authentication" for humans. Acceptable only while the API is bound to loopback (ADR-0012) |
| Implement SSO now against an assumed provider | Meets the BP's long-term direction early | Assumes the answer to OD-03, which the BP forbids | A wrong assumption about claims or groups would mis-map roles |
| Local passwords plus a second factor | Stronger human authentication without a provider | A credential system we must build, secure and support, likely to be discarded | Password storage and reset flows are a new attack surface |
| Client certificates (mTLS) for administrators | Strong authentication; fits the BP's workload identity direction (§10.2) | Certificate issuance and revocation need an authority that does not exist yet | Strong if run well; brittle if certificates are handled by hand |

## Default chosen for the local build
`ciso.identity` (`service.py`, `authn.py`, `hostlocal.py`, `gate.py`, `store.py`, `roles.py`, `tables.py`):
- Actors are human, service or agent. An actor is a user of this platform, not a company person record; it may point at a registry Person by reference (G30). An `anonymous` actor type exists only to label records of refused sign-ins; it can never hold a role and cannot be created.
- Five role templates from BP §9.3, each with a fixed permission set. `security_admin`, `system_owner`, `executive_risk_owner` and `auditor` are human-only: a service or agent is refused them at assignment, again when a principal is built, and again in the `Principal` model. One actor may hold several roles (FR-024). Who may approve is a separate question, answered in ADR-0021.
- A role assignment may be narrowed to systems, environments and classification labels, and to a validity window. It can be revoked. Each current assignment becomes one `RoleGrant` on the principal, with its scope as a mapping of attribute name to allowed values. Grants of one role are alternatives and never mix attributes. A role is decided with `Principal.covers`, not by holding the role alone. A stored scope with an unknown key or a non-list value raises `IntegrityFailure` instead of silently widening the grant. `security_admin` cannot be scoped or given an end date, so a scoped administrator cannot exist.
- The classification scheme is optional. With none configured, an assignment that narrows by classification is refused and everything else works.
- Only a human `security_admin` may create or disable actors, assign or revoke roles, or issue tokens. The caller is named by actor id and re-resolved from the database before the change and again inside the write transaction (`AdminGate`); a `Principal` object passed in is used only for its actor id, so a forged or stale object gets nowhere. The last active administrator cannot be disabled or lose the role (`Conflict`).
- Order of every identity change: audit an ATTEMPT record (if that fails, nothing changes), make the change in a short `BEGIN IMMEDIATE` transaction, audit the result. If the result record cannot be written, `FailClosed` is raised and the change stands; the ATTEMPT record shows it was made. No audit write happens while the write lock is held.
- A token is `<token_id>.<secret>`. The secret is random, shown once and never stored. The database holds a scrypt digest, a per-credential salt and the scrypt cost parameters used for that credential, so the cost can be raised later without breaking existing tokens. The default cost is `PRODUCTION_SCRYPT` (n=2**14, r=8, p=1) in `tokens.py`. The credential row records who issued it, and `authenticate` puts that actor id on the principal as `credential_issued_by`.
- Every token expires. The lifetime is capped by `max_token_ttl`; if that is unset, no token is issued (ADR-0019). A token can be revoked by a `security_admin` or by its own actor. Disabling an actor revokes all of its tokens in the same transaction; enabling it again restores none.
- Authentication rejects a malformed token, an unknown id, a wrong secret, a revoked or expired token and a disabled actor, all with one message, and a dummy hash keeps the timing alike. A malformed token or an unknown token id writes no audit record: it is logged and counted. A refusal against a real token id is audited as denied, under `unauthenticated` (type `anonymous`) when the secret did not match, and under the actor otherwise. The hash runs outside any write transaction.
- A successful authentication whose audit write fails still returns the principal. It is logged as an error and counted. This keeps sign-in, and with it reading and investigation, possible while the audit log refuses appends. State changes are still stopped, because they audit first.
- Host-local operations (`HostLocalAdmin`): `bootstrap_first_admin` creates the first human `security_admin` and its token, once per database for ever. It is refused if any `security_admin` assignment row has ever existed (revoked or lapsed included) or if the single-row bootstrap marker exists, so two concurrent bootstraps cannot both win. `recover_admin_token` issues a fresh token to an existing, active, human `security_admin` who is locked out; the operator's typed name and a reason go into the audit record, marked as a host-local recovery. Both run only through `python -m ciso.app.admin --config <settings file> bootstrap` and `recover-token` on the host, are audited under the fixed `host_local` identity, and print the token once on standard output. No API route reaches them, and a test checks that no API module names the service.
- `ExternalIdentityAdapter` is a protocol with no implementation: verify a provider assertion, say whether the subject is still active, map the subject to a local actor. The platform keeps its own actors and role assignments.
- In this model an administrator can issue a token to any active actor, including a `system_owner` or `executive_risk_owner`, and then authenticate as that person. That is how the bootstrap model works until an identity provider is chosen. The credential issuer is recorded so that the approvals module (planned) can refuse an approver whose credential the requester issued.

Weaknesses of this default:
- No MFA and no SSO. A leaked token is a full impersonation of its actor until it expires or is revoked.
- Host access is the root of trust for bootstrap and recovery. Whoever can run the admin command with the secret environment can become the first administrator, once, and can issue a fresh token to any existing administrator and so act as that person. The operator name is typed and not authenticated. There is no one-time secret for bootstrap.
- An administrator can mint a token for another human and act as them. The check that would catch an approver whose credential the requester issued is in the approvals module, which is not built. Until then the administrator role reaches every other role. Whether to forbid this, require a second administrator or accept it is an owner decision.
- One administrator is one point of failure. The last-admin guard stops the platform from removing them, and the recovery command fixes an expired token. Neither helps if the administrator's actor row is damaged or the database is lost.
- Authentication no longer depends on the audit log, but changing anything does. With the audit log refusing appends, an administrator can sign in, read and verify, and cannot change identity or release the kill switch until the log is repaired. The only automatic repair is the crash recovery in ADR-0013.
- A refusal against a real token id writes an audit record with an fsync. A caller who knows a token id can grow the log; the address rate limit before authentication (ADR-0012) is the only brake. Unknown and malformed tokens leave no audit record, only a counter and a log line, so a spray of them is visible in metrics and not in the audit trail.
- Every request costs one scrypt computation and one short write for `last_used_at`, and each success one audit append, because a bearer token is checked on each request and there is no session.
- The permission set of each role is fixed in code. The API's route permission check uses roles only and not grant scopes, so a scoped role passes a route check on the role alone; taking scopes into account is in progress.
- A person who leaves the company keeps a working actor until someone disables it by hand.

## Why this default is reversible
Seam: `Authenticator` and the `ExternalIdentityAdapter` protocol in `ciso.identity`. The API, policy engine and approval service depend on a `Principal` and its roles, not on how the principal was authenticated. To switch: implement the adapter for the provider named in Phase 0, map its groups or claims to role templates, link existing actors to provider subjects so audit history stays attributable, then stop issuing bootstrap tokens to humans.

## Evidence needed to make this final
- OD-03 answered with evidence: which provider or providers, SSO protocol support, MFA enforcement, group and claim structure, who administers it.
- How service identities are issued and rotated.
- The filled role-and-approver template from Phase 0, including the second administrator.
- The owner's decision on whether an administrator may mint tokens for other people, and on whether host access alone is enough to recover an administrator.
- Who has access to the host that runs the admin command.

## Consequences
- The control plane is usable today without waiting for OD-03.
- The build must not be exposed beyond loopback with bootstrap tokens as the only human authentication.
- A second `security_admin` should exist before anyone depends on this model. The lockout recovery command and the last-admin rule are built; a second administrator, an owner decision on minting and a provider-backed login are not.
- When SSO arrives, the bootstrap path stays as a documented break-glass procedure or is removed; that choice is part of closing this ADR.
