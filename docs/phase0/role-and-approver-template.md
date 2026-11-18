# Role and approver template

The BP defines roles now and assigns people later (BP §9.3; §3 register item "Roles": "AGREED: Role-based authority; no people assigned yet"). This file holds the five role templates, what each may approve, and blank slots for the people. Filling it is one of the Phase 0 exit gate items (owner/role templates).

## Rules that apply to every assignment

1. **A role is not a person.** The platform stores roles and approver roles without hardcoded named individuals (FR-002). The mapping below is data and will later come from the organization's identity provider (BP §9.3).
2. **One person may hold several roles** (BP §9.3, FR-024). This is expected in a small company.
3. **Agents and services can never hold an approver role.** Only a human can approve. The CISO "cannot expand its own authority, accept business risk, appoint approvers or alter its audit history" (BP §1), and the model cannot change approvers (BP §9.2). In the build, an agent or service actor can never hold `security_admin` or any approver role.
4. **The approver must not be the requester.** The build is meant to enforce this in its approvals module (ADR-0016), which is planned and not yet written; until it exists nothing enforces it. When one person holds several roles, some approvals therefore need a second human. Name that second person below; do not leave it to be discovered during an incident.
5. **Risk acceptance is a human business decision, not an AI decision** (BP §9.3).
6. **RBAC and ABAC together.** Roles are stable job or authority roles. A role assignment can be limited by attributes: resource, environment, sensitivity, action risk, time and scope (BP §9.3). Use the scope column for this.

## The five role templates (BP §9.3)

| Role template | Id in the build | Responsibilities (BP §9.3) | Notes (BP §9.3) | What the role may approve |
|---|---|---|---|---|
| Security Administrator | `security_admin` | Manages CISO configuration, connectors, policies, model configuration, allowed tools and role mapping | A role, not a named person. Must be strongly authenticated and auditable | The BP gives this role management of configuration and does not list approvals for it. In the build, a human holding this role engages and releases the kill switch. Any further approval right is a company decision; record it in the routing table below |
| System Owner | `system_owner` | Owns a system/service and approves scoped changes that affect it | May be a developer, platform owner or business application owner | Scoped changes that affect the system or service this person owns, and only that system |
| Executive Risk Owner | `executive_risk_owner` | Accepts or rejects significant business risk and policy exceptions | Risk acceptance is a human business decision, not an AI decision | Acceptance or rejection of significant business risk; policy exceptions |
| Employee | `employee` | Reports issues, requests guidance, provides declared ownership/context and receives relevant security instructions | No assumption of access to other employees' sensitive information | Nothing |
| Auditor / Reviewer | `auditor` | Read-only access to evidence, policy decisions, incidents and audit history where authorized | Optional role; can be combined with another role in a small startup | Nothing. The role reads; it does not approve |

## What the build does today

The last column of the routing table below, "Current build default (provisional)", states what the code does now, taken from `src/ciso/identity/roles.py` (role permissions), `src/ciso/common/enums.py` (`APPROVER_ROLES`) and `src/ciso/policy/rulesets/default.json` (default ruleset). These are placeholders so the platform can be exercised. None of them is the company's decision, and a filled "company decision" column replaces them. See ADR-0021 for the reasoning and its weaknesses.

Three facts frame the column:

- The approvals module is not built, so no approval can be recorded yet. Where the column says a role "would" approve, that is what the policy engine names as the required approver; nothing consumes it.
- A human who requests an L4 action must be a `security_admin` or a `system_owner` whose grant reaches the target. A `security_admin` may request and does not approve. A `system_owner` can do both for the same action, so the self-approval rule (ADR-0016) is what separates the two.
- Role grants can be narrowed to systems, environments and classification labels. The policy engine applies the narrowing. The API's route permissions do not yet (in progress).

## Approval routing

The BP requires an approval for each item below. For most of them it does not say which role gives it. Where the "named by BP" column says no, the company decides, and the decision is recorded here and then in policy. Do not guess.

| Approval | BP source | Approving role named by BP? | Approving role (company decision) | Second human if approver would be the requester | Current build default (provisional) |
|---|---|---|---|---|---|
| Scoped change that affects a system | §9.3 | Yes: System Owner of that system | System Owner | ____ | `system_owner` holds `approval.decide` and `scope.approve`, and is meant to approve only through a grant that reaches the system (the approvals module is to check this). No change-approval workflow exists yet. |
| Acceptance of significant business risk | §9.3 | Yes: Executive Risk Owner | Executive Risk Owner | ____ | `executive_risk_owner` is the only role holding `risk.accept`. No risk register or acceptance workflow exists yet. |
| Policy exception | §9.3 | Yes: Executive Risk Owner | Executive Risk Owner | ____ | `executive_risk_owner` (`risk.accept`). No exception mechanism exists; the ruleset has no exception rule. |
| L4 high-impact intervention | §9.1, §9.2 | No. "Human approval required"; role not named | ____ | ____ | The engine returns require_approval naming `executive_risk_owner` and `system_owner`. Requesters: an agent or service for operations marked requestable, or a human `security_admin` or `system_owner` with a grant reaching the target. `security_admin` does not approve. Self-approval is off by default (`allow_self_approval` false), but the module that enforces it is not built. |
| L3 playbook authorization | §9.2 | No. "Explicitly approved by an authorized role"; role not named | ____ | ____ | No role is given the right. The policy context reports no playbook and none ships, so every L3 request is denied. A human `security_admin` or `system_owner` could trigger an active playbook once one exists. |
| Discovery scope (domains, ranges, accounts, repositories, environments) | §7.3, §18 Phase 3 | No | ____ | ____ | `system_owner`, for a system the grant reaches (`scope.approve`). A `security_admin` does not approve a scope. No scope registry or discovery exists yet. |
| Deeper security test plan | §7.4 | No | ____ | ____ | None. No permission and no rule exist. The `active_scans` kill-switch capability governs deep tests as well as scans. |
| Connector scope change | §13.4 | No. "Configuration approval"; role not named | ____ | ____ | `security_admin` holds `connector.configure` (configure, not approve). No connector module or approval step exists. |
| External inference, per request | §8.4 step 4 | No. "A designated human"; open as OD-14 | ____ | ____ | Blocked. The feature is off, the approver role is unset and no external path is built. The settings would accept `security_admin`, `system_owner` or `executive_risk_owner` as the approver, which disagrees with the L4 default; the owner decides under OD-14. |
| Access to raw customer content for a specific incident | §4.5 | No | ____ | ____ | None. No permission, rule or evidence module exists. `auditor` reads evidence (`evidence.read`) once evidence exists. |
| Engaging and releasing the kill switch | §11.2 | No. "Operator-controlled". The build requires a human holding `security_admin` | ____ | ____ | `security_admin` only (`killswitch.engage`, `killswitch.release`). One person can engage and release; no second human is required. The host-local break-glass command can engage and cannot release. |
| Change to policy, allowed tools or role mapping | §9.3 | Managed by Security Administrator; the BP does not say whether a second approval is needed | ____ | ____ | `security_admin` holds `policy.manage` and `identity.manage`, with no second approval. The default ruleset denies envelopes for control-plane operations, and no API route changes policy or roles. Role assignment is done by a human `security_admin` through the identity service, audited. |

## Role holders

| Role template | Person | Alternate | Identity reference (identity provider subject or group: ____) | Scope limit (systems, environments), if any | Assigned by | Effective from | Next review |
|---|---|---|---|---|---|---|---|
| Security Administrator | ____ | ____ | ____ | ____ | ____ | ____ | ____ |
| Executive Risk Owner | ____ | ____ | ____ | ____ | ____ | ____ | ____ |
| Auditor / Reviewer (optional) | ____ | ____ | ____ | ____ | ____ | ____ | ____ |
| Employee | All staff by default: confirm ____ | Not applicable | ____ | ____ | ____ | ____ | ____ |

System Owner is assigned per system, in the next table.

## System Owners

One row per system. Use the row ids from `source-system-matrix.md`. An unowned system is a finding, not a blank to skip: write "unowned" and name who will resolve it.

| System (matrix row id) | Environment | System Owner | Alternate | Confirmed by the named person on | Notes |
|---|---|---|---|---|---|
| ____ | ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ | ____ |

## Approval delegation

The BP's domain model includes approval delegation (BP §6.3). Record any delegation here. A delegation goes to a human, has a scope and has an end date.

| From (role and person) | To (person) | Scope | Starts | Ends | Approved by |
|---|---|---|---|---|---|
| ____ | ____ | ____ | ____ | ____ | ____ |

## Checks before this template counts as complete

- [ ] Every role template has a person, or is recorded as intentionally unfilled (only Auditor / Reviewer is optional in the BP).
- [ ] Every row in the approval routing table has an approving role.
- [ ] For every person who holds more than one role, each approval where that person could be both requester and approver has a named second human.
- [ ] Every system in the source-system matrix has a System Owner or is recorded as unowned with someone assigned to resolve it.
- [ ] No row names an agent, a service account or a shared account as an approver.
- [ ] Each named person has confirmed the assignment.
- [ ] The identity reference column is filled, or marked "pending OD-03" if the identity system is not yet confirmed.
