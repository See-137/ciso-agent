# ADR-0016: Separation of duties for approvals (self-approval forbidden by default)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (build status; link to ADR-0021)
Blueprint refs: §3 (register item "Roles", AGREED), §8.4 step 4, §9.1, §9.2, §9.3, §9.5, §19.3 (policy/authorization tests: "multi-role conflicts"), FR-024, FR-025, NFR-005; plan gap G33

## Context
The BP says "one person may hold multiple roles" (§9.3) and requires human approval for L4 actions (§9.2) and for each external inference request (§8.4 step 4). It does not say whether the person who requests an action may also approve it. The build has to answer that question the first time an approval is checked, so it is a choice the BP did not make and it is recorded here. This ADR is a question for the owner. It is not a technical preference.

The setting is `SafetySettings.allow_self_approval` in `src/ciso/app/settings.py`. Its default is `False`, and `config/provisional-settings.json` also sets `"allow_self_approval": false`.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Forbid: an approver may not approve their own request | A second human sees every human-initiated high-impact action; simple rule; easy to test and to explain to a reviewer | In a company where one person holds every role, a human-initiated L4 action cannot be approved at all. With two people, either one being unavailable blocks the other | Strongest. One stolen or misused administrator credential cannot both request and approve |
| Allow, with an extra audit flag on every self-approved action | A one-person company can operate; every self-approval is marked and can be reported and reviewed afterwards | Review happens after the action; someone has to actually read the report | Approval no longer adds a second person. It becomes a deliberate confirmation step with a record |
| Allow only for named operations | Separation is kept for most actions; the exceptions are explicit and short | Someone must choose and maintain the list; the first list is a guess until real operations exist (OD-15) | Risk is limited to the listed operations; the list itself becomes something to protect and review |

## Default chosen for the local build
Forbid. `allow_self_approval` is `False` unless a named settings file says otherwise.

Build status: the setting exists and defaults to `false`. The approvals module that would read it (`ciso.approvals`, plan task T2.1) is not in `src`, so nothing enforces the rule yet and no code reads `allow_self_approval`. What exists for it to use is the resolved principal and `Principal.credential_issued_by`, the actor id of whoever issued the credential the approver signed in with, so that the module can also refuse an approver whose credential the requester minted (ADR-0004). Who may request and who may approve are in ADR-0021; a system owner can be both for the same L4 action, and this rule is what separates the two.

What this default means in practice:
- If one person holds every role, that person cannot get a human-initiated L4 action approved. There is no workaround inside the platform. The action does not happen.
- Agent-initiated proposals are unaffected. When the CISO proposes an action, the requester is the agent, and a human holding the required role may approve it.

Weaknesses of this default:
- The second point above also limits what the rule protects against. A single administrator who wants an action can have the agent propose it and then approve the proposal. The rule stops a person from approving a request filed under their own name; it does not stop one person from being the only human involved.
- The rule compares actors, not people. With bootstrap identities (ADR-0004) one person could hold two actor records. This closes only when identities come from the organization's identity provider (OD-03).
- Availability: an approval that needs a second human waits for that human. No expiry or escalation value is agreed (ADR-0019).
- The setting is one boolean today. The second and third options need more than a changed value: an audit flag and a report for one, a list of operations for the other.

## Why this default is reversible
Seam: the one check in the approval service that compares requester and approver, driven by `SafetySettings.allow_self_approval`. Switching to "allow" is a settings change in a named file. The other two options are small additions at the same place: a field on the approval record and audit event, or a list of operation names consulted by the check. No stored approval has to change.

## Evidence needed to make this final
The owner's answers to these questions:
- How many humans will hold approver roles, and who is the second person for each approval? (`docs/phase0/role-and-approver-template.md`, approval routing table.)
- Which L4 operations does the company expect a human, not the agent, to initiate?
- Is the agent-proposes, same-person-approves path acceptable, or must it also need a second human?
- Does any customer contract or obligation require separation of duties for administrative actions (OD-10)?
- If self-approval is allowed, who reviews self-approved actions and how often? (Auditor / Reviewer role.)
- Should the same rule apply to external inference approvals (OD-14) and to releasing the kill switch (ADR-0018)?

## Consequences
- Until the owner decides, a one-person installation can observe, investigate, coordinate and approve agent proposals, and cannot run human-initiated L4 actions.
- The policy and approval tests must cover the requester-equals-approver case and the multi-role case (BP §19.3).
- Any change to this setting is a change to who can authorize high-impact actions and should itself be recorded in the audit log and reviewed.
