# ADR-0021: Approval routing and risk class labels
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-18
Blueprint refs: §8.4 step 4, §9.1, §9.2, §9.3, §9.4 (`risk_class`), §19.3 (policy/authorization tests: "multi-role conflicts"), FR-024, FR-025, OD-11, OD-14, OD-15; plan gaps G25, G33; follow-ups F9, F10

## Context
Three questions had to be answered in code before any approval could be routed, and the blueprint answers none of them in full.

1. Who may approve an L4 action? BP §9.2 says L4 "always requires human approval". BP §9.3 says a System Owner "approves scoped changes that affect" a system and an Executive Risk Owner "accepts or rejects significant business risk and policy exceptions". It names no approver for L4 as such, for L3 playbook authorization, for discovery scope, for a deeper test plan, for a connector scope change, or for external inference (OD-14). For most approvals in `docs/phase0/role-and-approver-template.md` the column "Approving role named by BP?" says no.
2. Who may request an L4 action? The blueprint does not say. The action envelope carries a `requesting_component / authenticated_actor` (BP §9.4) but no rule on which roles may file a request.
3. What are the risk classes? BP §9.4 requires a `risk_class` on every envelope. BP OD-11 (risk methodology) is open and BP register item ADR-016 says not to select a scoring formula yet. Plan gap G25 asked for the provisional labels to be recorded in an ADR, and none was.

Until this ADR, two places disagreed: the role templates gave `approval.decide` to `system_owner` and `executive_risk_owner`, and the default ruleset named `security_admin` and `system_owner` as L4 approvers (follow-up F9). The code has since been brought into line; this record states what it does.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Approvers are the roles that hold `approval.decide` in the role templates (`system_owner`, `executive_risk_owner`). The administrator configures and may request, but does not approve. One list in code (`APPROVER_ROLES`) that the ruleset loader enforces | Follows BP §9.3 wording: the System Owner approves changes to the system, the Executive Risk Owner accepts significant risk. The role that can change policy and roles cannot also approve what it requests | In a small company the same person may hold all three roles, so approval depends on the self-approval rule (ADR-0016) rather than on the roles. Two lists must stay in step: `APPROVER_ROLES` and the `approval.decide` holders | Separates configuring the platform from approving its high-impact actions. Does not separate people when one person holds every role |
| The administrator also approves | Fewer people needed; a one-person company can run L4 actions | The role that mints tokens, assigns roles and changes policy could approve its own requests, and approve for any other role by minting a token | Weakest. Rejected as a default |
| Only the Executive Risk Owner approves L4 | One accountable approver for every L4 action | A business role for every technical action; BP §9.3 gives the System Owner scoped approval rights | Narrow, but ignores the System Owner's stated role |
| Approvers named per operation in the ruleset, with no global list | Most flexible | The list becomes data nobody checks against the role templates; the review that found F9 would repeat | Hard to audit |
| A numeric or computed risk class (a score) | Routing by consequence | Selects the risk methodology that OD-11 and register item ADR-016 leave open | Rejected: decides a deferred question |
| Free-text risk class | Nothing to maintain | A typo or invented label could match no rule, or the wrong one | Rejected |

## Default chosen for the local build
Roles and rules are as the code has them (`ciso.common.enums.APPROVER_ROLES`, `src/ciso/identity/roles.py`, `src/ciso/policy/rulesets/default.json`, version `default-2026.11.17-3`). All of it is provisional.

Who may approve:
- `APPROVER_ROLES` is `system_owner` and `executive_risk_owner`. The ruleset loader refuses a `require_approval` rule that names any other role as approver (`ciso.policy.rules.Rule`), so a changed ruleset cannot add `security_admin`, `auditor` or `employee` as an approver. The loader gives deny-all in that case (ADR-0009).
- Both roles are human-only. A service or agent can never hold them (ADR-0004), so an agent or service can never approve.
- `security_admin` configures the platform and may request L4 actions, as below. It holds no `approval.decide`, no `scope.approve` and no `risk.accept`.
- `auditor` and `employee` approve nothing.
- Discovery scope approval (`scope.approve`) belongs to `system_owner` for the system concerned. Risk acceptance and policy exceptions (`risk.accept`) belong to `executive_risk_owner`. Neither workflow exists in the code yet; the permissions are the only default.

Who may request an L4 action (rules `approve-l4-nonhuman` and `approve-l4-human-roles`):
- An agent or service may propose any L4 operation the catalog marks `agent_requestable`. A protected (control-plane) operation is denied for them whatever a rule says.
- A human may request an L4 action only as `security_admin` or `system_owner`, and only through a grant that reaches the target (`Principal.covering_roles`). An `executive_risk_owner`, an `auditor` and an `employee` cannot request one.
- The loader requires every `allow` or `require_approval` rule that can match a write, or anything at L2 or above, to name `actor_types`, and `required_roles` when humans are included. A rule that leaves the requester open is refused and the ruleset becomes deny-all. Only a read-only rule (`writes: false`) limited to L0 and L1 is exempt (follow-up M6).

How approver roles combine:
- Both L4 rules name `executive_risk_owner` and `system_owner`. When several `require_approval` rules decide one request, the approver roles are the intersection of their lists. An empty intersection is a deny (`no_common_approver`). A broader rule therefore cannot widen who may approve.

The two roles that can both request and approve:
- A `system_owner` can request an L4 action on a system they own and is also in `APPROVER_ROLES`. The roles do not separate the two acts for that person. The self-approval rule (ADR-0016, `allow_self_approval`, `false` by default) is what separates them: the approver must not be the requester.
- That rule is in the approvals module, which is planned (M2) and not in `src` yet. No code reads `allow_self_approval` today. Until the module exists the routing above is a decision record for the policy engine's output (`required_approver_roles`), and nothing consumes it.
- The approvals module is also meant to refuse an approver whose credential the requester issued (`Principal.credential_issued_by`, ADR-0004), because an administrator can mint a token for another person in this identity model.

Risk class labels:
- The default ruleset defines `low`, `medium` and `high` (`risk_classes`). They are labels, not a scale. They carry no numeric value, no ordering that the engine uses and no formula. BP OD-11 and register item ADR-016 stay open.
- An envelope must carry one of the labels the loaded ruleset defines; an unknown label is rejected. A rule may match on `risk_classes`, and a rule that names a label the ruleset does not define fails the load.
- No default rule uses `risk_classes`. The labels change no decision today. They exist so that a rule can later hold or require approval by label, and so that every envelope states a class.
- A different ruleset may define different labels. Nothing in `src` names a label other than through the loaded ruleset.

Weaknesses of this default:
- The routing is a choice the blueprint left open. It has not been put to the owner. Where it differs from what the company wants, the Phase 0 routing table (`docs/phase0/role-and-approver-template.md`) is the place to say so.
- Two lists must agree: `APPROVER_ROLES` and the roles whose template carries `approval.decide`. No test ties them together, so one can be changed without the other.
- `ExternalInferenceSettings` accepts `security_admin`, `system_owner` or `executive_risk_owner` as the external-inference approver (`src/ciso/app/settings.py`). `security_admin` is not an approver anywhere else. The setting is unset by default and the path is not built, but the two rules disagree until OD-14 is answered.
- An administrator can mint a token for any human, including an approver (ADR-0004), then request as themselves and approve as that person. The credential-issuer check closes this only once the approvals module exists.
- In a one-person company the same person holds all three roles. With the default self-approval rule that person cannot get a human-initiated L4 action approved, and can still have the agent propose one and then approve it (ADR-0016).
- No role is named for L3 playbook authorization, for a deeper test plan, for a connector scope change or for access to raw customer content. The default gives no role the right to approve them, so each is blocked until a role is chosen. L3 is blocked anyway: the policy context reports no playbook, and none ships (OD-15).
- Discovery scope approval by `system_owner` alone leaves a system without an owner unable to have a scope approved, and a scope that spans several systems needs several owners. Neither case is handled.
- The approver's grant is meant to reach the target (a scoped `system_owner` approves only their own system). That check belongs to the approvals module and is not built.
- Risk labels with no semantics can give a false sense of classification. A reader may treat `high` as a measured level when it is a name.
- The API's route permissions do not yet take grant scopes into account, so a scoped `system_owner` passes a route check on the role alone. That change is in progress.

## Why this default is reversible
Seams: `APPROVER_ROLES` in `ciso.common.enums`, the `approval.decide`, `scope.approve` and `risk.accept` entries in the role templates (`ciso.identity.roles`), and the ruleset file. To change who approves, edit the role template and `APPROVER_ROLES` together, change the `approver_roles` of the rules, and update the Phase 0 routing table. To route by label, add `risk_classes` conditions to rules. To replace the labels with the company's, change `risk_classes` in the ruleset; no code names a label. No stored approval record depends on the labels or the role list, because none exists yet.

## Evidence needed to make this final
- The filled approval routing table from Phase 0 (`docs/phase0/role-and-approver-template.md`): the approving role and the second human for each approval.
- Who the system owners are, system by system, and whether any person holds all three roles.
- OD-11 answered with the risk methodology; only then can the labels get a meaning or be replaced.
- OD-14 (external inference approver) and OD-15 (L3 playbook authorization), because both reuse this routing.
- The owner's decision on self-approval (ADR-0016) and on whether an administrator may mint tokens for other people (ADR-0004).
- A test that ties `APPROVER_ROLES` to the role templates, once the owner confirms the roles.

## Consequences
- The engine states, for each L4 request, which approver roles apply and who may have filed it, and rejects a ruleset that tries to widen either list.
- Until the approvals module exists nobody can approve anything; an L4 request ends as `require_approval` with the roles named.
- Policy, approval and identity tests must keep covering the requester-equals-approver and multi-role cases (BP §19.3).
- Changing `APPROVER_ROLES`, a role template or the ruleset changes who can authorize high-impact actions, and should itself be a recorded, reviewed change.
