# ADR-0009: Policy engine (in-process, deterministic, versioned declarative rules)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (actor resolution, typed grants, agent_requestable, loader gate, approver intersection)
Blueprint refs: §5.1 #11, §9, §9.1, §9.2, §9.4, §9.5, §19.3 (policy/authorization tests), §19.4 #6, FR-023, FR-024, FR-027, NFR-005, NFR-017, OD-15

## Context
"The LLM is not a root of trust. Authorization is performed by a deterministic, independently administered policy engine and execution broker" (§9). The policy engine must be "a separate logical trust boundary from the LLM and its prompt context" (§9.5), must evaluate RBAC/ABAC, action classification, scoped authority and approval conditions (§5.1 #11), and must fail closed for write actions. L0-L2 are autonomous in scope, L3 is disabled until a playbook is threat-modeled, tested and approved, and L4 always needs human approval (§9.2). The BP does not select a policy technology.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| In-process deterministic engine evaluating versioned declarative rule files | Typed end to end; easy to test every rule; no extra service; a decision records the rule ids and policy version that produced it | A rule format of our own, with semantics we must specify and test; no ecosystem tooling | A logical boundary only: same process and OS identity as the orchestrator. Rule files are protected by repository and file permissions, not by a separate administrator |
| External policy service in its own process, with its own administrative identity | A real administrative boundary; policy can be changed and audited separately from application code | A service to run; a network or IPC hop on every decision; availability of that service gates all writes | Matches "independently administered" (§9); a compromised orchestrator cannot edit policy |
| A general-purpose policy language embedded as a library | Mature semantics and tooling; rules portable to a service later | A second language for a small team; typed integration with our envelope needs glue | Same process boundary as the default unless combined with a service |
| Rules written directly in application code | No format to design | Policy changes are code changes; no policy version separate from the release | Hard to review and to show to an auditor; rejected |

## Default chosen for the local build
`ciso.policy` (`engine.py`, `rules.py`, `loader.py`, `catalog.py`, `envelope.py`, `context.py`):
- `PolicyEngine.evaluate(envelope, context) -> PolicyDecision`. The decision is one of allow, deny, hold or require_approval, with reasons, matched rule ids, required approver roles, ruleset version, ruleset content hash, the envelope hash, the requester and the evaluation time. The result is a function of the envelope, the identity store's answers, the context's answers, the loaded ruleset and the clock. It never calls a model.
- An operation exists only if it is registered in the operation catalog, which fixes its authority level, whether it writes, whether it is protected and whether an agent or service may request it. There is no free-text command. The catalog, not the requester, says what level an operation needs; an understated level is denied.
- The actor is resolved from the identity store at every evaluation (`PrincipalResolver`, implemented by `IdentityService`). The envelope names its actor by id and claimed type only. It carries no roles and no scopes, and nothing the requester wrote about either is used. An actor that is unknown, disabled, of a different type than claimed, or that cannot be resolved is denied. A role revoked a moment ago stops counting at the next evaluation.
- Roles are typed grants. Each role assignment reaches the principal as a `RoleGrant` with its scope. A rule's `required_roles` is satisfied only by a role the principal holds through a grant that reaches the target's attributes (system, environment, classification), never by holding the role alone. Grants of one role are alternatives and do not mix attributes. A scoped grant never applies to a target whose attribute is unknown. The context's own scope answer (`is_within_scope`) is required as well.
- A non-human actor (agent or service) may request only operations the catalog marks `agent_requestable`; the default is false. A protected operation (control plane: policy, rules, identity, roles and assignments, approvals and approvers, playbooks, connectors, models, audit, kill switch, permissions, prompts, and any operation using a suppression verb such as suppress, dismiss, mute or waive) is denied for agents and services whatever a rule says, and the default ruleset denies it for humans too (`deny-control-plane-changes`). A protected operation can never be marked agent-requestable.
- Rules are versioned JSON data. The default ruleset ships inside the package (`src/ciso/policy/rulesets/default.json`). The loader refuses, and gives a deny-all ruleset for, a file that is missing, unreadable, not UTF-8, malformed, nested absurdly deep, has a repeated or unknown key, a duplicate rule id, a boolean or a float where an integer is meant, or any schema violation. A UTF-8 byte order mark is stripped. The reason is kept on the ruleset.
- The loader also refuses a rule that leaves the requester open: an `allow` or `require_approval` rule that can match a write, or anything at L2 or above, must name `actor_types`, and `required_roles` when humans are included. It refuses a `require_approval` rule with no approver roles, or with a role outside `APPROVER_ROLES` (ADR-0021).
- When several rules match, the strictest effect wins: deny, then hold, then require_approval, then allow. For require_approval, the approver roles are the intersection over the deciding rules. An empty intersection is a deny.
- Built-in invariants run before the rules and no rule can override them: unknown operation or invalid or expired envelope denied; an actor that cannot be resolved denied; an agent or service asking for a protected or non-requestable operation denied; target outside the approved scope, or a channel that is not approved, denied; an operation the catalog lists at L3 denied unless the context reports an approved, enabled, unexpired playbook for this operation and target scope; L4 never a plain allow; no matching rule denied; a context lookup that fails or answers with anything but exactly `True` denied. A write whose supporting facts are not all `current` becomes hold.
- Every evaluation attempts an audit record. If the record cannot be written, a writing operation is denied; a read keeps its decision and the failure is logged. Any other exception inside an evaluation becomes a deny with reason `internal_error`; if the audit write fails as well, `FailClosed` is raised.
- `ciso.policy` never imports inference, orchestration, the API or execution; a test enforces this.
- In the shipped composition root the engine is built with an empty operation catalog and a context whose every answer is the refusing one (no approved scope, no channel, no playbook, no fresh facts). Every request therefore ends as a deny today. The engine's behaviour is exercised by the tests, not by a running platform.

Weaknesses of this default:
- "Independently administered" (§9) is not met. Whoever can change the ruleset file in the installed package changes policy. Change control is code review in the repository.
- The default ruleset makes choices the BP leaves open: the L4 approver roles, who may request an L4 action, and the three risk class labels. They are recorded in ADR-0021, are provisional and have not been put to the owner.
- A ruleset that fails to load denies reads as well as writes, so a broken policy file also stops observation by agents and services. The BP requires fail-closed for writes (§9.5); stopping reads is stricter than that and costs visibility. Human reads go through the API's route permissions and not through the engine, so people can still look at the platform. This was kept on purpose (follow-up F22).
- Rule files are not signed. A modified file is detected only by review or by a hash comparison someone has to run.
- The import rule is a static test. It does not stop code in the same process from calling the engine's internals.
- The rule format's expressiveness for attribute conditions (resource, environment, sensitivity, action risk, time, scope; §9.3) is limited to what has been implemented and tested. The playbook lookup is keyed by operation and target scope; a playbook's rate and per-target expiry are not bound to the envelope.
- The engine trusts the context's answers when they are exactly `True`. A faulty context implementation that says yes too often would be believed. The registry, scope, channel and playbook sources do not exist yet.
- Operation patterns match segment by segment (`*` never crosses a dot), so a rule for `ticket.*` does not cover a three-segment name. A family with names of several depths needs one pattern per depth.

## Why this default is reversible
Seam: `PolicyEngine.evaluate`, with `ActionEnvelope` and `PolicyDecision` as plain data. The execution broker calls this one method immediately before execution and already treats "no decision" as denial. To switch: implement the same interface as a client of an external service, translate the rule files, and run the policy test class from BP §19.3 against it.

## Evidence needed to make this final
This ADR must be revisited before L3 is enabled.
- A threat model of policy tampering for the approved host and process layout (ADR-0010, ADR-0015).
- Who administers policy and who operates the orchestrator, from the Phase 0 role mapping. If they are the same person, the value of a separate service is lower.
- The conditions real L3 playbooks need (OD-15), to see whether the rule format can express them.
- Whether signed policy bundles or a two-person policy change are required by the obligations found in Phase 0 (OD-10).

## Consequences
- Deny-by-default policy tests can be written and run now (BP §19.4 #6).
- Policy files need protected branches and review in the repository until a stronger boundary exists.
- No L3 playbook may be enabled while this ADR is still at its default.
