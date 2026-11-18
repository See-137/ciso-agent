# M1 review: policy and identity

Saved verbatim from the reviewing agent's report, 2026-11-17. Findings are tracked in
`docs/plan/followups.md`. Probe scripts named here lived in a session scratchpad and may be gone.

---

I found 2 critical, 4 high, 8 medium and 5 low problems. 21 of the 22 findings are proven by probe scripts; the bootstrap race is from reading only. I didn't edit any repo files; the probes and the mutation plugin are under the scratchpad. Your baseline `uv run pytest tests/policy tests/identity` is green.

Probe scripts, run from `C:\Users\<user>\Desktop\Projects\CISO_AG` with `uv run python <script>`:
- `C:\Users\<user>\AppData\Local\Temp\claude\89363c7559032d42\1304fad4-2155-48c0-8a06-85e7efb17aae\scratchpad\sec_probe_policy.py`
- `C:\Users\<user>\AppData\Local\Temp\claude\89363c7559032d42\1304fad4-2155-48c0-8a06-85e7efb17aae\scratchpad\sec_probe_identity.py`
- `C:\Users\<user>\AppData\Local\Temp\claude\89363c7559032d42\1304fad4-2155-48c0-8a06-85e7efb17aae\scratchpad\sec_probe_loader.py`
- `C:\Users\<user>\AppData\Local\Temp\claude\89363c7559032d42\1304fad4-2155-48c0-8a06-85e7efb17aae\scratchpad\sec_probe_family.py`
- Mutation plugin: `C:\Users\<user>\AppData\Local\Temp\claude\89363c7559032d42\1304fad4-2155-48c0-8a06-85e7efb17aae\scratchpad\sec_mut.py`

---

## CRITICAL

**C1. The engine's own scope check never fires for a principal built by identity (PROVEN)**
- **Where:** `src/ciso/policy/engine.py:54-60` and `:321-328`, against `src/ciso/identity/roles.py:7-9` and `:166-178`.
- **What happens:** Identity writes scopes as `<role>.<n>.<attribute>`, for example `{"system_owner.0.system": {"app:payroll"}}`. The engine only knows the keys `system`, `resource`, `tenant`, `environment` and `boundary`, and silently skips any other key.
- **Probe:** a system_owner scoped to `app:payroll` sends `ticket.create_draft` (an L2 write) against `app:billing`:
  - `allow ['rule_allow']`
  - The same owner with the flat key the tests use: `deny ['out_of_scope']`
  - A key spelled `System`: `allow`
- **Also:**
  - The docstring at `context.py:38-39` says "The engine also checks the principal's own attribute scopes". For real principals that is false.
  - The `classification` attribute has no matching envelope field at all.
  - The engine's check ignores which role the scope belongs to.
- **Fix:**
  - Have the engine call `scope_matches(principal, role, ...)` for each role that a matching allow or require_approval rule depends on.
  - Turn unknown scope keys into a deny, not a skip.
  - Give the envelope a classification field, or deny when a scope narrows classification and nothing can be compared.
  - Delete the flat-key code path.

**C2. The engine trusts the Principal written inside the envelope (PROVEN)**
- **Where:** `envelope.py:98`, `engine.py:135-136` and `:156-163`.
- **What happens:** `authenticated_actor` is just data in the request. Nothing ties it to a token or to the identity tables:
  - `actor_is_active(actor_id)` checks the id only. It ignores type, roles and scopes.
  - The protected-operation invariant reads `actor_type` straight from the request.
- **Probe:** the agent `agent_ciso` sends `policy.update_rule` with the actor written as a human `security_admin`:
  - Real agent: `deny ['protected_operation']`
  - Same id, written as human: `require_approval ['rule_require_approval']`
  - An agent can also send `scopes={}` to remove all narrowing.
- **Docstring:** `envelope.py:158-160` says roles are "checked live at evaluation and execution time (G12)". The engine only reads the snapshot in the request.
- **Severity:** I rated this critical because the envelope sits downstream of model proposals. If no code path lets model output fill `authenticated_actor`, it drops to high. You decide.
- **Fix:**
  - `evaluate()` takes an `actor_id` from the authenticated request context and rebuilds the Principal from identity (`principal_for`) at evaluation time.
  - It denies if the type, roles or scopes in the envelope differ from the rebuilt one, or drops the roles and scopes from the envelope entirely.

## HIGH

**H1. Claiming L4 for an L3 operation skips the playbook gate (PROVEN)**
- **Where:** `engine.py:169`, which tests `checked.authority_level is L3_EXECUTE`. The level used there is `max(claimed, catalog)`.
- **Probe:** an agent sends `playbook.rotate_key` with no playbook:
  - At L3: `deny ['playbook_not_active']`
  - Claimed as L4: `require_approval approvers=['security_admin','system_owner']`
  - `playbook_status` was never consulted.
- **Impact:** one human click runs an L3 operation that blueprint 9.2 / OD-15 says is disabled until a playbook is approved.
- **Fix:** test `checked.spec.authority_level >= L3_EXECUTE` (the catalog's level, not the claimed one). Add a regression test for the overstated case.

**H2. IdentityService and Authenticator accept forged or stale Principal objects (PROVEN)**
- **Where:** `service.py:81-82` and `:242-245`, `authn.py:220` and `:252`.
- **Probe:**
  - A made-up `Principal(actor_id="nobody", HUMAN, {security_admin})` creates an actor: `OK`.
  - The first admin is disabled (`principal_for` now returns `None`), yet that admin's cached Principal still assigns `security_admin` to another actor: `OK`.
- **Tests:** they depend on this. The `admin` fixture in `tests/conftest.py` is not a row in the database.
- **Fix:** every privileged method re-resolves `by.actor_id` through `principal_for()` inside its transaction and refuses unless the result is a current, active, human `security_admin`. Better: require a sealed capability that only the Authenticator can issue.

**H3. Bootstrap reopens by itself and has no caller check (PROVEN; mutation survived)**
- **Where:** `authn.py:337-357` and `service.py:206-215`.
- **Probe:**
  - The admin revokes its own `security_admin` role, then `bootstrap_first_admin("Mallory")` returns `OK`.
  - A temporary admin whose validity window has passed, with the original admin disabled: two hours later bootstrap returns `OK` with no human action.
- **ADR:** ADR-0004 lists the reopening as a known weakness. What it does not show is the timer-driven path, and that no test covers it.
- **Mutation:** making `active_admin_exists` ignore revocation and the validity window passed every test in `tests/policy` and `tests/identity`. `test_bootstrap_reopens_only_when_no_active_admin_remains` (`test_authn.py:291`) only exercises the disable path.
- **Fix:**
  - Refuse to revoke, disable or let lapse the last current human admin.
  - Gate bootstrap behind a host-only one-time secret or a file on disk.
  - Add tests for the revoke and window-lapse paths.

**H4. The control-plane name list is a denylist with gaps (PROVEN)**
- **Where:** `catalog.py:24-36`.
- **Probe:** each of these registers as an *unprotected* write:
  - `identity.role.assign` (identity's own audit verbs are `identity.*`)
  - `approvals.decide`
  - `playbook.enable`
  - `finding.suppress`
  - `audit_log.purge`
  - `policies.update`
  - `role.assign`
- **Impact:** the default rules allow agents at L2 (`allow-l2-nonhuman`), so any such operation registered at L2 is agent-allowed. Blueprint 9.2 explicitly forbids letting the model suppress findings or change approvers.
- **Fix:**
  - Add the families `identity`, `approval(s)`, `playbook(s)`, `connector`, `model`, plural and singular forms, and finding-suppression verbs.
  - Better: invert it. A non-human may only request operations marked `agent_requestable=True`.

## MEDIUM

**M1. Mutable dicts inside "frozen" models (PROVEN)**
- **Where:** `principal.py:22` (`scopes: dict`) and `envelope.py:102` (`arguments: dict`).
- **Probe:**
  - `env.authenticated_actor.scopes.clear()` turned `deny ['out_of_scope']` into `allow`, and the envelope hash did not change (scopes are excluded from it).
  - Mutating `arguments` in place does change the hash, so it is caught only if the executor recomputes the hash.
- **Fix:** use `Mapping` / `MappingProxyType` with a frozen validator. For arguments, store canonical JSON text and parse it on read.

**M2. Re-enabling an actor brings back every old token (PROVEN)**
- **Where:** `service.py:289-294`.
- **Probe:**
  - Old token while the actor is disabled: `AuthenticationError`
  - Same token after `enable_actor`: `OK`
- **Impact:** disabling is the usual response to a compromise, and the stolen token comes back with the account.
- **Fix:** revoke all of the actor's tokens when it is disabled, in the same transaction.

**M3. A scoped `security_admin` is a full admin (PROVEN)**
- **Where:** `service.py:81-82`, where `is_human_admin` ignores scope.
- **Probe:** an admin scoped to `development` grants itself an unscoped `system_owner` role: `OK`. `active_admin_exists` also counts scoped admins.
- **Fix:** refuse a scope on `security_admin`, or make identity management require an unscoped grant.

**M4. An admin can mint tokens for any human, including approvers (PROVEN)**
- **Where:** `authn.py:212-239`.
- **Probe:** the admin issues a token to a `system_owner` and authenticates as that owner: `OK`.
- **Impact:** this gets around the G33 self-approval ban: request as yourself, approve as the owner whose token you minted.
- **Fix:**
  - Refuse to issue tokens to actors holding approver or admin roles other than yourself, or require a second admin.
  - At minimum, have the approvals module refuse an approver whose token was issued by the requester.

**M5. Approver roles are a union, and auditor counts as an approver (PROVEN)**
- **Where:** `engine.py:211-213` and `rules.py:121`.
- **Probe:** two matching require_approval rules gave `approvers=['auditor','security_admin']`. A broader rule *widens* who can approve, while every other merge in the engine picks the strictest result.
- **Also:** `auditor` and `executive_risk_owner` both load as L4 approvers, but `auditor` is read-only under blueprint 9.3, and `roles.py:116` gives it no `approval.decide`.
- **Fix:**
  - Take the intersection of approver roles, or require one approver from each rule.
  - Limit `approver_roles` to roles whose template has `approval.decide`.

**M6. An L0/L1 allow rule needs no requester gate, and that includes writes (PROVEN)**
- **Where:** `rules.py:136-138`.
- **Probe:** `{"effect":"allow","match":{"authority_levels":[0,1]}}` loads, and an `employee` performing an L1 *write* gets `allow`.
- **Fix:** apply the gate whenever `writes` is not `false`, not only at L2 and above.

**M7. A stored `scope_json` key the code doesn't recognise removes the scope (PROVEN)**
- **Where:** `service.py:138-144`.
- **Probe:** a hand edit to `{"systems": [...]}` changed the principal's scopes from `{'system_owner.0.system': ...}` to `{}`, i.e. unscoped.
- **Why it matters:** ADR-0004's lockout recovery is "a manual change to the database".
- **Fix:** validate `scope_json` against a closed model and raise `IntegrityFailure` on unknown keys or non-list values.

**M8. Docstrings promise more than the code does**
- `engine.py:16` ("Every evaluation is audited"), `context.py:38`, `envelope.py:158-160` (G12) and `roles.py:9` ("never by hand", while the engine reads it by hand).
- Each is shown false by C1, C2 or L2.

## LOW

**L1. Truthy answers from the context count as yes (PROVEN)**
- **Where:** `engine.py:157`, `:162`, `:165`.
- **Probe:** `actor_is_active` returning `"disabled"` and `is_within_scope` returning `[False]` gave `allow`.
- **Fix:** require `is True`.

**L2. Some errors escape `evaluate()` with no decision and no audit record (PROVEN)**
- **Where:** `engine.py:118-121` and `:229-233`.
- **Probe:** each of these raised an exception and wrote 0 audit events:
  - A lone surrogate in the arguments: `UnicodeEncodeError` from `envelope_hash`
  - `fact_freshness` returning a list: `AttributeError`, because `.get` sits outside `_ask`
  - A clock that raises: `OSError`
- **Impact:** this still fails closed (an exception, not an allow), but nothing is audited.
- **Fix:** catch everything in `evaluate()`, return a deny with a reason code, and attempt the audit write. Also reject non-UTF-8-encodable strings at validation.

**L3. A token with a trailing newline is accepted (PROVEN)**
- **Where:** `authn.py:54`. In Python regexes, `$` also matches just before a final newline.
- **Probe:** `token + LF` authenticated: `OK`.
- **Fix:** use `\Z` or `re.fullmatch`.

**L4. The loader's strict mode still coerces values (PROVEN)**
- **Probe:**
  - `"authority_levels": [true]` loads as L1.
  - `4.0` loads as L4.
  - `"schema_version": 1.0` is accepted.
- **Impact:** the same meaning can be written in ways that hash differently, and a reviewer may misread them.
- **Fix:** add a `BeforeValidator` that refuses `bool` and `float`.

**L5. Bootstrap race (READING ONLY)**
- **Where:** `authn.py:346-375`.
- **What happens:** check-then-insert with no unique constraint. Safety relies on SQLite's single-writer locking and would break on another database.
- **Fix:** add a guard row or a unique partial index.

**Info**
- A UTF-8 BOM makes the ruleset deny-all. That fails closed, but PowerShell 5.1's `-Encoding utf8` writes one.
- In `fnmatchcase`, `*` also matches dots: `ticket*` matches `tickets_admin.purge`.
- `playbook_status(operation)` is keyed by operation only, so the playbook's target scope, rate and expiry per target aren't bound to the envelope.
- If the audit write fails for a read, the allow stands. That is a documented design choice, but it contradicts `engine.py:16`.

## Tests that cannot catch the bug

- **`test_escalation.py:269-318`** (`test_attribute_scope_is_enforced`, `test_multi_role_holder_outside_attribute_scope_is_denied`): they build principals with flat keys that identity never produces, so they pass while C1 is live. Fix: build the principal through `IdentityService`.
- **The bootstrap closure test** (`test_authn.py:291`): the `admin_ignores_window` mutation survived. See H3.
- **No test sends an L3 operation with a claimed L4.** Changing the check to `is` or `>=` makes no difference to the suite. See H1.
- **No test pins checking the secret before revoked, expired or disabled state.** Today's order is correct, but moving the state checks ahead of the secret check would fail no test.
- **Identity tests use a forged `admin` Principal** (`tests/conftest.py`), which writes H2 into the tests as expected behaviour.
- **Control mutations:** removing the evidence requirement, removing the TTL cap and making the validity-window end inclusive were all caught (one failing test each).

## What I checked and found sound

- **Tokens:** 256-bit secret from `token_urlsafe`, 16-byte salt per credential, cost parameters stored per row, `hmac.compare_digest`.
- **Failure handling:** one error message for every failure cause; the secret is verified before any state is revealed; a dummy scrypt runs on the malformed and unknown-id paths; tokens never appear in logs or audit records (test present); expiry uses `>=`.
- **Human-only roles** are enforced in three places: at assignment, in `build_principal`, and in the `Principal` model.
- **Identity writes** run in the same transaction as their audit record and roll back if the audit write fails.
- **Loader:** duplicate keys, unknown keys and schema errors all give deny-all.
- **Engine rules:** the strictest effect wins; L4 is never a plain allow; an understated level is denied; an unknown operation is denied; arguments are validated strictly against a closed schema.
- **Envelope hash:** covers `request_id`, the claimed level and the expiry, so two requests can't share a hash. Excluding roles and scopes is deliberate, but it is safe only once C2 is fixed.

## Verdict

- **Fix before anything is built on this:** C1, C2, H1, H2. Each one lets the engine allow, or route to a single click, something it should deny.
- **Fix soon:**
  - Before any network exposure: H3, H4.
  - Then: M1-M7, plus the tests above, especially rewriting the scope tests to go through `IdentityService` and adding the L3-overstated and bootstrap-lapse cases.
- **Sound:** the token cryptography, loader strictness, rule precedence and the human-only role layering.

2 critical, 4 high, 8 medium findings (plus 5 low, 4 info).
