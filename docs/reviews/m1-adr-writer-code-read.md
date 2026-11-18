# M1: findings from the ADR writer's code read

Saved verbatim from the reviewing agent's report, 2026-11-17. Findings are tracked in
`docs/plan/followups.md`. Probe scripts named here lived in a session scratchpad and may be gone.

---

The eight ADRs are brought in line, and ADR-0004, 0018 and 0020 are corrected against the code. Reading the code turned up one likely fail-open bug in scope enforcement and several gaps in the audit and identity recovery paths. Everything below comes from reading the code, not from running it, and all 20 ADRs still carry the exact Proposed status line.

## Files changed (all in `C:\Users\<user>\Desktop\Projects\CISO_AG\docs\adr\`)

Rewritten as agreed:
- `0003-evidence-storage.md`
- `0006-external-inference-gateway.md`
- `0007-queue-and-workflow-layer.md`
- `0010-execution-boundary.md`
- `0011-connector-framework.md`
- `0012-api-and-console.md`
- `0013-audit-integrity.md`
- `0014-backup-and-recovery.md`

Corrected against completed code:
- `0004-identity-bootstrap-model.md`
- `0018-kill-switch-semantics.md`
- `0020-observability.md`

Small edits:
- `0017-provisional-classification-labels.md`: notes that `IdentityService` requires a classification scheme.
- `0019-provisional-safety-parameters.md`: two knob descriptions corrected (token lifetime, inference timeout).
- `README.md`: titles for 0006, 0012 and 0013.
- `open-decisions.md`: rows OD-12, OD-14, OD-17 and the "Employee interface" register row.

Outside your list: `0009-policy-engine.md`. It pointed at `policies/*.json`, but the ruleset ships at `src/ciso/policy/rulesets/default.json` and the repo-root `policies/` is empty. I corrected the "Default chosen" paragraph and added two weaknesses. Say so if you want it reverted.

Not changed: ADR-0002, 0008 and 0016.

For modules not yet in `src` (evidence, approvals, execution, connectors, API, ops, `ciso.inference.external`), the ADRs say "planned, not yet in `src`" and follow `decisions.md` and the plan rows.

## Code findings, most serious first

1. **Role scopes from identity are ignored by the policy engine (fail-open).**
   - `identity/roles.py` `encode_scopes` builds keys like `system_owner.0.system`.
   - `policy/engine.py` `_outside_attribute_scope` only recognises flat keys (`system`, `environment`, …) and skips anything else.
   - A principal built by `IdentityService` is therefore never narrowed by the engine's own check; only `context.is_within_scope` remains, and nothing in `src` implements it yet.
   - `tests/policy/test_escalation.py:306` uses the flat form, which identity never produces, so the test can pass.
   - The docstring in `common/principal.py` describes the flat form and contradicts `roles.py`.

2. **A sole administrator is locked out when their token expires.**
   - `issue_token` needs an authenticated human `security_admin`, and bootstrap stays closed while an active admin exists.
   - The provisional lifetime in the file is 43200 seconds.
   - The only exit is a hand edit of the database; there is no host-local re-issue command.

3. **Bootstrap reopens more easily than "the only admin is disabled".** It also reopens when the admin role is revoked or the assignment's `valid_until` passes. Nothing stops the last admin being disabled or losing the role. `bootstrap_first_admin` takes no credential, so its exposure (API route or host-only) decides the risk.

4. **Audit anchor: three gaps beyond the builder's list.**
   - Rollback: replacing `audit.db` and the anchor with an older matching pair verifies `ok`. This needs file access only, not the key.
   - Wipe: an empty log with no anchor accepts appends (`_require_anchor_at_head` returns when `head_seq == 0`), and `verify()` is `ok` after the next append. Also file access only.
   - A failed `COMMIT`, not only a crash, leaves the anchor one ahead, because the anchor is written before the commit.

5. **A log that refuses appends locks everyone out.** `authenticate()` writes an audit record on success and on refusal and fails if that write fails. With no re-anchor tool, an anchor mismatch means nobody can sign in to investigate or to release the kill switch. Break-glass engage is the only thing that still works.

6. **Unauthenticated requests write audit records.** Every bad token appends to the audit log (with an fsynced anchor rewrite) and runs one scrypt. The API rate limit is the only brake, and the API is not built.

7. **Approval routing is decided in two places that disagree, and in no ADR.**
   - `identity/roles.py` gives `approval.decide` to `system_owner` and `executive_risk_owner`, not `security_admin`; `scope.approve` goes only to `system_owner`.
   - `rulesets/default.json` names `security_admin` and `system_owner` as L4 approvers.
   - The blueprint names no role for either.

8. **Risk class labels have no ADR.** `default.json` ships `"risk_classes": ["low", "medium", "high"]`. G25 (accepted as written) says the provisional scale goes in an ADR; none of 0001 to 0020 covers it.

9. **`inference_timeout_seconds` is not a timeout.** `gateway.py` compares the provider's self-reported `elapsed_seconds` after the call returns, so a hung provider hangs the caller.

10. **Kill switch.**
    - An engage needs a writable operational database. If the database is unreadable, capabilities read as blocked but nothing is stored, so the block ends when it returns.
    - Restoring a backup reverts any later engage.
    - `release` does not wait for owed engage records, so the log can show a release before its engage.
    - Outbox delivery is at-least-once, so duplicates are possible.
    - Nothing in `src` calls `retry_pending_audit()` or `initialise()` yet.
    - The break-glass operator name is typed text recorded as a human actor.
    - The credential accessor is not in the code.

11. **Queue ordering breaks after a dead-letter.** `_next_candidate` blocks only on earlier pending or leased jobs. Later jobs with the same `ordering_key` proceed past a dead one, and a replay then applies an old event after newer ones.

12. **Observability.**
    - Nothing outside the package increments a counter, registers a health check or calls `configure_logging`.
    - Health checks have no time limit.
    - Redaction covers only records reaching this one handler.
    - The dropped-record count is not surfaced.
    - The `metrics.py` docstring cites ADR-0015; it should be ADR-0020.

13. **A ruleset that fails to load denies reads too.** That is stricter than blueprint §9.5, which asks for fail-closed on writes, and it stops observation.

14. **No settings file means no classification scheme, but `IdentityService` requires one.** The "observes and refuses" default cannot construct identity as written.

15. **Blueprint §12.1 is not met.** It lists a security administration console as a required logical capability; G28 makes the build API-only. ADR-0012 states this as a deviation for the owner. FastAPI's built-in docs pages are unauthenticated and load scripts from a public CDN by default.

16. **Smaller items.**
    - `ExternalInferenceSettings` accepts `auditor` as approver role.
    - Unauthenticated attempts are audited as `service` in one place and `human` in another.
    - Plan rows T2.6 and T3.2 still say "restricted" although no label names exist in code.
    - Plan row T1.3 still shows `src/ciso/secrets/` paths.

`docs/phase0/role-and-approver-template.md` still lists discovery-scope and L4 approvers as "company decision", while the code now has defaults (finding 7). I can add a "current build default" column there if you want it.
