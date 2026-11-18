# Follow-ups

The coordinator's working list. One row per finding that is not yet fixed and verified.
Status: `open`, `assigned` (a builder has it), `fixed` (change made, test named),
`verified` (coordinator ran the test and a mutation), `wontfix` (reason given),
`owner` (needs the owner's decision; an ADR states it).

Sources: `ADR` = the ADR writer's code read on 2026-11-17, `SEC` = automated commit
review, `B-x` = builder x's own report, `REV-n` = independent review n.

Statuses below were set on 2026-11-18 by reading the code and the tests in the tree. The
tests were not run for this update, and no row is `verified`: that status is the
coordinator's after a gate.

## M1 findings

| # | Finding | Source | Owner of fix | Status |
|---|---|---|---|---|
| F1 | Policy engine ignored per-role scopes: identity packed them into keys like `system_owner.0.system`, the engine only read flat keys, so a scoped role was not narrowed. Fail-open. Now identity builds one `RoleGrant` per assignment and the engine decides each rule's `required_roles` through `Principal.covering_roles`. | ADR | coordinator (contract), then policy and identity lanes | fixed: `tests/policy/test_escalation.py` (scoped owner on another system denied, two grants do not mix, classification narrowing, unknown attribute), `tests/identity/test_roles.py` (TestScope), `tests/unit/test_common.py`. Both sides use the same `RoleGrant` shape, but no single test goes from `IdentityService` through the engine |
| F2 | A sole admin was locked out when their token expired. Now the host-local command `python -m ciso.app.admin recover-token` (`HostLocalAdmin.recover_admin_token`) issues a new token to an existing active human administrator, audited with operator and reason. | ADR | identity lane | fixed: `tests/identity/test_hostlocal.py` (TestRecovery), `tests/app/test_admin.py` |
| F3 | Bootstrap reopened when the last admin was disabled, lost the role, or the assignment expired; nothing prevented removing the last admin; bootstrap took no credential. Now bootstrap works once per database, ever (assignment history plus a single-row marker), the last active admin cannot be disabled or lose the role, and bootstrap is host-local only. Bootstrap still takes no credential: host access is the control (ADR-0004). | ADR, B-C | identity lane | fixed: `tests/identity/test_hostlocal.py` (TestBootstrap: refused after revoke, disable and window lapse; marker alone blocks), `tests/identity/test_roles.py` (TestLastAdmin, TestAdminGrantShape), `tests/api/test_host_local_unreachable.py` |
| F4 | Audit: an empty log with no anchor accepted appends, so wiping both files looked like a fresh install. Now the log has an id created by an explicit `initialise()`, the composition root remembers it and never re-initialises a wiped log. If the operational database that remembers the id is wiped as well, nothing remembers it (ADR-0013). | ADR | audit lane, plus start-up check | fixed: `tests/audit/test_identity.py`, `tests/app/test_container.py` (`test_wiped_audit_database_is_not_reinitialised`) |
| F5 | Audit: the anchor was written before the commit, so a crash or a failed COMMIT left the log refusing appends with no recovery. Now two-phase anchor with automatic recovery of the two crash signatures, recorded as `audit.anchor_recovered`. A crash during `initialise()` is not covered (in progress). | B-A, ADR | audit lane (two-phase anchor) | fixed: `tests/audit/test_recovery.py` |
| F6 | Audit: replacing the database and anchor with an older matching pair verifies ok. Inherent without anchoring off the host. An optional signed head witness now exists in `ciso.audit.witness` and detects this up to its last published head (`tests/audit/test_witness.py`, `tests/audit/test_second_review.py`). The composition root does not wire it yet (in progress), and where it lives is the owner's decision (ADR-0013). | ADR | document in ADR-0013; owner decision on external anchoring | owner |
| F7 | A log that refuses appends locked everyone out, because authentication failed when its audit write failed. Now a valid token still authenticates when the audit write fails (logged and counted); state changes still audit first and stop. | ADR | identity lane | fixed: `tests/identity/test_authn.py` (`test_refusing_audit_log_does_not_lock_out_a_valid_token`), `tests/api/test_auth_system.py` (TestDegradedApi) |
| F8 | Unknown or malformed tokens each caused an audit append and an scrypt hash. Now they write no audit record (logged and counted) and the API charges the client address before authentication. A refusal against a real token id is still audited. | ADR | identity lane (no append for unknown tokens), API lane (limit before auth) | fixed: `tests/identity/test_authn.py` (`test_every_failure_raises_the_same_error`), `tests/api/test_auth_system.py` (`test_bad_token_burst_is_limited_before_authentication`) |
| F9 | L4 approver roles disagreed: permissions gave `approval.decide` to system_owner and executive_risk_owner; the default ruleset named security_admin and system_owner. Now `APPROVER_ROLES` is system_owner and executive_risk_owner, the loader refuses any other approver role, and ADR-0021 records the routing. No test ties `APPROVER_ROLES` to the roles whose template holds `approval.decide`. | ADR | coordinator decision, then policy and identity lanes; ADR-0021 | fixed: `tests/policy/test_engine_defaults.py` (L4 approvers), `tests/policy/test_loader.py` (approver roles outside the set give deny-all) |
| F10 | Risk class labels (`low`, `medium`, `high`) shipped in the default ruleset with no ADR (gap G25 requires one). Now ADR-0021 records them as provisional labels with no scale. | ADR | ADR-0021 | fixed: ADR-0021; `tests/policy/test_loader.py`, `tests/policy/test_envelope.py` (`test_unknown_risk_class_is_rejected`) |
| F11 | `inference_timeout_seconds` was checked after the provider returned; a hung provider hung the caller. Now the gateway enforces a deadline on a worker thread and refuses new work while too many abandoned calls remain. | ADR | inference lane | fixed: `tests/inference/test_gateway.py` (TestDeadline) |
| F12 | Kill switch: `release` did not wait for owed engage audit records, so the log could show a release before its engage. Now release delivers what is owed and refuses if anything is still owed. | ADR | kill-switch lane | fixed: `tests/killswitch/test_killswitch.py` (`test_release_refuses_while_an_engage_audit_is_owed`, `test_release_delivers_the_owed_engage_first`) |
| F13 | Kill switch: restoring a backup reverts a later engage. The restore report always warns and a test checks the warning (`tests/resilience/test_backup_restore.py`), but the revert itself is not prevented, start-up `reconcile()` cannot see it (the restored audit log is old too), and the runbook the fix called for does not exist. | ADR | ops lane (restore report warns; runbook) | open: runbook missing |
| F14 | Queue: jobs behind a dead-lettered job with the same ordering key proceeded, so a replay applied an old event after newer ones. Now a dead job blocks its key until replayed or discarded. | ADR | queue lane | fixed: `tests/workflows/test_queue.py` (`test_dead_job_blocks_its_ordering_key_until_replay`), `tests/resilience/test_queue_recovery.py` (`test_dead_job_still_blocks_its_key_after_restart`) |
| F15 | Queue: no test with two workers leasing at once against a file database. | B-EF | review 3 is probing it; queue lane | fixed: `tests/resilience/test_queue_recovery.py` (`test_several_engines_on_one_file_lease_every_job_exactly_once`) |
| F16 | Health checks had no time limit; a hung check hung the aggregate. Now each check has a limit from settings and a hung check reads `unknown`. | B-EF, ADR | observability lane | fixed: `tests/observability/test_observability.py` (`test_hung_check_is_unknown_and_aggregate_returns_on_time`) |
| F17 | `IdentityService` required a classification scheme; default settings have none. Now the scheme is optional. | ADR | identity lane | fixed: `tests/identity/test_roles.py` (TestNoClassificationScheme), `tests/app/test_container.py` |
| F18 | Identity: the audit-failure path had no proven test (the builder's mutation landed in dead code). Now attempt-audit and result-audit failures each have a test for create, assign, issue and bootstrap. Mutation results are the coordinator's gate. | B-C | identity lane | fixed: `tests/identity/test_roles.py`, `tests/identity/test_authn.py`, `tests/identity/test_hostlocal.py` |
| F19 | No `ANONYMOUS` actor type: failed logins were recorded as `service` in one place and `human` in another. Now `ActorType.ANONYMOUS` labels refused sign-ins and can never hold a role. | B-C, ADR | coordinator (contract), identity lane | fixed: `tests/unit/test_common.py` (`test_anonymous_actor_holds_nothing`), `tests/identity/test_authn.py`, `tests/policy/test_envelope.py` |
| F20 | `ExternalInferenceSettings` accepted `auditor` as the approver role. Now refused. Note: it still accepts `security_admin`, which is not an approver anywhere else (ADR-0021); the owner decides under OD-14. | ADR | coordinator | fixed: `tests/app/test_settings.py` (`test_external_approver_cannot_be_the_read_only_auditor`) |
| F21 | FastAPI documentation pages were unauthenticated and loaded scripts from a public CDN by default. Now off; the OpenAPI document is served at `/v1/openapi.json` to an authenticated caller. | ADR | API lane | fixed: `tests/api/test_auth_system.py` (`test_openapi_needs_authentication`) |
| F22 | A ruleset that fails to load denies reads too. Stricter than blueprint 9.5. Human reads go through API route permissions, not the engine, so observation by people continues; agent-initiated reads stop. | ADR | wontfix: keep deny-all; ADR-0009 states it (`tests/policy/test_engine_defaults.py`, `test_deny_all_ruleset_denies_reads_and_writes`) | wontfix |
| F23 | Blueprint 12.1 lists an administration console as a required logical capability; this build is API-only (decision G28). The API is built (ADR-0012); there is still no console. | ADR | owner; consider a framework-free console in M6 | owner |
| F24 | Self-approval rule compares actors, not people: an admin can have the agent propose and then approve. The approvals module that enforces the rule (and the check against an approver whose credential the requester issued) is not built; `allow_self_approval` has no reader yet. | ADR | owner (ADR-0016, ADR-0021) | owner |
| F25 | `verify()` held the audit write lock for the whole walk. Now it walks a read snapshot and takes the lock briefly. | B-A | audit lane: note only until the log is large | fixed: `tests/audit/test_concurrent_verify.py` |
| F26 | Inference: "prompt body never stored" was proven for the database and only spot-checked for audit details; no mutation checks were run by the builder. Now tests cover the database file bytes, the audit details and exception chains. The audit-details test checks the input marker only, not an output marker. Mutation checks are the coordinator's gate. | B-G | inference lane, coordinator mutation at gate | fixed: `tests/inference/test_gateway_records.py` |
| F27 | Kill switch: if the database commit failed after the audit accepted a release, the audit said released while the flag stayed engaged. The code now changes the flags first and audits the success after (`ciso.killswitch.service`, `release`), writing a failed record if the change fails. No test makes the change fail and checks that no success record exists and a failed one does. | B-BD | kill-switch lane (note; safe direction) | open: no test for the failed-change branch (`src/ciso/killswitch/service.py:238`) |
| F28 | Policy: `default.json` is located through `Path(__file__)`; not checked that it is included in a built wheel. Same for inference prompts and manifest. `pyproject.toml` lists `packages = ["src/ciso"]`, and nothing builds a wheel or lists its contents. | B-H | coordinator at the clean-clone gate | open: no wheel build or content check exists |

## M1 review round (2026-11-17)

Three independent reviews and the ADR writer's code read are saved in `docs/reviews/`.
Work resumed on 2026-11-18; the statuses below were set from the code and tests in the
tree, were not run for this update, and none is verified at a gate.

Every finding in them is assigned to the lane that owns the code; the rows above marked
`open` that belong to a lane are part of the same fix round. Status of the round:

| Lane | Review items | Status |
|---|---|---|
| policy | C1 scope check, C2 actor trusted from the request, H1 playbook gate, H4 protected-operation list, M1, M5, M6, M8, L1, L2, L4, loader robustness, pattern matching, playbook scope | fixed, each with a test in `tests/policy/`: C1 and playbook scope in `test_escalation.py` and `test_engine_defaults.py`; C2 (`test_actor_is_resolved_at_every_evaluation`, `test_claimed_type_must_match_resolved_type`); H1 (`test_l3_claimed_as_l4_still_needs_its_playbook`); H4 (`agent_requestable`, `test_envelope.py` protected names); M1 (`test_arguments_cannot_be_mutated_in_place`); M5 (`test_approver_roles_are_the_intersection`); M6 (`test_loader.py`, ungated rules); L1 (`test_truthy_scope_answer_is_no`); L2 (`test_clock_failure_is_a_deny_with_audit`); L4 and loader robustness (`test_loader.py`); pattern matching (`test_operation_pattern_star_stays_in_its_segment`). Not gated |
| identity | H2 forged principal, H3 bootstrap, M2, M3, M4, M7, L3, L5, lockout recovery, audit ordering, unknown-token audit, optional classification | fixed, with tests in `tests/identity/`: H2 (TestCallerIsReresolved), H3 and L5 (`test_hostlocal.py`), M2 (`test_disable_revokes_every_token_and_enable_restores_none`), M3 (TestAdminGrantShape), M7 (TestStoredScopeIsValidated), L3 (trailing newline case in `test_every_failure_raises_the_same_error`), lockout recovery, unknown-token audit, optional classification. M4 (an administrator can mint a token for another person): the issuer is recorded and put on the principal (`test_valid_token_gives_that_actors_principal_and_issuer`); the approvals module that would refuse such an approver is not built, and the owner decides whether minting stays allowed. Not gated |
| audit | engine change, two-phase anchor, log id and initialise, verify without the write lock, Windows replace, witness (C1), M1, M2, M8, L1, L6 | fixed, with tests in `tests/audit/`: two-phase anchor (`test_recovery.py`), log id (`test_identity.py`), verify without the lock (`test_concurrent_verify.py`), Windows replace (`test_anchor.py`, retries while another handle holds the anchor), witness (`test_witness.py`, `test_second_review.py`), M1 (`test_append_verify.py`, non-JSON details refused), M2 (`test_tamper.py`), M8 (`test_anchor.py`), L1, L6 (`test_anchor.py`, key mismatch). Open and in progress: the witness is not wired into the composition root; recovery from a crash during `initialise()` and from a torn witness line. Whether the mutations that were cut off have been run is not recorded in the tree; they belong to the gate. Not gated |
| kill switch | H2 outbox forgery, H3 flag integrity and initialise, H4 lock across audit, M3, M4, L4, L5 | fixed, with tests in `tests/killswitch/`: H2 and M3 (`test_outbox.py`), H3 (`test_killswitch.py`: forged MAC, deleted row, initialise with history), H4 (`test_audit_sink_is_never_called_under_the_write_lock`), M4 (`test_breakglass.py`), L5 (`test_decision_uses_the_resolver_not_the_object_handed_in`). L4 is open as F27: no test for the failed-change branch. Not gated |
| inference | H5 timeout, M6 exception chain, M7 provider and model pin, L2, L3, audit ordering | fixed, with tests in `tests/inference/`: H5 (TestDeadline), M6 (TestExceptionHygiene, `test_parse_failure_traceback_carries_no_output`), M7 (`test_providers.py`, `test_manifest.py`), L2 (`test_malformed_response_is_a_recorded_failure`), L3 (`test_class_is_final_and_repr_shows_no_digest`, keyed digest tests; the container does not configure a digest key), audit ordering (TestAuditOrder). Not gated |
| queue, observability | guard results, renew, dedupe conflict, dead-letter blocking, resolver, concurrency tests, health timeout and race, logging coverage, metrics | fixed, with tests: `tests/workflows/test_queue.py` (guard results: `test_lost_guard_raises_conflict`; renew; dedupe conflict; dead-letter blocking; resolver), `tests/resilience/test_queue_recovery.py` (concurrency), `tests/observability/test_observability.py` (health timeout and race, non-propagating loggers, dropped records, series cap, label names, JSON snapshot), `tests/app/test_container_startup.py` (server loggers through the handler). A logging traceback fix is in progress. Not gated |
| coordinator | `BEGIN IMMEDIATE` engine, frozen mappings, `RoleGrant`, `PrincipalResolver`, `APPROVER_ROLES`, anonymous actor, settings (finite numbers, anchor and witness paths, kill-switch key, approver role) | fixed, tests in `tests/unit/test_common.py`, `tests/app/test_settings.py`; `BEGIN IMMEDIATE` is exercised through the two-engine tests in `tests/audit/test_append_verify.py` and `tests/killswitch/test_killswitch.py` (`create_db_engine` has no test of its own for it). Not mutation-checked at a gate |
| composition root, API, host-local commands, ops | `ciso.app`, `ciso.api`, `python -m ciso.app.admin`, `ciso.ops` | built, with tests in `tests/app/`, `tests/api/`, `tests/resilience/`. Open and in progress: audit witness wiring, route permissions taking grant scopes into account, minimum key length for every key, a logging traceback fix. Open, not in progress: the start-up sequence and integrity gate in `ciso.ops` (`startup`, `GatedKillSwitch`) are not called by the composition root. Not gated |

Cross-cutting rules that came out of the reviews (now part of every brief):

1. A `Principal` object is a snapshot. A component that decides a privilege resolves the
   actor id through `PrincipalResolver` and decides on the result.
2. Never call the audit sink while holding the operational database write lock. Audit an
   attempt, make the change in a short transaction, audit the result.
3. Dict and list fields on models that carry authority use `FrozenMap` / `FrozenJson` /
   tuples.
4. A guard is not done until a mutation of it turns a named test red.

`Principal.scopes` (the old flat form) is gone; one docstring in
`src/ciso/identity/store.py:271` still mentions it.

Owner decisions raised by the reviews:

- Where the audit anchor and the witness file live. The default anchor is
  `data_dir/anchor/audit-head.json`: outside the audit database's directory, which the log
  requires, but still under the data directory, so whoever can write that directory can roll
  both back (review C1). The witness has no default and is not wired. Readiness reports
  both. ADR-0013.
- Whether an administrator may mint tokens for other people in the bootstrap identity
  model (review M4). It is how the model works until an identity provider is chosen;
  approvals will refuse an approver whose credential the requester issued. ADR-0004.

## Decisions taken while fixing (written into ADR-0021)

- L4 approver roles follow blueprint 9.3: `system_owner` (within its scope) and
  `executive_risk_owner`. `security_admin` configures and may request, but does not
  approve. Provisional.
- Discovery scope approval: `system_owner` for the system concerned. Provisional.
- Risk class labels `low`, `medium`, `high` are provisional and carry no numeric scale.

## Later milestones (do not lose)

- M1, not finished: the witness wired into the composition root, route permissions that
  take grant scopes into account, a minimum key length for every key, a logging traceback
  fix, recovery from a torn witness line and from a crash during audit initialise (all in
  progress on 2026-11-18); the start-up sequence and integrity gate from `ciso.ops` called
  by the composition root; a test for the failed-change branch of kill-switch release
  (F27); a kill-switch restore runbook (F13); a wheel build check (F28); an end-to-end
  test from `IdentityService` through the policy engine (F1); a test tying `APPROVER_ROLES`
  to the roles that hold `approval.decide` (F9); then the gate: full suite in the tree and
  on a fresh clone, the disabled-guard search, one hand mutation per security-critical
  module, and the audit mutations that were cut off.
- M2: the approvals module (it enforces ADR-0016 and reads `allow_self_approval`); write
  credentials resolved through a kill-switch-checked accessor (G20).
- M6 (D6.1): ADR status pass; plan rows T1.3, T2.6, T3.2 wording.
- M6: mutation step for each milestone gate is recorded in `docs/definition-of-done.md`.
