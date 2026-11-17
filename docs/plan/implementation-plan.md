<!-- Written by the planner agent on 2026-11-17 from the blueprint and docs/architecture/system-design.md.
     Coordinator decisions on its gap list and on deviations are in docs/plan/decisions.md, which wins where they differ.
     ADR numbers cited here are the planner's; the authoritative numbering is docs/adr/README.md. -->

# Implementation Plan: Unified CISO Agent, local baseline build

Repo root for every path below is `C:\Users\<user>\Desktop\Projects\CISO_AG`. Paths in the tables are relative to it. Gate commands run from that directory in PowerShell.

Two notes on the source text:
- The BP §14 priority column is scrambled in the dump. FR-033 reads "Later / channel undecided". FR-034 and FR-035 are "Later" and "Deferred pending environment evidence", but I can't tell from the dump which is which. The other priorities can't be mapped row by row with confidence, so the plan doesn't rely on them.
- The repo is not a git repository yet. Running parallel builders in one checkout without git means nobody can check who touched which file, so `git init` is task T0.1.

---

## 1. Gaps and disagreements (design doc vs BP)

Ranked by how much damage each would do if built as written.

| # | Sev | BP ref | Design heading | Issue | Resolution |
|---|---|---|---|---|---|
| G1 | Critical | §8.4, FR-017/018 | §3 import rules; §5 inference | No rule stops `ciso.orchestrator` from importing `ExternalInferenceGateway`. The "no automatic route" guarantee rests on convention only. | Put the external gateway in its own package, `ciso.inference.external`, importable only by `ciso.api.routers.external_inference` and `ciso.app.container`. Enforce with an architecture test. |
| G2 | Critical | §8.4 step 4 | §5 inference | The approval binds only the payload hash. The BP requires binding to the specific request, provider/model, purpose and payload. The design also never says the approval is single-use. | Bind to `hash(payload) + provider + model + purpose + request_id`, make it single-use, and consume it on transmit. |
| G3 | Critical | §9.5, §19.3 | §5 execution / inference / §3 rule 2 | Approvals live in `ciso.execution`, but external-inference approvals need them too, and rule 2 forbids `inference` importing `execution`. The design contradicts itself. | Move approvals into a standalone `ciso.approvals` module that both sides use. The subject is the canonical hash of whatever is being approved. |
| G4 | High | NFR-006, §11 audit tampering | §5 audit | An unkeyed SHA-256 chain plus SQLite triggers does not detect tail truncation. Anyone with file access can also drop the triggers and recompute the whole chain. | Add an HMAC-keyed head anchor: the key comes from SecretStore, the anchor is written outside `audit.db` and included in backups. `verify()` checks the chain against the anchor. |
| G5 | High | §9.5 fail closed, §19.3 partial failure | §5 audit, execution | Audit and operational data sit in two SQLite files, so no transaction spans both. Nothing defines ordering, what happens when the "result" audit write fails after the tool ran, or how in-flight executions are recovered after a crash. | Rule: audit the attempt before the side effect. Executions get explicit states (`pending`, `executed_unverified`, `verified`, `verification_failed`, `unknown_outcome`, `rolled_back`). At startup, in-flight executions go to `unknown_outcome` and must be verified before any retry. |
| G6 | High | FR-022, §8.3 memory, §11 memory poisoning, §19.2 `memory/`, §19.3 "memory poisoning" | absent | The design has no memory module. The required memory-poisoning test has nothing to test. | Add `ciso.memory` (T5.4): versioned, source-attributed entries. Agent writes land as `pending_review`. Protected namespaces cannot be written. Entries support expiry and rollback. |
| G7 | High | §20 OD-09, App C | §5 common `DataClassification` | The fixed set public, internal, confidential, restricted silently decides the deferred data-classification scheme. | Classification labels become configuration. Only `unknown` is built in, and it ranks as most restrictive. Record the provisional labels in ADR-0017. |
| G8 | High | §11.1, §4.5, §19.3 privacy "tenant boundary" | absent | The design has no tenant concept anywhere: not on source facts, evidence, findings or access checks. | Add `tenant_ref` to source_fact, evidence metadata and findings. Filter on it during evidence access and retrieval. Covered by the privacy tests. |
| G9 | High | §13.4 "no silent scope expansion", §7.7 | §5 connectors | Nothing checks that a connector's records fall inside its approved account, project or environment scope. | Add a connector scope registration plus per-record `scope_ref` checks. A record outside scope is rejected, audited and shown as a health flag (T3.8). |
| G10 | High | §13.2 `payload_ref`, FR-011 | §4 data flow | The flow runs `registry.ingest`, then `reconcile`, then `evidence.put`. Source facts need `evidence_ref` at ingest, so the order is wrong. | Correct order: payload, then `evidence.put`, then envelope with `payload_ref`, then queue, then `registry.ingest` with `evidence_ref`. |
| G11 | High | FR-013, FR-014, FR-015, App D "three AI domains separately" | §1 lists "AI asset registry"; §5 has no contract | No module, no domain tagging, no records for approved use cases and allowed data classes, no visibility-gap model for DF-02, and no home for product-AI checks. The CISO's own model is never self-inventoried. | Add `ciso.ai_registry`: T4.6 inventory, T4.7 employee AI governance, T4.8 product AI baseline checks. |
| G12 | High | §9.5 "evaluate actor ... immediately before execution", §19.3 multi-role | §5 execution | The broker re-runs policy but never re-checks that the approver still holds the role, or that the actor is still active. | Approval validity is computed when it is checked, not when it is granted. Test: role revoked after approval leads to refusal. |
| G13 | High | §9.1 L2 "channel-specific authorization" | §5 policy "approved channels" | The policy default refers to "approved channels", but no channel registry is defined anywhere. | Add `execution/channels.py`, a channel record approved by security_admin. L2 notify or ticket to an unapproved channel is denied. |
| G14 | Medium | §2 design table "no SLOs" vs §7.3, §7.6, §6.5, §9.4 | §2, §5 registry/discovery/policy | Freshness thresholds, retirement grace periods, approval expiry windows, scan rate and concurrency ceilings and API rate limits all need numbers the BP doesn't give. Builders will make them up. | Put every numeric safety knob in one settings file (ADR-0019, "provisional"). The safety-critical ones have no silent default: unset means fail closed (freshness `unknown`, no auto-retire, no approvals granted, no scans). |
| G15 | Medium | §13.1 `subscribe_events`, §10.2 signed webhooks, §13.4 replay protection | §5 connectors, workflows | Dedupe is on `event_id` only. The design has no signature or replay window check and no `subscribe_events`. | Dedupe on `(source_system, event_id)`. Validate the envelope: reject `signature_valid=false`, `replay_checked=false` and clock-skew violations. `subscribe_events` stays an interface only, with no webhook route (no source exists). |
| G16 | Medium | §19.3 connector integration tests | §5 connectors (fixture only) | A JSON fixture connector can't simulate auth expiry, pagination, quotas, API errors or stale cursors. | Add a scriptable fault-injection fake in `tests/fakes/fault_connector.py` (T3.7). |
| G17 | Medium | §7.2 "correlate duplicates before creating records" | §5 registry | The design has no alias or entity-resolution model. | Add an `entity_alias` table keyed by `(source_system, source_record_id)`. Exact-key match only. An ambiguous match creates a reconciliation record instead of merging. |
| G18 | Medium | NFR-012, §5.1 #14 service health, NFR-018 "no false healthy" | absent | The design has no observability module and no health aggregation. | Add `ciso.observability` (T1.8): stdlib structured logging through the redactor, an in-process metrics registry, and a health aggregate where any `unknown` component means overall is not healthy. |
| G19 | Medium | §11 runaway loops, §10.4 degrade | §5 orchestrator, inference | The design has a step budget, timeout and no-recursion rule. It lacks a token budget, concurrency limit, circuit breaker, and a defined degrade path when local inference is unavailable. | Add these to T5.5. On `InferenceUnavailable`, the job is requeued and deterministic checks continue. Never external. |
| G20 | Medium | §11.2 "revoke or suspend execution-broker credentials", App D "deep/active scans" | §5 killswitch | The kill switch flags don't suspend credentials and don't explicitly cover deep tests. If the API or identity layer is down, there is no way to engage it. | The broker resolves write credentials through a kill-switch-checked accessor. `active_scans` also blocks deep tests (test-proven). Add a host-local break-glass CLI. Engaging the switch succeeds even if the audit write fails (audit retried). Releasing it fails closed. ADR-0018. |
| G21 | Medium | §8.3 prompt templates, model artifacts integrity | absent | The design has no prompt template registry and no model manifest with a hash pin. | T1.10: versioned prompt files plus a manifest with sha256. Load fails on mismatch. The stub provider is registered through the manifest too. |
| G22 | Medium | §5.1 #2 rate limits, request validation | §5 api | The API design has no rate limiting. | Add an in-process limiter with values from settings (G14) (T1.15). |
| G23 | Medium | FR-031, §12.2, §12.3 purpose limitation | §5 api (route-level permission only) | Nothing restricts rows by subject (for example, employees see only their own records), and collection has no declared purpose or field scope. | Connector manifest declares purpose, field scope and retention ref (T3.6). Row-level ABAC filter on employee-visible resources (T5.8, T6.1). |
| G24 | Medium | §7.3 time windows, concurrency, prod-safe profile; §7.4 plan fields | §5 discovery | Scopes lack time windows, rate and concurrency limits and a production-safe profile rule. Run records lack tool/version and checks performed. `customer_owned` is not modelled as never-scannable. | Covered by T4.2 and T4.3. Add `customer_owned` to `Environment`, hard-denied. |
| G25 | Medium | OD-11 | §5 risk "qualitative impact and likelihood" | A fixed qualitative scale is still a methodology choice. Phase 4 allows qualitative inputs, but OD-11 defers the scale. | Store free-text rationale plus a factor list, with no aggregate and no score field (test-asserted). The provisional scale goes in an ADR. |
| G26 | Medium | OD-14 | §5 inference "approver with the configured role" | Approving role and allowed data classes are deferred. The design must not default them to security_admin. | Default unset. Unset means transmit is impossible. Tests set them explicitly. |
| G27 | Low | §19.3 class list | §1 "Tests" bullet | The design's test list omits three §19.3 classes: connector integration, execution broker and privacy/data protection. | Each test class gets a marker, and a meta-test asserts every marker collects more than 0 tests (T0.6). |
| G28 | Low | OD-12, §12.1 UI stack undecided | §1, §5 api "minimal console" | A console means choosing a UI stack, which the BP leaves undecided. | Recommend API-only plus OpenAPI for this build. The console waits on an ADR. App D only needs "authenticate admins", which the API satisfies. |
| G29 | Low | App D "private service boundaries", NFR-016 | §3, §8 one process | Isolating trust domains by OS process can't be met in-process. | State plainly that this App D bullet is not met locally (ADR-0010). The gate before any real write adapter stays. |
| G30 | Low | §6.3 vs §9.3 | §5 identity / registry | Company people (registry Person) and CISO users (identity Actor) are blurred together. | Keep them separate. An Actor optionally links to a registry Person ref. |
| G31 | Low | §8.3 inference log fields | §5 inference | Missing model version, token/compute metrics and result metadata. | Add to the invocation record (T1.9). |
| G32 | Low | NFR-010 versioned schemas | §6 storage "versioned migration scripts" | No migration tool is named, and one shared migration chain guarantees conflicts between parallel builders. | Per-module versioned DDL plus a `schema_version(module, version)` table. No cross-module foreign keys (refs are `EntityRef` strings). ADR-0012. |
| G33 | Decision to record | §9.3 "one person may hold multiple roles" | §5 execution "approver must not be requester" | Forbidding self-approval is a separation-of-duties choice the BP doesn't make. In a one-person startup it makes human-initiated L4 actions impossible. | Keep it as the default, but record it in ADR-0016 for the owner to decide. Agent-initiated proposals are unaffected. |

---

## 2. Milestones and exit gates

Every gate runs on a fresh clone into a scratch directory, not on the working checkout. Base command, from the clone root, PowerShell:
`uv sync --locked; uv run ruff check src tests; uv run mypy src; uv run pytest -p no:cacheprovider`

| M | Name (BP phase) | Exit gate: observable checks |
|---|---|---|
| M0 | Repo and contracts (BP backlog #1-3, App C #10-14) | Base command green on a fresh clone. Architecture tests report a scanned-file count above 0 per rule. One forbidden import is introduced by hand and the test goes red (mutation proof), then it is reverted. `docs/adr/` holds ADR-0001..0019 with status `proposed`. `open-decisions.md` lists OD-01..18. |
| M1 | Control-plane foundation (Phase 1 gate) | (a) The API returns 401 without a token, with an expired token and with a revoked token, and 200 with a valid one. (b) The secret-seed sweep: a known secret is pushed through logs, audit details and inference input, with an assertion that the seeding happened, then grep of `data/`, logs and the DB files finds 0 hits. (c) Settings default `external_inference_enabled=False` and bind 127.0.0.1, and the runtime socket guard is active in conftest. (d) Every write operation gets `deny` from the policy engine under the default ruleset, and an unloadable ruleset denies everything. (e) Audit events are recorded, and `verify()` detects edit, delete-middle and tail truncation. (f) A backup and restore round-trip passes audit verify and the anchor check with matching row counts. |
| M2 | Approvals, broker, external gate (Phase 5 core, App D bullets 3, 8, 9) | Every T2.x test passes. The number of classes implementing `ExternalTransport` in `src` is 0. With the kill switch engaged, the broker, external transmit and L3 are all refused (counted). A hand mutation that removes the kill-switch check from the broker and the approval check from transmit makes the suite red. |
| M3 | Registry, evidence, connectors (Phase 2 gate) | The fixture estate is loaded: people/identities, apps, repos, cloud resources and AI assets, plus 1 planted conflict and 1 failing connector. The API shows provenance on every field. The conflicting field returns `conflicting` with 2 or more assertions. The failing connector produces 1 or more coverage-gap rows, and the summary state is not `clean`. |
| M4 | Discovery and AI inventory (Phase 3 gate, App D bullets 5-6) | One scripted run on the fixture estate shows declared assets and newly discovered unknown assets as separate counts, both above 0. All five information states appear at least once. Every `discovery_safety` test is green. The AI inventory lists more than 0 assets in each of employee_ai, product_ai and ciso_platform, and the CISO's own stub model is among them. |
| M5 | Findings, risk, memory, orchestrator (Phase 4 gate, App D bullet 7) | E2E through the API: a finding links to evidence refs that resolve, affected entities that resolve, an owner, a confidence state and a "why it matters" field. A risk acceptance by `executive_risk_owner` is recorded, and the same acceptance by an agent is denied. The adversarial suite is green, and a mutation of the proposal validator makes it red. |
| M6 | Hardening, DoD (Phase 5 gate subset, App D) | The privacy sweep, outage/replay, kill-switch acceptance, action path and audit-completeness tests are all green. The DoD checklist has every App D bullet mapped to a test, or to an explicit "not achievable locally" with its ADR. The traceability matrix has no empty cells. |

Phase 0 exit gate: not buildable, because it needs people. The repo ships the instruments for it (D0.3), and the gate itself belongs to the owner.

---

## 3. Tasks

Conventions:
- Each task lists tests first, then implements.
- One test marker per BP §19.3 class: `unit`, `connector`, `policy`, `adversarial`, `external_inference`, `broker`, `privacy`, `resilience`, `discovery_safety`.
- pytest runs with `--import-mode=importlib`, so test directories need no `__init__.py`.
- "Lane" means the task can run in parallel with the others in the same lane group. Serial tasks are marked C (coordinator).
- "OD" lists the deferred decisions the task must not resolve on its own. Where no OD applies, the cell is "-".

### M0: coordinator, serial; docs lane D runs in parallel throughout

| ID | Goal | Files owned | Dep | Tests first | Covers | OD |
|---|---|---|---|---|---|---|
| T0.1 C | `git init`, toolchain, pinned deps | `.gitignore` (ignores `data/`, caches), `pyproject.toml` (ruff, mypy strict, pytest config with markers and importlib mode), `.python-version`, `uv.lock`, `tests/test_smoke.py` | - | Package imports; `data/` is ignored | NFR-010 | Stack choices are ADR-0001 |
| T0.2 C | Common primitives | `src/ciso/__init__.py`, `src/ciso/common/__init__.py`, `ids.py`, `clock.py`, `hashing.py`, `errors.py` | T0.1 | Prefixed ids sort by time; `EntityRef` parse/format round-trips and rejects malformed input; canonical JSON is key-order independent; FixedClock injects UTC and rejects naive datetimes | NFR-010 | - |
| T0.3 C | Shared contracts | `src/ciso/common/enums.py`, `schemas.py` (frozen base with `extra=forbid`, `Principal`), `protocols.py` (AuditSink, KillSwitchReader, SecretResolver, Redactor, PolicyContext, PreconditionChecker), `tests/common/test_contracts.py` | T0.2 | Enums match the BP vocabularies (§6.5, §7.5, §13.3); `Environment` includes `customer_owned`; models reject extra fields and are immutable; a `Principal` of type agent cannot carry the admin or approver role flags | FR-001, FR-012 | OD-09: no classification enum (G7) |
| T0.4 C | DB base | `src/ciso/common/db.py` (engine factory with WAL, busy_timeout, foreign_keys; `install_module_schema(engine, module, steps)`; `schema_version` table), `tests/common/test_db.py` | T0.2 | Install is idempotent; steps apply in order; a re-run skips applied versions; pragmas are set; a tmp-path DB is used | NFR-010 | Database product is ADR-0002 |
| T0.5 C | Test harness | `tests/conftest.py` (markers, autouse socket guard, tmp data dir, PYTHONDONTWRITEBYTECODE), `tests/fakes/__init__.py`, `tests/fakes/core.py` (FakeAudit, FakeKillSwitch, FakeSecrets, FixedClock), `tests/fakes/test_fakes.py` | T0.3 | A socket connect raises inside tests; the fakes satisfy the protocols (isinstance on runtime_checkable) | NFR-003 | - |
| T0.6 C | Architecture tests | `tests/architecture/test_import_boundaries.py`, `test_network_imports.py`, `test_read_connector_surface.py`, `test_required_test_classes.py` | T0.5 | All rules from design §3, plus G1, plus: no `importlib` or `__import__` in guarded packages; `connectors` cannot import `write_adapters`; `orchestrator` cannot import `execution` tools. Each rule reports a scanned-file count, and a rule is xfail (not a silent pass) until its package exists. The required-class meta-test asserts every marker collects more than 0 tests, and stays xfail until M6. | NFR-001, NFR-003, NFR-016, §9.5 | - |
| D0.1 lane D | ADRs | `docs/adr/0001-*.md` .. `0019-*.md` covering: language, DB, evidence storage, identity, inference runtime, queue, secret manager, backup, host/network, process decomposition, web framework/console, migrations, policy format, audit integrity, observability, SoD, classification labels, kill-switch semantics, safety parameters | - | n/a (review: each lists options, security impact and the evidence needed) | App C #14, App D last bullet | All |
| D0.2 lane D | Open-decision register and traceability skeleton | `docs/adr/open-decisions.md`, `docs/traceability.md` | - | n/a | App C #10 | - |
| D0.3 lane D | Phase 0 instruments | `docs/phase0/questionnaire.md`, `docs/phase0/source-permission-matrix.md`, `docs/phase0/system-inventory-template.csv` | - | n/a | BP backlog #2, App C #11 | No vendors named |

### M1: lanes A-H in parallel, then the integration tasks run serially

| ID | Lane | Goal | Files owned | Dep | Tests first | Covers | OD |
|---|---|---|---|---|---|---|---|
| T1.1 | A | Audit core | `src/ciso/audit/__init__.py`, `tables.py`, `log.py`, `tests/audit/test_append_verify.py`, `tests/audit/test_tamper.py` | M0 | Seq is gapless under 4 concurrent appenders; prev_hash chains; UPDATE and DELETE abort; verify flags an edited row (triggers dropped in the test) and a deleted middle row; details pass through the redactor; append failure raises, never swallowed | FR-028, NFR-006 | - |
| T1.2 | A | Audit anchor | `src/ciso/audit/anchor.py`, `tests/audit/test_anchor.py` | T1.1, T1.3 | HMAC head anchor detects tail truncation and a full-chain recompute; a missing anchor reports `unverifiable`, not `ok` | NFR-006, §11 | Anchor location provisional (ADR-0014) |
| T1.3 | B | Secrets and redaction | `src/ciso/secrets/__init__.py`, `store.py`, `redact.py`, `tests/secrets/test_store.py`, `tests/secrets/test_redactor.py` | M0 | `repr` and `str` are masked; JSON, pickle and `model_dump` raise; an unknown ref raises (never an empty string); prefix enforced; optional `expires_at`; the redactor scrubs registered values plus bearer, JWT, PEM and cloud-key shapes; idempotent; logging filter | §11.1, NFR-007, FR-031 | Production secret manager is ADR-0007 |
| T1.4 | C | Identity model | `src/ciso/identity/__init__.py`, `tables.py`, `roles.py`, `service.py`, `tests/identity/test_roles.py` | M0 | The five role templates load with zero assignments; multiple roles per actor allowed; ABAC scope (system, environment, classification, time window) matches correctly; agent and service actors are rejected for security_admin and approver roles; assignments and revocations are audited | FR-002, FR-024, NFR-004 | OD-03: no IdP |
| T1.5 | C | Authentication | `src/ciso/identity/authn.py`, `tests/identity/test_authn.py` | T1.4 | Token shown once and stored hashed; constant-time compare; expiry, revocation and disabled-actor checks reject; no shared admin identity (each token maps to exactly one actor) | NFR-004, FR-003 | MFA and SSO are OD-03 |
| T1.6 | D | Kill switch | `src/ciso/killswitch/__init__.py`, `tables.py`, `service.py`, `breakglass.py`, `tests/killswitch/test_killswitch.py` | M0 | Flags are `writes`, `external_inference`, `active_scans` (which also covers deep tests) and `l3_runs`. Engage and release require a human security_admin; an agent is denied. A read error means blocked. Engage still persists when the audit write fails (audit retried); release fails closed. Break-glass CLI engages from the host. | FR-030, §11.2 | ADR-0018 semantics |
| T1.7 | E | Durable queue | `src/ciso/workflows/__init__.py`, `tables.py`, `queue.py`, `tests/workflows/test_queue.py`, `tests/resilience/test_queue_recovery.py` | M0 | Dedupe on `(source, event_id)`; an expired lease requeues; backoff; retry ceiling sends to dead-letter; replay from dead-letter requires a human and is audited; FIFO per ordering key; state survives engine dispose and reopen | FR-029, NFR-008 | Values from ADR-0019 |
| T1.8 | F | Observability | `src/ciso/observability/__init__.py`, `logging.py`, `metrics.py`, `health.py`, `tests/observability/test_observability.py` | M0 | Log records are redacted; the health aggregate reports `unknown` or `degraded` if any component is unknown, never `healthy`; counters exist for policy decisions, broker outcomes, inference calls and connector syncs | NFR-012, NFR-018 | No exporter (ADR-0015) |
| T1.9 | G | Local inference gateway | `src/ciso/inference/__init__.py`, `gateway.py`, `stub.py`, `records.py`, `tests/inference/test_gateway.py` | M0 | Routes only to the configured local provider; provider error or timeout raises `InferenceUnavailable` and a spy on any other provider records 0 calls; low confidence is returned as-is; the invocation record has model and version, task category, context refs, latency, token metrics and no prompt body; input is redacted; output is wrapped `UntrustedModelOutput` | FR-016, FR-017, §8.3 | OD-02 |
| T1.10 | G | Prompt and model manifest | `src/ciso/inference/manifest.py`, `src/ciso/inference/prompts/README.md`, `src/ciso/inference/prompts/stub_v1.txt`, `tests/inference/test_manifest.py` | T1.9 | A hash mismatch refuses to load; the prompt version is recorded on each invocation; nothing writes prompts at runtime (no write API exists) | §8.3, §11 supply chain | OD-02 |
| T1.11 | H | Action envelope | `src/ciso/policy/__init__.py`, `envelope.py`, `tests/policy/test_envelope.py` | M0 | Every §9.4 field is present; extra fields are rejected; `operation` must be registered (no free-text command); expiry is required and capped by setting; canonical hash is stable | FR-023, §9.4 | Expiry cap ADR-0019; `risk_class` labels come from the ruleset |
| T1.12 | H | Rules and loader | `src/ciso/policy/rules.py`, `loader.py`, `src/ciso/policy/rulesets/default.json`, `tests/policy/test_loader.py` | T1.11 | Malformed JSON, a schema violation or an unknown key puts the engine in deny-all; ruleset version and content hash are exposed | FR-023 | - |
| T1.13 | H | Policy engine | `src/ciso/policy/engine.py`, `tests/policy/test_engine_defaults.py`, `tests/policy/test_escalation.py` | T1.12 | Unknown operation is denied. L0-L2 are allowed only inside scope, and L2 to an unapproved channel is denied. L3 is denied when the playbook is missing, disabled or expired. L4 returns `require_approval`. An agent or service asking to change policy, roles, approvers, audit or its own permissions is denied even when a rule allows it. Wrong role and wrong scope are denied; a multi-role holder outside their attribute scope is denied. A stale fact returns `hold`. A context provider that raises gives deny. The decision carries rule ids, version and `evaluated_at`. | FR-023, FR-024, FR-027, NFR-005, NFR-017 | OD-15: zero playbooks |
| T1.14 C | serial | Settings and composition root | `src/ciso/app/__init__.py`, `settings.py`, `container.py`, `tests/app/test_settings.py` | lanes A-H | External inference off by default; bind 127.0.0.1; a missing required secret ref or safety knob fails at startup | NFR-002, NFR-003 | ADR-0019 |
| T1.15 C | serial | API skeleton | `src/ciso/api/__init__.py`, `app.py`, `deps.py`, `routers/system.py`, `tests/api/test_auth_system.py` | T1.14 | No, bad, expired or revoked token gives 401. A test lists every route and fails on any route with no declared permission. An employee reading audit gets 403. Exceeding the rate limit gives 429. Kill switch engage and audit read work end to end. | FR-003, NFR-005, §5.1 #2 | Limits from ADR-0019 |
| T1.16 | after T1.14 | Backup and restore | `src/ciso/ops/__init__.py`, `backup.py`, `restore.py`, `tests/resilience/test_backup_restore.py` | T1.14 | Archive bytes contain no known plaintext row; a tampered archive fails the GCM tag; restore matches row counts and passes audit verify and the anchor check; works while the DB is open on Windows (online backup API, no `os.replace` on open files) | NFR-007, NFR-018, §10.3 | ADR-0008 |
| T1.17 | after T1.14 | Startup and shutdown recovery | `src/ciso/ops/lifecycle.py`, `tests/resilience/test_restart.py` | T1.16 | Startup expires leases, marks connector health `unknown` until the next sync, and runs audit verify; if verify fails, the write capability stays blocked; shutdown drains workers | NFR-008, NFR-018 | - |
| D1.1 | D | Runbooks | `docs/runbooks/recovery.md`, `docs/runbooks/kill-switch.md`, `docs/runbooks/backup.md` | T1.6, T1.16 | n/a | Phase 1 "procedure tested" | UPS is out of scope (OD-01) |

### M2: lanes A-D in parallel; T2.3 waits for T2.1 and T2.2

| ID | Lane | Goal | Files owned | Dep | Tests first | Covers | OD |
|---|---|---|---|---|---|---|---|
| T2.1 | A | Approvals module | `src/ciso/approvals/__init__.py`, `tables.py`, `service.py`, `tests/approvals/test_approvals.py` | M1 | Binds subject hash, approver role, scope and expiry. A non-holder, agent or service cannot approve. Requester = approver is denied (ADR-0016). Expired approvals are invalid. Single-use is enforced. An approver whose role was revoked after approving is invalid at check time. Each transition is audited, and an audit failure leaves nothing recorded. | FR-025, §9.5 | ADR-0016 SoD |
| T2.2 | B | Tool registry and channels | `src/ciso/execution/__init__.py`, `tools.py`, `channels.py`, `tests/execution/test_tool_registry.py` | M1 | Unregistered tool rejected; an L3 tool without rollback or verification is rejected at registration; extra args rejected; shell metacharacters stay inert data; an unapproved channel is denied; channel approval requires security_admin | FR-026, §9.5 | OD-13: channel targets are local outboxes only |
| T2.3 | A+B | Broker | `src/ciso/execution/broker.py`, `tables.py`, `tests/execution/test_broker_gates.py`, `tests/execution/test_broker_failures.py` | T2.1, T2.2 | The order of gates is asserted via a spy. The broker refuses on: kill switch engaged; kill switch read error; policy unavailable; attempt-audit failure (the tool is never called); expired envelope; stale precondition; missing or mismatched approval; rate limit hit. Duplicate idempotency key returns the prior result without re-running. Verification mismatch gives `verification_failed` with residual risk recorded. Tool raises after its side effect: `unknown_outcome`. L3 fake triggers rollback on failure. Write credentials are fetched through a kill-switch-gated accessor. | FR-026, FR-027, NFR-005, NFR-017 | - |
| T2.4 | B | Outbox tools and execution recovery | `src/ciso/execution/outbox_tools.py`, `recovery.py`, `tests/execution/test_outbox_tools.py`, `tests/resilience/test_execution_recovery.py` | T2.3 | Verification reads the outbox independently of the tool reply; in-flight executions at restart become `unknown_outcome`; retry without verification is refused | FR-026, NFR-018 | - |
| T2.5 | C | Write-adapter contract (interface only) | `src/ciso/write_adapters/__init__.py`, `contract.py`, `tests/architecture/test_write_adapter_isolation.py` | M1 | Zero implementations in `src`; `connectors` never imports it | §19.1, §13.1 | No adapter (OD-13) |
| T2.6 | D | External: propose, preview, minimize | `src/ciso/inference/external/__init__.py`, `proposal.py`, `minimize.py`, `tests/external_inference/test_preview_minimize.py` | M1 | The preview is the exact bytes later hashed. Secrets are redacted. Unknown classification counts as restricted. Allowed classes are unset by default, which blocks everything. Context refs carry classification labels. | FR-018, §8.4 1-3, §11.1 | OD-14 |
| T2.7 | D | External: authorize, transmit, record, reintegrate | `src/ciso/inference/external/gateway.py`, `transport.py`, `tests/external_inference/test_approval_binding.py` | T2.1, T2.6 | Transmit refuses when: feature flag off (the default); kill switch engaged; approval mismatched on payload, provider, model or purpose; approval expired or reused; approving role unset; transport absent. The record carries every §8.4 step-6 field. The result is wrapped untrusted. | FR-018, NFR-003 | OD-14 |
| T2.8 | D | No-fallback suite | `tests/external_inference/test_no_fallback.py`, `tests/external_inference/test_egress.py` | T2.7 | Local timeout, error, low confidence, queue pressure and circuit-open all leave the spy transport with 0 calls. The socket guard sees no connect attempt during a full orchestrated run. Audit records exist for every external path step. | FR-017, NFR-003, NFR-017, App D #3 | - |
| T2.9 C | serial | API routers | `src/ciso/api/routers/approvals.py`, `external_inference.py`, `policy.py` (read-only), `tests/api/test_approvals_api.py` | T2.1-T2.7 | Approve and reject need the named role; preview returns the exact payload; there is no route that changes policy | FR-025, FR-018 | OD-14 UX |

### M3: lanes A (evidence), B (registry), C (connectors); then T3.8 and T3.9

| ID | Lane | Goal | Files owned | Dep | Tests first | Covers | OD |
|---|---|---|---|---|---|---|---|
| T3.1 | A | Evidence crypto and store | `src/ciso/evidence/__init__.py`, `tables.py`, `crypto.py`, `store.py`, `tests/evidence/test_store.py` | M2 | AES-GCM with key id; no plaintext on disk (grep the blob dir); content hash checked on read; tampered blob raises; metadata carries classification, source and `tenant_ref` | FR-011, NFR-007 | ADR-0003 |
| T3.2 | A | Evidence access and retention | `src/ciso/evidence/access.py`, `retention.py`, `tests/privacy/test_evidence_access.py` | T3.1 | `get` requires purpose and role. Restricted or unknown classification requires a purpose grant. Tenant filter applies. Every access is audited. Unset retention means no auto-delete and the item is flagged. Deletion leaves a tombstone plus audit. Key rotation re-encrypts. | FR-031, NFR-007, §4.5 | OD-17 |
| T3.3 | B | Registry ingest and correlation | `src/ciso/registry/__init__.py`, `tables.py`, `ingest.py`, `correlate.py`, `tests/registry/test_ingest.py` | M2 | Ingest is append-only. Required provenance fields are enforced. Secret-shaped values are rejected (refs only). An exact alias match merges; an ambiguous match creates a reconciliation record and no merge. Entity kind comes from the vocabulary. `tenant_ref` is preserved. | FR-009, FR-011, §7.2 | - |
| T3.4 | B | Authority and resolve | `src/ciso/registry/authority.py`, `resolve.py`, `tests/registry/test_resolve.py`, `tests/registry/test_freshness.py` | T3.3 | The authoritative source wins per field; a newer non-authoritative fact does not override. With no rule and a disagreement, the field is `conflicting` and all assertions are returned. Declared never outranks verified. Inferred is never upgraded. Unset freshness policy gives `unknown`. `as_of` resolves history. An owner can validate and clear `awaiting_owner_validation`. | FR-010, FR-012, FR-022 | Freshness values ADR-0019 |
| T3.5 | B | Relationships and lifecycle | `src/ciso/registry/relationships.py`, `lifecycle.py`, `tests/registry/test_relationships.py`, `tests/registry/test_lifecycle.py` | T3.3 | Only §6.4 types are accepted; source and timestamp are required; confidence is an evidence-based enum. An entity vanishing from one source is not retired. Unset grace means no auto-transition. Retirement needs cross-source confirmation. Rows are never deleted. | FR-009, §7.6 | Grace values ADR-0019 |
| T3.6 | C | Connector contract | `src/ciso/connectors/__init__.py`, `contract.py`, `envelope.py`, `health.py`, `tests/connectors/test_contract.py` | M2 | Envelope rejects `signature_valid=false`, `replay_checked=false`, non-UTC timestamps and skew. Health carries auth validity, quota, permission gaps, last success and degraded state. The manifest declares purpose, field scope and retention ref. Read connectors have no execute or write methods. | FR-004, FR-031, §13.1-13.2 | - |
| T3.7 | C | Fixture connector and fault fake | `src/ciso/connectors/fixture.py`, `tests/fakes/fault_connector.py`, `tests/fixtures/estate/README.md`, `tests/connectors/test_fixture.py` | T3.6 | The fixture paginates and checkpoints; the fault fake can script auth expiry, 429 quota, 5xx, stale cursor, duplicates and permission gaps | FR-004 | No vendor |
| T3.8 | after A-C | Scope, pipeline, coverage | `src/ciso/connectors/scope.py`, `pipeline.py`, `coverage.py`, `tests/connectors/test_integration_faults.py`, `tests/connectors/test_scope_expansion.py` | T1.7, T3.2, T3.4, T3.7 | Order is evidence, then envelope, then queue, then ingest (spy). Auth expiry, API error or permission gap creates a coverage gap and never a "clean" result. Duplicates and replay are deduped. A stale cursor triggers resync and a gap. Quota triggers backoff. An out-of-scope record is rejected, audited and flagged in health. | FR-004, FR-006, FR-029, §13.4 | - |
| T3.9 C | serial | API registry and connectors | `src/ciso/api/routers/registry.py`, `connectors.py`, `tests/api/test_registry_api.py` | T3.8 | Filters for unknown, stale and disputed work; each field returns value, state, freshness, reconciliation and provenance | BP backlog #8, NFR-015 | - |
| T3.10 C | serial | Phase 2 gate data and e2e | `tests/fixtures/estate/*.json`, `tests/e2e/test_phase2_gate.py` | T3.9 | Assertions as in the M3 gate, all on positive counts | Phase 2 gate | - |

### M4: lanes A (discovery) and B (AI registry) in parallel

| ID | Lane | Goal | Files owned | Dep | Tests first | Covers | OD |
|---|---|---|---|---|---|---|---|
| T4.1 | A | Onboarding | `src/ciso/discovery/__init__.py`, `onboarding.py`, `tests/discovery/test_onboarding.py` | M3 | Everything lands as `declared` with attestation evidence; a declared owner is not marked verified; the module imports no write adapter | FR-005, §7.1 | - |
| T4.2 | A | Scopes and profiles | `src/ciso/discovery/scopes.py`, `profiles.py`, `tests/discovery_safety/test_scopes.py` | T4.1 | Approval role, expiry, exclusions, time window and environment tag are enforced. Production accepts only `production_safe` profiles. `third_party` and `customer_owned` never match, including when referenced by an in-scope asset. Changes are audited. | FR-007, §7.3 | Approver role and profile contents are provisional (ADR) |
| T4.3 | A | Active guard and scanner interface | `src/ciso/discovery/active.py`, `scanner.py`, `tests/discovery_safety/test_active_guard.py` | T4.2 | Refuses: out of scope, excluded target, expired scope, outside window, kill switch engaged (a running scan pauses). Throttle is enforced on rate and concurrency using the fake clock. The run record carries every §7.3 field, including on error. Results enter the registry as inferred. | FR-007, NFR-009 | No real scanner |
| T4.4 | A | Deep-test gate | `src/ciso/discovery/testplans.py`, `tests/discovery_safety/test_deep_test_gate.py` | T4.3 | The plan requires every §7.4 field. Its approval is separate from scope approval. Production needs an explicit extra flag. Methods outside the plan are refused. The kill switch blocks. | FR-008, §7.4 | - |
| T4.5 | A | Passive discovery | `src/ciso/discovery/passive.py`, `src/ciso/workflows/scheduler.py`, `tests/discovery/test_passive.py` | T4.1 | Scheduled pulls run. Unknown assets are labelled unverified with no owner. A declared asset not found stays declared. A failure creates a coverage gap. | FR-006, §7.2 | Schedule values ADR-0019 |
| T4.6 | B | AI inventory | `src/ciso/ai_registry/__init__.py`, `models.py`, `service.py`, `tests/ai_registry/test_ai_inventory.py` | M3 | Every §6.3 AI kind is accepted. A domain tag is required. The stub model is self-registered as `ciso_platform`. Credential fields accept refs only. Data flows are relationships. | FR-013, App D #6 | OD-05 |
| T4.7 | B | Employee AI governance | `src/ciso/ai_registry/governance.py`, `tests/ai_registry/test_employee_ai_governance.py` | T4.6 | Approved use cases reference configured classification labels. The "personal accounts unobservable" gap is always present unless a control is declared. The query answers approved, not approved or unknown, and never "safe". | FR-014, DF-02, §12.2 | OD-06, OD-09 |
| T4.8 | B | Product AI baseline checks | `src/ciso/ai_registry/product_checks.py`, `tests/ai_registry/test_product_checks.py` | T4.6 | Deterministic checks over declared attributes emit `FindingCandidate`s: RAG without declared tenant isolation; tool without an allowlist; missing output validation; model artifact without hash. Each candidate carries the state of its source facts. | FR-015 (partial) | OD-05: the check list is provisional |
| T4.9 C | serial | API discovery and AI | `src/ciso/api/routers/discovery.py`, `ai_registry.py`, `tests/api/test_discovery_api.py` | T4.1-T4.8 | Scope approval needs the role; the active-run endpoint returns refusal reasons | FR-005, FR-007 | - |
| T4.10 C | serial | Phase 3 gate e2e | `tests/e2e/test_phase3_gate.py` | T4.9 | Assertions as in the M4 gate | Phase 3 gate | - |

### M5: lanes A (findings and risk), B (memory then orchestrator), C (reporting and employee reports)

| ID | Lane | Goal | Files owned | Dep | Tests first | Covers | OD |
|---|---|---|---|---|---|---|---|
| T5.1 | A | Findings core | `src/ciso/findings/__init__.py`, `tables.py`, `service.py`, `tests/findings/test_findings.py` | M4 | Every §13.3 field is present. Dedupe by fingerprint. Transitions follow a table; `accepted` requires a linked risk acceptance. Evidence and entity refs must resolve. Findings are never deleted. Correlation groups findings by shared entity. | FR-019, FR-021 | - |
| T5.2 | A | Detectors and native findings | `src/ciso/findings/detectors.py`, `native.py`, `tests/findings/test_detectors.py` | T5.1 | The design's detectors fire, plus coverage-gap and FindingCandidate intake. Native severity and id are preserved. `confidence_state` is the weakest of its inputs. | FR-019, FR-015 | - |
| T5.3 | A | Risk register | `src/ciso/risk/__init__.py`, `tables.py`, `service.py`, `tests/risk/test_risk_register.py` | T5.1 | Only a human `executive_risk_owner` can accept. The acceptance record carries approver, rationale, scope, expiry and residual exposure. An expired exception reopens and is reported. The model has no score field (asserted). | FR-020, FR-021 | OD-11 |
| T5.4 | B | Governed memory | `src/ciso/memory/__init__.py`, `tables.py`, `service.py`, `tests/memory/test_memory_governance.py` | M4 | Agent writes land as `pending_review` and only a human promotes them. Protected namespaces (policy, authority rules, permissions, prompts) refuse writes. Entries are versioned with rollback and expiry, and every write is attributed. | FR-022, §8.3 | OD-17 |
| T5.5 | B | Orchestrator | `src/ciso/orchestrator/__init__.py`, `runner.py`, `context.py`, `proposals.py`, `tests/orchestrator/test_runner.py` | T5.4 | Step, token, timeout and concurrency budgets are enforced; recursion is refused. The circuit breaker degrades to deterministic checks and requeues, with no external call. Proposals with an unknown entity or evidence ref, or an unregistered operation, are rejected. Explanations must cite evidence refs. The orchestrator holds no tool or credential handles. | §11, §10.4, Phase 4 | - |
| T5.6 | B | Adversarial suite | `tests/fakes/adversarial_provider.py`, `tests/adversarial/test_prompt_injection.py`, `tests/adversarial/test_poisoned_retrieval.py`, `tests/adversarial/test_memory_poisoning.py` | T5.5, T2.3 | Direct and indirect injection, tool-output manipulation, false evidence, hallucinated IDs, policy-change requests and memory poisoning are all stopped, by validation, policy or the broker, with the expected reason code | §19.3 LLM adversarial, §8.5 | - |
| T5.7 | C | Operator reporting | `src/ciso/reporting/__init__.py`, `summary.py`, `tests/reporting/test_summary.py` | T5.3 | The summary has coverage gaps, connector health, open findings, unresolved risks and pending approvals. A gap prevents a "clean" verdict. | FR-032 | - |
| T5.8 | C | Employee report record (interface only) | `src/ciso/employee/__init__.py`, `reports.py`, `tests/privacy/test_employee_visibility.py` | M4 | An employee sees only their own reports. Responses never claim "resolved" or "safe" without evidence. | FR-033 (interface), §12.2 | OD-12: no channel |
| T5.9 C | serial | API findings, risk, memory, reporting | `src/ciso/api/routers/findings.py`, `risk.py`, `memory.py`, `reporting.py`, `tests/api/test_findings_risk_api.py` | T5.1-T5.8 | Role checks on accept, promote and assign | FR-019-022, FR-032 | - |
| T5.10 C | serial | Phase 4 gate e2e | `tests/e2e/test_phase4_gate.py` | T5.9 | Assertions as in the M5 gate | Phase 4 gate | - |

### M6: lanes A-C in parallel; D6.1 last

| ID | Lane | Goal | Files owned | Dep | Tests first | Covers |
|---|---|---|---|---|---|---|
| T6.1 | A | Privacy sweep | `tests/privacy/test_tenant_boundary.py`, `test_access_segregation.py`, `test_secret_sweep.py`, `test_backup_encryption.py` | M5 | A seeded secret and a cross-tenant marker are pushed through every ingress; grep finds 0 hits; seeding is asserted positive | FR-031, NFR-007, §19.3 privacy |
| T6.2 | B | Outage and replay | `tests/resilience/test_outage_replay.py` | M5 | A subprocess is killed mid-sync; after restart the cursor resumes, there are no duplicates, health is not healthy until a sync succeeds, and audit verify passes | NFR-008, NFR-018, App D #10 |
| T6.3 | C | Kill-switch acceptance | `tests/e2e/test_killswitch_acceptance.py` | M5 | Blocked: broker, external transmit, active scans, deep tests, L3, write credentials. Still working: reads, findings, health. | FR-030, §11.2, App D #9 |
| T6.4 | C | Action path (Phase 5 gate) | `tests/e2e/test_action_path.py` | M5 | Model proposal, policy, approval, broker, verify, audit; plus denial, failure, retry, duplicate, stale precondition and L4 approval bypass attempt | Phase 5 gate, App D #8 |
| T6.5 | A | Audit completeness | `tests/e2e/test_audit_completeness.py` | M5 | One e2e run emits each event category: user, agent, connector, model, policy, approval, action, result | FR-028, NFR-006 |
| D6.1 | D | DoD and traceability | `docs/traceability.md`, `docs/definition-of-done.md`, ADR status updates | all | n/a | App C #10, App D |

---

## 4. Requirements traceability

Status key: **Built**; **Partial** (the mechanism is built, the real capability needs a Phase 0 or OD answer); **Interface** (contract only); **Deferred**.

| Req | Module(s) | Task(s) | Proof | Status |
|---|---|---|---|---|
| FR-001 | common.enums, findings, risk | T0.3, T5.1, T5.3 | Findings in all 4 domains land in one register (T5.1) | Built |
| FR-002 | identity, registry | T1.4, T3.3 | Templates load with zero assignments; org entity kinds ingest | Built |
| FR-003 | api, identity.authn | T1.15, T1.5 | test_auth_system | Built (API only; console: G28) |
| FR-004 | connectors | T3.6-T3.8 | test_contract, test_integration_faults | Partial: fixture only, first real source is Phase 0 |
| FR-005 | discovery.onboarding | T4.1 | test_onboarding | Built |
| FR-006 | discovery.passive, connectors.pipeline | T4.5, T3.8 | test_passive | Built |
| FR-007 | discovery.scopes/active | T4.2, T4.3 | discovery_safety suite | Partial: scanner is a fake |
| FR-008 | discovery.testplans | T4.4 | test_deep_test_gate | Built |
| FR-009 | registry | T3.3-T3.5 | test_ingest, test_relationships, test_lifecycle | Built |
| FR-010 | registry.authority/resolve | T3.4 | test_resolve | Built |
| FR-011 | registry, evidence, findings | T3.1, T3.3, T5.1 | Phase 2 gate e2e | Built |
| FR-012 | registry.resolve | T3.4, T4.10 | Phase 3 gate: all 5 states appear | Built |
| FR-013 | ai_registry | T4.6 | test_ai_inventory | Built |
| FR-014 | ai_registry.governance | T4.7 | test_employee_ai_governance | Partial: OD-06 visibility controls |
| FR-015 | ai_registry.product_checks | T4.8, T5.2 | test_product_checks | Partial: OD-05 |
| FR-016 | inference | T1.9, T1.10 | test_gateway | Partial: stub, OD-02 |
| FR-017 | inference | T1.9, T2.8 | test_no_fallback, test_egress | Built |
| FR-018 | inference.external, approvals | T2.6, T2.7, T2.9 | test_approval_binding | Built without transport: Interface (OD-14) |
| FR-019 | findings | T5.1, T5.2 | test_findings, test_detectors | Built |
| FR-020 | risk | T5.3 | test_risk_register | Built (no scale: OD-11) |
| FR-021 | findings, risk | T5.1, T5.3 | Separate tables; acceptance-link test | Built |
| FR-022 | memory, registry (as_of) | T5.4, T3.4 | test_memory_governance, as_of test | Built |
| FR-023 | policy | T1.11-T1.13 | test_engine_defaults, test_loader | Built |
| FR-024 | identity, policy | T1.4, T1.13 | test_roles, test_escalation | Built |
| FR-025 | approvals | T2.1 | test_approvals | Built |
| FR-026 | execution | T2.2-T2.4 | broker suites | Built (outbox tools only) |
| FR-027 | policy, execution | T1.13, T2.3 | L3 deny tests; L4 require_approval | Built; zero playbooks (OD-15) |
| FR-028 | audit (+ all) | T1.1, T1.2, T6.5 | test_tamper, test_anchor, test_audit_completeness | Built |
| FR-029 | workflows, connectors | T1.7, T3.8, T6.2 | test_queue_recovery, test_outage_replay | Built |
| FR-030 | killswitch | T1.6, T6.3 | test_killswitch_acceptance | Built |
| FR-031 | evidence.access, connectors manifest, employee | T3.2, T3.6, T5.8, T6.1 | privacy suite | Built (retention values: OD-17) |
| FR-032 | reporting | T5.7 | test_summary | Built |
| FR-033 | employee | T5.8 | test_employee_visibility | Interface: OD-12 channel |
| FR-034 | none | D0.1 | ADR only | Deferred: OD-10, OD-18 |
| FR-035 | none | D0.1 | ADR only | Deferred: OD-11 |
| NFR-001 | all | T0.6 | Architecture tests | Built |
| NFR-002 | app.settings, inference | T1.14, T1.9 | test_settings (loopback, local-only) | Built (office host: OD-01) |
| NFR-003 | arch tests, conftest guard, inference.external | T0.5, T0.6, T2.8 | test_network_imports, test_egress | Built (host egress firewall: OD-01) |
| NFR-004 | identity | T1.4, T1.5 | test_authn | Partial: no MFA or SSO (OD-03); workload identity is an Actor row |
| NFR-005 | api, policy, execution | T1.15, T1.13, T2.3 | Route-permission test; execution-time re-eval spy | Built |
| NFR-006 | audit | T1.1, T1.2, T6.5 | test_tamper, test_anchor | Built |
| NFR-007 | evidence, ops.backup, secrets | T3.1, T3.2, T1.16 | test_store, test_backup_encryption | Partial: no TLS on loopback; retention (OD-17) |
| NFR-008 | workflows, ops | T1.7, T1.16, T1.17 | resilience suite | Built |
| NFR-009 | discovery, execution, policy | T4.3, T2.3, T1.13 | discovery_safety, broker suites | Built |
| NFR-010 | common.db, adr | T0.4, D0.1 | Base gate; ADR-0012 | Built |
| NFR-011 | protocols | T0.3, T3.7, T1.9 | Contract tests run against 2 implementations (fixture + fault fake; stub + adversarial provider) | Built |
| NFR-012 | observability | T1.8 | test_observability | Built (no exporter) |
| NFR-013 | none | n/a | No targets in code; reviewer check | Deferred by design (§15.1) |
| NFR-014 | registry, identity | T3.10 | Fixture uses 500+ identities as a no-ceiling check, not a performance target | Built |
| NFR-015 | api routers | T3.9, T5.9 | Response schema includes state and explanation fields | Built |
| NFR-016 | audit DB, secrets, arch tests | T1.1, T0.6 | Separate audit file; import rules | Partial: no process isolation (ADR-0010) |
| NFR-017 | execution, inference, killswitch | T2.3, T2.8, T1.6 | Fail-closed tests | Built |
| NFR-018 | ops, observability | T1.16, T1.17, T6.2 | test_restart, test_outage_replay | Built |

App D bullet not achievable locally: "office-hosted deployment runs with private service boundaries" (OD-01, ADR-0010). The DoD doc must state this rather than tick it.

---

## 5. Build risks, ranked

| # | Risk | Early signal | Mitigation |
|---|---|---|---|
| 1 | Builders in one checkout touch each other's files: repo-wide `ruff --fix`/`ruff format`, editing `pyproject.toml`, `conftest.py` or `api/app.py` | `git status --porcelain` after each task shows paths outside the task's ownership list | Coordinator diffs changed paths against the ownership table before accepting. Brief: format only owned paths. No `uv add` or `uv sync` by builders; all deps are pinned in T0.1. |
| 2 | Concurrent test runs collide on shared state: `.pytest_cache`, `.mypy_cache`, `__pycache__`, a stray `data/` DB, the uv lock | Intermittent "database is locked" or corrupted mypy cache; `data/` appears in the tree | `-p no:cacheprovider`, PYTHONDONTWRITEBYTECODE=1, `mypy --cache-dir .mypy_cache_<agent>`, `ruff --no-cache`. All DBs in `tmp_path`. A conftest assertion that `data/` is untouched. Paste the agents.md background block into every builder brief. |
| 3 | Safety tests pass vacuously: a stub allows everything, the guard never runs, an architecture rule scans 0 files | Test count per marker or per rule is 0; mutation of a guard leaves the suite green | Architecture tests report counts. Meta-test on markers. Hand mutation step in the M1, M2 and M5 gates on policy/engine, execution/broker, external/gateway, discovery/active and audit/log. |
| 4 | Deferred decisions get hardcoded (classification labels, retention days, freshness, approver role, scales) | Numeric literals or label strings in guard modules; the reviewer's OD column doesn't match the diff | Single safety-settings ADR; unset means fail closed; each brief carries its task's OD column; code review checks it. |
| 5 | Shared contracts change mid-milestone (enums, Principal, protocols) | A builder asks to edit `ciso.common` | Contracts are coordinator-only. Change requests are queued and applied between lanes, never mid-lane. |
| 6 | SQLite concurrency under TestClient threads plus the queue worker | Flaky lock errors first show in T1.7 and T1.15 | WAL plus busy_timeout from T0.4; the T1.7 concurrent-lease test runs early; one writer connection per module service. |
| 7 | Windows-specific failures: signal semantics for graceful shutdown, `os.replace` on open files, subprocess kill in resilience tests | T1.16 and T1.17 fail on Windows only | Online backup API; resilience tests use `subprocess` plus `taskkill /F /T`; no POSIX signals assumed. |
| 8 | Cross-DB inconsistency between audit and ops (G5) produces states nobody tests | Recovery tests find rows with no matching audit record | Audit-first rule; `unknown_outcome` state; T2.4 and T6.2. |
| 9 | Static import scanning is evadable (dynamic imports, plugins) | Code review finds `importlib` or `getattr`-based loading | Ban those in guarded packages (T0.6); keep the runtime socket guard as a second layer. |
| 10 | Scope creep into §6.3's ~50 entity kinds as separate tables | A registry PR adds per-kind tables | Kinds are vocabulary data in one `entity` table; reviewed at T3.3. |
| 11 | Toolchain availability: uv, Python 3.13 on this machine | T0.1 fails | T0.1 runs first, alone; it's a 10-minute check and blocks nothing else. |

---

**Decisions for you (blocked on you):**
- G33: should self-approval be forbidden by default?
- G28: API-only for this build, or a console now?
- G14: fail closed when safety knobs are unset, or provisional defaults recorded in an ADR? I recommend fail closed: it is the only option that can't silently resolve a deferred decision.

**Queued:** nothing has been dispatched; this is a plan only.

**Next step:** you approve the G-list resolutions, then the coordinator runs T0.1-T0.6 serially while lane D starts the ADRs.
