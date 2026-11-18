# Unified CISO Agent: system design (baseline platform)

Status: working design for the local build. Source of truth for scope is
`docs/reference/blueprint-v1.0.txt` (the blueprint, "BP"). Where this file and the BP
disagree, the BP wins. Every technology choice below is a *proposed, reversible default*
recorded in an ADR under `docs/adr/`; none is final until the owner approves it (BP §3
change control, Appendix C).

## 1. What is being built, and what is not

Built now (needs no live company environment):

- The control-plane skeleton: identity, RBAC/ABAC, audit, secrets interface, kill switch.
- The security registry with field-level provenance, source authority and reconciliation.
- The connector contract, health/checkpoint handling, and a fixture connector that reads
  local files. No vendor connector: the first real source is a Phase 0 decision (BP §19.4 #7).
- Guided onboarding, the approved-scope registry, and the active-discovery guard.
- The inference gateway with a stub local runtime, and the external opt-in path that is
  disabled by default and cannot be reached automatically.
- Findings, a qualitative risk register, an AI asset registry.
- Action envelope, policy engine, approvals, execution broker (no playbooks enabled).
- An authenticated admin API and a minimal read-mostly console.
- Tests: unit, policy, external-inference, adversarial, discovery-safety, resilience.

Not built, on purpose (BP §1.2, §20):

- Real connectors to any identity provider, cloud, Git host, SaaS or AI provider.
- A real model runtime, hardware sizing, embeddings or reranking.
- Any network scanner. The active-discovery module enforces scope and records runs; the
  only "scanner" is a fake used in tests.
- Any L3 playbook, any write adapter to a real system, any external LLM transport.
- A risk-score formula, a compliance mapping, an employee chat channel.
- Phase 0 itself. It needs people. This repo ships the questionnaire and templates for it.

## 2. Requirements driving the design

| Driver | Source | Design consequence |
|---|---|---|
| LLM is not a root of trust | §9, §9.5 | Policy and execution are separate packages that may not import inference or orchestration; enforced by a test |
| Writes fail closed | §9.5, NFR-017 | Broker requires a live policy decision, audit write, kill-switch read and fresh preconditions, or it refuses |
| No external fallback | §8.4, FR-017 | One gateway; local errors raise; external path needs an approval bound to the exact payload hash |
| Source systems stay authoritative | §6.1 | Registry stores source facts per field; the resolved view is computed by authority rules; nothing is overwritten |
| Uncertainty stays visible | §7.5 | Every resolved field carries an information state, freshness and reconciliation state |
| Connector failure is not "clean" | §7.2, §7.7 | Coverage gaps are first-class records and show in reporting |
| Tamper-evident audit | NFR-006 | Hash-chained append-only log in its own database, with triggers that block update and delete |
| No secrets in prompts, logs, registry | §11.1 | Secret references only; a redaction filter on logging and on inference input |
| Replaceable runtime and connectors | NFR-011 | Protocol interfaces at each boundary; storage through SQLAlchemy Core |
| Do not invent SLOs | §15.1 | No performance targets in code or tests |

## 3. Components and trust boundaries

```
                 humans (admin console / API clients)
                          |
                  [ api ] authenticated control-plane API
                          |
        +-----------------+------------------+
        |                                    |
 [ orchestrator ]  ---- proposes ---->  [ policy ]  deterministic, no LLM imports
   |        |                               |
   |   [ inference ]                   [ execution ] broker, approvals
   |    gateway -> local stub               |
   |    external: disabled               write adapters (none shipped)
   |
 [ findings ] [ risk ] [ registry ] [ evidence ] [ discovery ] [ connectors ] [ workflows ]

 cross-cutting, importable by all:  [ common ] [ audit ] [ secrets ] [ identity ] [ killswitch ]
```

Import rules (a test parses the source tree and fails on a violation):

1. `ciso.policy`, `ciso.execution`, `ciso.audit`, `ciso.killswitch`, `ciso.identity`,
   `ciso.vault` never import `ciso.inference` or `ciso.orchestrator`.
2. `ciso.inference` never imports `ciso.execution` or `ciso.connectors`.
3. Network client libraries (`socket`, `http.client`, `urllib.request`, `httpx`,
   `requests`, `aiohttp`) may be imported only in an allowlist of modules. In this build
   the allowlist is empty outside tests.
4. `ciso.connectors` read connectors expose no method named `execute*` or `write*`.

Trust domains match BP §5.2: (a) user/API, (b) orchestrator and workflow worker,
(c) model serving, (d) connectors and discovery, (e) execution broker. In this build they
run in one process for development, but each is reachable only through its interface so
they can be split into processes without changing callers (ADR-0010).

## 4. Data flow (BP §5.3)

```
source / onboarding
   -> connector.list_assets / list_changes        (read-only, scoped)
   -> workflows queue                             (dedupe on event_id, retry, dead-letter)
   -> registry.ingest_source_fact                 (never overwrites; records provenance)
   -> registry.reconcile                          (authority rules -> resolved view + states)
   -> evidence.put                                (encrypted blob, hash, classification)
   -> findings.detect                             (deterministic detectors)
   -> inference.gateway.complete                  (local stub; output is untrusted)
   -> orchestrator builds ActionProposal          (schema-validated)
   -> policy.evaluate                             (deny | hold | require_approval | allow)
   -> execution.approvals                         (L4: human, bound to envelope hash, expiring)
   -> execution.broker.execute                    (allowlisted tool, preconditions, idempotency)
   -> verify against source                       (never trust the tool reply)
   -> audit.append + registry update
```

## 5. Module contracts

Package root is `src/ciso`. Each module owns its tables and exposes a small service class
that takes its dependencies as constructor arguments (no globals, no module-level state).

### common
`ids` (prefixed, sortable ids; `EntityRef` = `"<kind>:<id>"`), `clock` (injectable UTC
clock), `enums`, `errors`, `db` (engine factory; SQLite pragmas), `schemas` (Pydantic base
with `extra="forbid"`, frozen models).

Enums: `InformationState` verified|declared|inferred|disputed|unknown;
`FreshnessState` current|stale|expired|missing|unknown;
`ReconciliationState` matched|superseded|conflicting|awaiting_owner_validation|unresolved;
`Environment` production|staging|development|third_party|unknown;
`AuthorityLevel` L0..L4; `SecurityDomain` enterprise|product_ai|employee_ai|ciso_platform;
`DataClassification` public|internal|confidential|restricted|unknown (unknown is handled
as restricted, BP §11.1); `ActorType` human|service|agent.

### audit
`AuditLog.append(event) -> AuditRecord`; `AuditLog.verify() -> VerifyResult`;
`AuditLog.query(...)`. Record = id, seq, occurred_at, actor, actor_type, action, target,
outcome, correlation_id, details (JSON, redacted), prev_hash, hash. `hash` =
SHA-256 over the canonical JSON of the record plus `prev_hash`. Own database file. Triggers
abort UPDATE and DELETE. The log object has no delete or update method. If an append fails,
the caller must treat the operation as not allowed (used by the broker).

### vault (secrets interface)
`SecretStore.get(ref) -> SecretValue` where `ref` is `secret://<name>`. `SecretValue` hides
itself in `repr`/`str` and is not serialisable. Dev provider reads process environment
variables with a fixed prefix; nothing is written to disk by this repo. `Redactor` scrubs
known secret values and common token shapes from any string; it is applied to audit
details, log records and inference input.

### identity
Actors (human, service, agent), role templates from BP §9.3 (security_admin, system_owner,
executive_risk_owner, employee, auditor), role assignments with optional attribute scope
(system, environment), bootstrap credentials (random token shown once, stored as a scrypt
hash). `Authenticator.authenticate(token) -> Principal`. An OIDC adapter is an interface
only (OD-03). Agents and services can never hold `security_admin` or approver roles.

### killswitch
Persistent flags: `writes`, `external_inference`, `active_scans`, `l3_runs`. `engage` and
`release` require a human principal with `security_admin`; both are audited. Readers call
`KillSwitch.is_blocked(capability)`; a read failure counts as blocked.

### policy
`ActionEnvelope` (BP §9.4, every field), `PolicyDecision` (allow | deny | hold |
require_approval, with reasons, matched rule ids, policy version, evaluated_at).
`PolicyEngine.evaluate(envelope, context) -> PolicyDecision`. Rules are versioned data
(`policies/*.json`), loaded and validated at start; an unloadable policy set means every
write is denied. Default rule set: L0-L2 allow inside read scope and approved channels;
L3 deny unless a playbook record is approved, enabled and not expired; L4
require_approval; unknown operation deny; agent or service actor asking to change policy,
roles, approvers, audit or its own permissions deny, always.

### execution
`ApprovalService` (request, approve, reject; an approval binds to the envelope hash,
approver role, scope and expiry; approver must hold a role the policy names and must not
be the requester). `ToolRegistry` (allowlisted, typed tools; each declares authority
level, argument schema, preconditions, verification, rollback). `ExecutionBroker.execute`
performs, in order: kill switch, envelope schema, idempotency lookup, policy evaluate
*now*, approval check, expiry, preconditions, rate limit, audit "attempt" write, tool call,
independent verification, audit "result" write. Any step that cannot complete stops the
run. Tools shipped: only L2 coordination tools writing to local outboxes
(`create_ticket_draft`, `notify_owner_draft`), plus test fakes.

### registry
Tables: `entity` (kind, canonical id, lifecycle, first_seen, last_seen, last_verified,
owner_ref, criticality, environment), `source_fact` (entity, field, value, source_system,
source_record_id, field_authority, observed_at, received_at, valid_from, valid_until,
verification_state, evidence_ref), `relationship` (typed, from BP §6.4, with source,
evidence, timestamp, confidence), `authority_rule` (entity kind, field, ordered sources),
`conflict`. `Registry.ingest(fact)` appends. `Registry.resolve(entity) -> ResolvedEntity`
computes, per field: winning value, information state, freshness, reconciliation state,
and all competing assertions. Entity kinds cover BP §6.3. An entity that vanishes from
one source moves to `suspected_retired` after a grace period, never deleted.

### evidence
`EvidenceStore.put(bytes, classification, source, retention) -> EvidenceRef` and
`get(ref, principal, purpose)`. Blobs are AES-256-GCM encrypted on disk, content-hashed,
with metadata rows. Access is checked and audited. Key comes from `SecretStore`.

### connectors
`ReadConnector` protocol with BP §13.1 operations: `discover_sources`, `health_check`,
`list_assets`, `get_asset`, `list_changes`, `list_findings`, `get_configuration`,
`map_identity`, `checkpoint`. `ConnectorHealth` carries connectivity, auth validity,
quota, permission gaps, last success, degraded state. `EventEnvelope` per BP §13.2.
`WriteAdapter` is a different protocol in a different package and has no implementation.
`FixtureConnector` reads a directory of JSON files.

### workflows
Durable job queue in the database: enqueue, lease, complete, fail with backoff, retry
ceiling, dead-letter, replay, dedupe key. Survives restart (leases expire).

### discovery
`onboarding` (declare systems, accounts, repos, AI providers, owners: all recorded as
`declared`). `scopes` (approved scope registry: target kind, pattern, environment,
profile, approver, expiry, exclusions). `passive` (pull through connectors, write coverage
gaps on failure). `active` (`ActiveDiscovery.run(target, profile)` refuses anything not
matched by an approved, unexpired scope; refuses when the kill switch blocks scans; a deep
test needs a `TestPlan` with its own approval; every run is recorded). Scanner is an
interface with a fake.

### inference
`InferenceGateway.complete(request) -> InferenceResult` routes to the configured local
provider only. `StubLocalProvider` is deterministic. Failures raise `InferenceUnavailable`;
there is no alternate route in the gateway. `ExternalInferenceGateway` is a separate class:
`propose -> preview -> minimize -> authorize -> transmit -> record -> reintegrate` (BP
§8.4). `transmit` requires: feature enabled in config (default off), kill switch clear, an
approval whose payload hash equals the hash of the bytes about to be sent, an unexpired
approval, a human approver with the configured role. Transport is an interface with no
implementation shipped. Output from either path is wrapped as `UntrustedModelOutput` and
must pass schema validation before it can become a proposal. Every call is logged with
model, task category, context refs and timing; prompt bodies are not logged.

### findings, risk
`Finding` per BP §13.3 with status lifecycle and dedupe fingerprint. Deterministic
detectors: disputed facts, stale verified facts, unowned assets, connector coverage gaps,
declared-but-unverified AI providers, identities with access after departure.
`RiskRegister`: qualitative impact and likelihood inputs, owner, status, exceptions with
expiry, review date. Acceptance requires a human `executive_risk_owner`. No numeric score.

### orchestrator
Bounded task runner: step budget, timeout, no recursion. Builds context from registry and
evidence refs, calls the inference gateway, validates output, produces proposals, hands
them to policy. Holds no credentials and no tool handles.

### api
FastAPI. Bearer auth through `Authenticator`; every route declares the permission it
needs; server-side checks only. Routes for onboarding, scopes, registry views (including
unknown, stale, disputed filters), connectors health, findings, risks, approvals, audit
(read), kill switch, external-inference approvals, reporting summary. Binds to loopback by
default.

## 6. Storage

Two SQLite files in development: `data/ciso.db` (operational) and `data/audit.db` (audit
only). Evidence blobs under `data/evidence/`. `data/` is git-ignored. SQLAlchemy Core keeps
the SQL portable to PostgreSQL; the choice of production database stays open (ADR-0002).
Schema is created from each module's table definitions; a `schema_version(module, version)` row
is kept per module and a mismatch refuses to start. No migration tool is chosen (ADR-0002).

## 7. Reliability

Single host, no HA (BP §10.3). Restart safety comes from: durable queue with lease expiry,
connector checkpoints, idempotency keys on execution, WAL mode. Backup uses the SQLite
online backup API into an encrypted archive; a restore test verifies the audit chain and
row counts. No performance targets are set (BP §15.1).

## 8. Trade-offs taken

| Choice | Gain | Cost | Revisit when |
|---|---|---|---|
| One process, strict module boundaries | Simple to run and test | Boundaries are by convention plus a test, not by OS | Before any real write adapter exists |
| SQLite | Zero setup, real transactions | One writer; no network access | Phase 0 shows multi-process or volume needs |
| In-process policy engine | Typed, testable, no extra service | Not a separate administrative boundary | Before L3 is enabled |
| Stub model | Whole platform testable without a GPU | Says nothing about real model quality | OD-02 benchmark |
| Fixture connector only | No vendor assumption | Contract is unproven against a real API | Phase 0 picks the first source |
| Bootstrap tokens | Works with no IdP | No SSO, no MFA | OD-03 resolved |

## 9. Open items this build deliberately leaves open

OD-01 to OD-18 from BP §20 are tracked in `docs/adr/open-decisions.md`. Each ADR lists the
evidence needed to close it.

## 10. Revisions after plan review (2026-11-17)

The planner checked this design against the blueprint and found 33 gaps
(`docs/plan/implementation-plan.md` section 1). `docs/plan/decisions.md` records which were
accepted. Where the sections above disagree with the list below, the list below is right.

- Approvals are their own package, `ciso.approvals`, used by both the execution broker and
  the external inference gateway. An approval binds to the subject hash, the approver
  role, the scope and an expiry, is single-use, and is re-validated when it is checked
  (a role revoked after approval makes it invalid).
- The external inference gateway is its own package, `ciso.inference.external`. Only the
  API router a human calls and the composition root may import it; a test enforces this.
  Its approval binds payload hash, provider, model, purpose and request id.
- The audit log adds an HMAC-keyed head anchor stored outside the audit database, so tail
  truncation and a full recompute of the chain are detected.
- Executions have explicit states including `unknown_outcome`; the attempt is audited
  before the side effect; in-flight executions at restart must be verified before a retry.
- New modules: `ciso.memory` (governed, versioned knowledge; agent writes wait for human
  review), `ciso.ai_registry` (employee AI, product AI and the CISO's own model, kept
  separate), `ciso.observability`, `ciso.reporting`, `ciso.employee` (report record only),
  `ciso.ops` (backup, restore, lifecycle), `ciso.write_adapters` (contract only).
- Classification labels are configuration (`ClassificationScheme`), not an enum.
- A tenant reference is carried on source facts, evidence metadata and findings, and
  filtered on at evidence access.
- Connectors register an approved scope; a record outside it is rejected, audited and
  shown in connector health. Events are deduplicated on `(source_system, event_id)`.
- Data-flow order is: payload, `evidence.put`, event envelope with `payload_ref`, queue,
  `registry.ingest` with `evidence_ref`.
- `Environment` has `customer_owned`, which is never scannable.
- Numeric safety parameters have no defaults; unset means the feature refuses.
- No console is built. The API and its OpenAPI document are the interface.
- The API has an in-process rate limiter.

