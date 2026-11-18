# ADR-0019: Provisional safety parameters (unset means refuse; values only from a named file)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (five new knobs; token and inference timeout rows; which knobs are read today)
Blueprint refs: §5.1 #2 and #12, §6.5, §7.3, §7.6, §9.4, §10.4, §11 (resource exhaustion row), §13.4, §15.1, NFR-013, NFR-017, OD-02, OD-03, OD-04, OD-13, OD-15; plan gap G14

## Context
BP §15.1 says: "Do not invent throughput, latency or model context requirements." Yet several controls the BP requires cannot run without a number: a short validity window for an action envelope (§9.4), approval expiry, a source-specific freshness policy (§6.5), grace periods before retirement (§7.6), rate limits and concurrency ceilings for scans (§7.3), rate limits for tools and the API (§5.1), retry ceilings and backoff (§13.4). The BP gives none of these values. If builders pick them quietly, a deferred decision is made in code (plan gap G14).

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Every numeric safety knob defaults to unset; unset means the feature refuses; values are loaded only from a settings file that is named explicitly | No number is decided silently; a missing value is loud, not permissive | Out of the box the platform observes and refuses; every deployment and every test must supply values | Fail closed. A forgotten value cannot become an unlimited one |
| Built-in defaults in code | Works immediately | The defaults become decisions nobody made | A default chosen for convenience may be too loose for a real environment |
| Unset means unlimited | Nothing blocks | No expiry, no rate limit, no ceiling until someone notices | Rejected; contradicts NFR-017 |
| Wait for Phase 0 before building any bounded feature | No provisional number exists anywhere | The controls themselves go unbuilt and untested | Delays the safeguards the numbers are for |

## Default chosen for the local build
All knobs are fields of `ciso.app.settings.SafetySettings` and default to `None`. A component that receives `None` refuses to act. `load_settings(None)` gives the all-refusing defaults. A settings file is read only when its path is given, and an unknown key in the file is an error, so a misspelt knob cannot stay silently unset. A number must be greater than zero and finite (not-a-number and infinity are refused), and a count must be a real integer greater than zero. `Settings.missing_for_writes()` names the unset values without which no write path can run: the audit and kill-switch key references, `max_envelope_ttl_seconds`, `approval_ttl_seconds` and `max_token_ttl_seconds`.

`config/provisional-settings.json` holds provisional values so the platform can be exercised locally. The table quotes that file exactly. **None of these values is a recommendation or an agreed decision.** They are placeholders to be replaced after Phase 0.

| Knob | What it bounds | Provisional value in the file | Evidence that would set the real value |
|---|---|---|---|
| `max_token_ttl_seconds` | Longest lifetime of a bootstrap token. Unset means no token is issued. A sole administrator whose token expires is locked out until the host-local recovery command issues a new one (ADR-0004) | 43200 | The company's session and authentication policy; the identity system (OD-03) |
| `max_envelope_ttl_seconds` | Longest validity window of an action envelope (BP §9.4) | 900 | Observed time from proposal to execution in real workflows; how quickly preconditions go stale on the first write targets (OD-13, OD-15) |
| `approval_ttl_seconds` | How long an approval stays usable | 3600 | Approver availability from the role mapping; observed approval response times; the per-request UX for external inference (OD-14) |
| `queue_lease_seconds` | How long a worker holds a job before it becomes available again | 300 | Measured duration of each job handler; a lease must outlast the longest job |
| `queue_max_attempts` | Retry ceiling before a job is dead-lettered (BP §13.4) | 5 | Failure patterns and retry guidance of each source, from the source-system matrix |
| `queue_backoff_base_seconds` | First retry delay | 5 | Rate limits and quota behaviour of each source, from the source-system matrix |
| `queue_backoff_max_seconds` | Longest retry delay | 600 | The same, plus how long each source retains events for replay |
| `inference_timeout_seconds` | Deadline the gateway enforces on a local inference call, measured by the gateway's own monotonic clock on a worker thread. A late answer is never returned. A thread cannot be killed, so a call that missed its deadline runs on until the provider returns | 120 | The benchmark of the chosen model and runtime on the approved host (OD-02, OD-01) |
| `inference_max_abandoned_calls` | How many calls that missed their deadline may still be running before the gateway refuses new work. Unset means one abandoned call is enough to refuse | 2 | The behaviour of the chosen runtime when a call is abandoned; its own deadline handling (OD-02) |
| `audit_witness_every` | How often the audit head is published to the witness: every N appends. Required when a witness is configured; no consumer yet (the witness is not wired into the composition root) | 1 | Where the witness lives and what a publish costs there; how much rollback window the owner accepts (ADR-0013, OD-01) |
| `killswitch_claim_timeout_seconds` | How long a claim on an owed kill-switch audit record holds before another delivery loop may take it over. Unset means a claim is never taken over | 300 | Observed delivery time of the audit log under load (ADR-0018) |
| `health_check_timeout_seconds` | Time limit for each health check. A check that runs past it reads `unknown`. Unset means no check is run and every component reads `unknown` | 5 | The slowest legitimate check on the approved host; how often health is polled (ADR-0020) |
| `metrics_max_series_per_metric` | Most distinct label sets one metric may hold. A new label set past the cap is refused and counted. Unset allows only the unlabelled series | 200 | The labels metrics really need, and the memory the host can spare (ADR-0020) |
| `fact_freshness_seconds` | Age after which a fact is no longer current | 86400 | The owner's freshness expectation and the sync method per source, from the source-system matrix |
| `fact_expiry_seconds` | Age after which a fact is expired | 604800 | The same; the BP expects a source-specific policy (§6.5) |
| `retirement_grace_seconds` | How long an asset may be missing from a source before it is treated as suspected retired (BP §7.6) | 1209600 | Sync cadence and outage history per source; the BP expects source-specific grace periods and cross-source confirmation |
| `event_clock_skew_seconds` | Largest accepted difference between an event's timestamp and the platform clock | 300 | Time synchronization on the approved host (OD-01); observed timestamp drift and delivery delay per source |
| `scan_max_rate_per_second` | Rate ceiling for bounded active discovery (BP §7.3) | 1 | Approved scan profiles per environment and what each System Owner accepts for production targets (OD-04) |
| `scan_max_concurrency` | Concurrency ceiling for bounded active discovery | 1 | The same |
| `tool_rate_limit_per_minute` | How often the execution broker may call a tool | 10 | API limits of the first real write target and the blast radius accepted for each playbook (OD-13, OD-15) |
| `api_rate_limit_per_minute` | Request rate accepted at the API edge (BP §5.1 #2) | 120 | Number of administrators and automation clients; measured API use after Phase 0 |

`SafetySettings` also holds `allow_self_approval` (`false` in the file). It is not a number and is covered by ADR-0016.

Which knobs the code reads today, from a search of `src`: `max_token_ttl_seconds`, `max_envelope_ttl_seconds`, `queue_lease_seconds`, `queue_max_attempts`, `queue_backoff_base_seconds`, `queue_backoff_max_seconds`, `inference_timeout_seconds`, `inference_max_abandoned_calls`, `killswitch_claim_timeout_seconds`, `health_check_timeout_seconds`, `metrics_max_series_per_metric` and `api_rate_limit_per_minute` all reach a service through the composition root or the API. `approval_ttl_seconds`, `allow_self_approval`, `audit_witness_every`, `fact_freshness_seconds`, `fact_expiry_seconds`, `retirement_grace_seconds`, `event_clock_skew_seconds`, `scan_max_rate_per_second`, `scan_max_concurrency` and `tool_rate_limit_per_minute` have no reader yet, because their modules (approvals, registry, discovery, execution, the audit witness wiring) are not built or not wired. A value in the file for them decides nothing today.

A safety number is also checked against the others: `queue_backoff_base_seconds` may not exceed `queue_backoff_max_seconds`, and `fact_freshness_seconds` may not exceed `fact_expiry_seconds`. 
Weaknesses of this default:
- A file of numbers in the repository invites someone to point a real deployment at it. The file's comment says it is provisional; nothing technical prevents the mistake.
- Freshness, expiry and retirement grace are single global values. The BP asks for source-specific policies (§6.5, §7.6). One value for all sources is a simplification that will be wrong for some of them.
- Whoever can edit the settings file changes the safety bounds. The file is not signed, and this ADR does not claim that the loaded values are recorded in the audit log at start.
- Refusing everything when unset is safe and also unhelpful: an operator who names no file sees a platform that does nothing and must work out why. Readiness lists what is missing, but a knob that nothing reads yet (see above) is not listed because nothing depends on it.
- The provisional file sets the witness cadence but no witness path or key, so the cadence has no effect there, and it names no anchor path, so the anchor stays under the data directory (ADR-0013).
- A timeout that is enforced by a thread the code cannot kill still ties up that thread until the provider returns, so `inference_timeout_seconds` bounds the caller's wait, not the provider's work.

## Why this default is reversible
Seam: `SafetySettings`, passed to components as explicit constructor arguments. Changing a value is an edit to a settings file. Making a knob per-source or per-environment means replacing one field with a lookup at the point where it is read; callers that receive the resolved value do not change.

## Evidence needed to make this final
Mostly Phase 0 workload discovery (BP §15.1): the filled source-system matrix (rate limits, sync method, freshness expectation), the role mapping, the host decision (OD-01) and the model benchmark (OD-02). Each row of the table names its own evidence. A value becomes final when the owner approves it with that evidence attached.

## Consequences
- With no settings file the platform is meant to refuse writes, approvals, scans, queue leasing and inference. Each component must have a test that shows it refuses when its knob is unset; a knob without such a test is a gap.
- Tests set the values they need, so a change to the provisional file cannot change a test result.
- Every value in the table needs an owner-approved replacement before real data or real sources are connected.
