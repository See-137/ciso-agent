# M1 review: queue, observability, whole-tree correctness

Saved verbatim from the reviewing agent's report, 2026-11-17. Findings are tracked in
`docs/plan/followups.md`. Probe scripts named here lived in a session scratchpad and may be gone.

---

Findings are below, split by what I ran and what I only read. Probe scripts are in `C:\Users\<user>\AppData\Local\Temp\claude\89363c7559032d42\1304fad4-2155-48c0-8a06-85e7efb17aae\scratchpad`. They are `probe_lease.py`, `probe_edge.py`, `probe_misc.py`, `probe_race.py` and `probe_loader.py`. I changed nothing in the repo.

Baseline: `uv run pytest tests/workflows tests/observability tests/resilience` passes. mypy on `ciso.workflows` and `ciso.observability` is clean, and ruff is clean on `src` and the three test directories.

## Must fix before building on this

**[HIGH] Nothing on the operational engine takes the write lock before a read-then-write. Proven.**
- File: `src/ciso/common/db.py:63-86`, used everywhere as `engine.begin()`.
- Cause: pysqlite only issues BEGIN at the first DML statement. A SELECT inside `engine.begin()` holds no snapshot or lock, so every "check, then write" in the codebase can interleave with another process.
- Proven by probe, with two engines on one file:
  - `bootstrap_first_admin`: with the interleave forced, both callers passed `active_admin_exists` and both returned `ok`. Two first admins and two tokens were created (`identity/authn.py:347-376`).
  - `KillSwitch.initialise()`, 6 concurrent callers: 2 `ok`, 4 raw `IntegrityError`. Same select-then-insert pattern (`killswitch/service.py:229-243`).
  - The same pattern exists, not probed, in `revoke_token` (double revoke, double audit), `_set_status`, and `init_operational_schema` (`schema_version` insert).
- Fix: in `create_db_engine`, apply the SQLAlchemy recipe for pysqlite. Set `isolation_level=None` on connect and emit `BEGIN IMMEDIATE` from a `begin` event. Then `engine.begin()` really is a serialized write transaction. Before you do that, restructure `Authenticator.authenticate` (`authn.py:299-331`). It runs scrypt and an audit append (fsync plus anchor) inside the transaction, and that would become a global write lock held per request. Do the read and verify first, then a short write transaction.

**[HIGH] `complete`, `fail` and `replay` ignore the result of `_guarded_update`. Proven.**
- File: `src/ciso/workflows/queue.py:241,269,307`. `_guarded_update` returns False when the row changed underneath.
- Scenario: worker A passes `_held_by` just before expiry. The clock passes expiry and worker B leases the job. A's guarded update matches no row.
- Probe 2 output: `complete() returned state leased owner B -> caller A thinks success, no exception`.
- For `replay`, the audit record already says SUCCESS while the update may have lost.
- Fix: check the boolean and raise `Conflict`. Add a test that forces the lost-guard branch. No current test reaches it.

**[HIGH] No lease renewal, and `complete` refuses once the lease has expired even if nobody took the job. From reading.**
- File: `queue.py:236-249,360-370`.
- The module docstring says "a lease that nobody renews simply expires", but there is no `renew` or `extend` method.
- Any job that runs longer than `lease_seconds` is picked up by a second worker and run twice.
- If that happens on the last attempt, the next `lease()` dead-letters a job whose first worker is still working (`queue.py:213-223`).
- Fix: add `renew(job_id, worker_id)`. Let `complete` and `fail` succeed when the row is still leased by the same worker with the same attempt number, even if the lease has expired. The guard already protects against takeover.

**[HIGH] The inference timeout is not enforced. From reading.**
- File: `src/ciso/inference/gateway.py:88-96`.
- `provider.complete()` is called with no deadline. The "timeout" compares `response.elapsed_seconds`, which the provider reports about itself.
- A hung provider hangs the caller forever. The `inference_timeout_seconds` setting suggests enforcement that does not exist.
- Fix: run the provider call with a real deadline (worker thread plus `future.result(timeout)`), or state plainly that the limit is advisory.

**[HIGH] `Principal.scopes` can be changed after construction. Proven.**
- File: `src/ciso/common/principal.py:22`. `dict[str, frozenset[str]]` inside a frozen model.
- Probe: `p.scopes["system"] = {...two systems}` and `p.scopes["environment"] = {"prod"}` both succeeded. A holder of the authority object can widen its own scope.
- The same applies to `ActionEnvelope.arguments: dict[str, JsonValue]`, so mutating after approval changes `envelope_hash()`. That one is from reading, not probed.
- Also proven: `HealthReport.components` is a plain list that can be appended to. `Job.payload` and `InferenceRequest.inputs` are the same pattern.
- Fix: use `MappingProxyType` or a frozen mapping with a validator that copies, and use tuples instead of lists.

## Should fix soon

**Queue**
- **[MED] Enqueue dedupe silently drops differing content. Proven.** Enqueueing `kind=k2, payload={"zzz":1}` for an existing `(source, event_id)` returned the old job with payload `{'n': 7}` and kind `k`. No error and no "created" flag (`queue.py:179-190`). Raise `Conflict` when kind, payload or ordering key differ, or return `(job, created)`.
- **[MED] NaN and inf are accepted as knobs. Proven.**
  - `JobQueue(lease_seconds=nan)` constructs fine, then `lease()` raises `ValueError: cannot convert float NaN to integer`.
  - `inf` raises `OverflowError` at lease time.
  - `SafetySettings(queue_lease_seconds=inf)` is accepted (`settings.py:24`).
  - `max_attempts=2.5` and `max_attempts=True` are also accepted.
  - Fix: use `math.isfinite` in `_positive`, add `allow_inf_nan=False` to the `Seconds` type in settings, and type-check the int knobs.
- **[MED] Dead-letter unblocks successors, and replay can break FIFO. From reading.** `_next_candidate` (`queue.py:390-394`) treats only PENDING and LEASED as blocking. Once `a1` is dead, `a2` runs. Replaying `a1` later runs it after `a2`, or concurrently with a leased `a2` for the same key. The test `test_dead_letter_does_not_block_its_ordering_key` pins this. If that is the intended policy, document it. Otherwise block on DEAD until replayed or discarded.
- **[MED] Replay audit order. From reading.** `queue.py:305` writes a SUCCESS outcome before the update and commit. The rule in `audit/log.py` is ATTEMPT first, then the result. If the update or commit fails you have a false SUCCESS record. `KillSwitch.release` (`killswitch/service.py:274-280`) has the same shape: audit inside the transaction, then a commit that can fail.
- **[MED] Locked database and disk errors surface as raw `sqlalchemy.exc.OperationalError`. Proven.** With a foreign `BEGIN IMMEDIATE` held, `lease` raised after about 5.4 s and `enqueue` after about 5.3 s. The audit log and the kill switch wrap these in `FailClosed`, so the error types differ between modules.
- **[MED] Lease can spin forever on other databases. From reading.** `lease()` is `while True`, and `_guarded_update` compares `updated_at ==`. On a database with millisecond or second timestamp precision the guard never matches, so the loop never ends. The same goes for `String(n)` columns: `event_id`, `source`, `kind` and `ordering_key` have no length validation at enqueue. SQLite ignores the limits and another database will not.
- **[LOW]**
  - `log = logging.getLogger(...)` at `queue.py:43` is never used (dead code).
  - Dead-lettering on expiry is not logged, audited or counted.
  - There is no purge for DONE or DEAD rows, and dedupe requires keeping them.
  - `dead_letters()` is unbounded.
  - A clock stepping backwards extends leases and backoff and makes `oldest_pending_age_seconds` negative.
  - A row with corrupt payload JSON would wedge every worker at `limit(1)`.

**Observability**
- **[MED] `HealthRegistry.aggregate()` races with `register()`. Proven.** Output: `RuntimeError: dictionary changed size during iteration` (`health.py:87`). Iterate over `list(self._checks.items())` under a lock. Checks have no timeout, as the docstring admits, so one hung check hangs the health endpoint.
- **[MED] Unredacted output channels. Partly proven.**
  - A logger with its own handler and `propagate=False` bypasses redaction. Proven: `propagate=False logger leaked: True`.
  - uvicorn's default config does exactly this: `uvicorn` and `uvicorn.access` have `propagate: False` with their own handlers, so access logs, including query strings, skip the redactor.
  - `configure_logging` does not replace or inspect existing root handlers, and it is not idempotent. A second call produced 2 lines for one record.
  - Fix: use a `logging.config` dictConfig-style setup that owns the handlers, or a `logging.Filter` or log record factory.
- **[MED] Dropped records are invisible.** `handleError` increments `handler.dropped` and nothing reads it. It is not wired to a metric or to health, so a broken redactor looks like a quiet system.
- **[LOW]**
  - NaN is emitted as bare `NaN`, which is invalid JSON. Proven.
  - `MetricsRegistry.inc(name, amount, **labels)` breaks for label names `name`, `amount` and (for gauges) `value`. Proven: `TypeError multiple values for argument 'name'`.
  - `snapshot()` returns tuple keys, so it is not JSON-serializable once it holds data. The test at `test_observability.py:195` pins that shape.
  - There is no cap on label cardinality.
  - `CheckResult.reason` is not redacted.
  - `observability/__init__.py` exports nothing (9 public names). `app/__init__` has no `__all__` either. Minor gaps are `AnchorKey`, `MatchFacts` and `RuleSetDocument`.

**Cross-tree**
- **[MED] Audit anchor wedge, and a Windows replace failure. Partly proven.**
  - `audit/log.py:128-133` writes the anchor, then COMMITs. If COMMIT fails (disk full, I/O error) the anchor is one record ahead and the log refuses all further appends until a person intervenes. The docstring says this is intended for crashes. A transient COMMIT error should not need the same manual repair. From reading.
  - `HeadAnchor.write` uses `tmp.replace` (`anchor.py:132`). With a second handle reading the file, 361 of 598 writes raised `FailClosed`. The in-process lock does not cover another process or an antivirus scan. In practice an append fails and rolls back. Retry the replace with a short backoff, or read via a share-delete handle.
- **[MED] `KillSwitch._deliver` (`killswitch/service.py:335-355`). From reading.**
  - If `_mark(delivered_at)` raises after `audit.append` succeeded, `engage` raises a raw error although the flags are already engaged.
  - The row stays pending, so `retry_pending_audit` appends a duplicate audit event. There is no idempotency key.
  - `engage` also calls `_states` after the commit. If `status()` fails, it raises `FailClosed` even though the engage persisted.
- **[MED] `load_ruleset` raises, contrary to its docstring. Proven.** A file with invalid UTF-8 raised `UnicodeDecodeError`, and 100,000 nested brackets raised `RecursionError`. Only `OSError` and `ValueError` from the JSON parse are caught (`policy/loader.py:46-60`). Catch `UnicodeDecodeError` and `RecursionError` too, so a bad file always yields deny-all.
- **[LOW]**
  - `ensure_utc` raises a bare `ValueError` for naive datetimes. It is called from `assign_role` (`service.py:325-326`), `audit.query` and `AuditLog.append`. Callers expecting `ValidationFailed` do not get it.
  - `load_settings` lets `UnicodeDecodeError` and `PermissionError` through raw.
  - `PolicyEngine._freshness` calls `answer.get` outside `_ask`. A context that returns a non-dict makes `evaluate` raise `AttributeError` instead of denying.
  - Every malformed token appends a hash-chained audit record with fsync under the global audit write lock. Unauthenticated traffic can bloat and slow the audit path. Worth a note to the security reviewers.
  - `identity/service.py` is 435 lines, `authn.py` is 387 and `bootstrap_first_admin` is 51 lines. Those are marginal against the 400/50 guideline.

## Tests

- **No test exercises concurrency.** There are no threaded or two-engine tests in `tests/workflows` or `tests/resilience`, though double-lease prevention is the queue's main guarantee. My probe found 0 double leases, so a test would pass today. It guards a regression, not a current bug.
- **The resilience test is thinner than its name.** It restarts by `engine.dispose()` on a clean state. It never kills a process mid-transaction and never has two engines open at once.
- **Observability tests use `FakeRedactor`, a substring replace.** They never run the real vault redactor, and nothing tests `propagate=False`, a second handler, or double configure.
- **Untested guarantees:**
  - Metrics claim "safe to share between threads", with no threaded test.
  - There are no tests for the NaN or inf knobs, for `complete` after expiry with no takeover, or for the guard-lost branch.
  - There is no clock-backwards test.
  - There is no test that dead-lettering on expiry is recorded anywhere.
- **No test depends on wall-clock time.** All queue tests use `FixedClock`.

## Checked and found sound

- **Lease atomicity:** 8 workers against 200 jobs on a file database, as threads sharing one engine and as separate engines. Both runs gave 200 unique leases, 0 double leases, 0 jobs never leased and 0 errors. The optimistic guard in `lease` works even without the write lock.
- **Enqueue dedupe under concurrency:** 8 concurrent callers on 2 engines returned 1 distinct job id, 1 row and 0 errors.
- **FIFO per key under retry:** a retry-waiting `a1` keeps `a2` blocked. Covered by `test_fifo_per_ordering_key` and the restart test.
- **Fail-closed on unset knobs** is genuinely enforced for the queue's own operations.
- **Health aggregate:**
  - An empty registry gives UNKNOWN.
  - A raising or non-`CheckResult` check gives UNKNOWN.
  - Severity ranking is correct.
  - `BaseException` propagates, which is acceptable.
  - NFR-018 holds for the paths I tried.
- **Per-record redaction:** a secret in the message, args, extras (including dict keys, via the final-line pass), tracebacks and object reprs was redacted. A redactor that raises drops the record instead of leaking it. Root level and handlers are restorable.
- **Kill switch:** the fail-closed read path (`is_blocked` returns True on any error) is sound.
- **Audit log:** BEGIN IMMEDIATE plus an in-process lock, and the verify logic, look correct.
- **Other:** scrypt handling is constant-time and uniform. The `UtcDateTime` type is consistent. No `datetime.now` is used outside `SystemClock`.

## Suggested order

1. Add BEGIN IMMEDIATE, then restructure `authenticate`.
2. Check the guard result in `complete`, `fail` and `replay`, and add `renew`.
3. Freeze `Principal.scopes`, `ActionEnvelope.arguments` and the report lists.
4. Enforce the inference deadline.
5. Add the concurrency tests to `tests/workflows`.
