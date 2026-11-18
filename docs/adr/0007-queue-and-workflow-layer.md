# ADR-0007: Queue and workflow layer (database-backed durable job queue)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (lease renewal, dead-letter blocking, discard, guard checks)
Blueprint refs: §1.2, §3 (register items "Availability", AGREED INITIAL SIMPLIFICATION, and "Technology stack", DEFERRED), §5.1 #13, §10.3, §13.4, FR-029, NFR-008, NFR-018, Appendix C #14; plan gap G15

## Context
The BP requires a workflow/event layer with durable jobs, retries, event ingestion, scheduling and replay after outage, with deduplication, ordering where required, dead-letter and replay controls (§5.1 #13). §10.3 asks for durable local queues or source-side replay where feasible and accepts a temporary outage. §13.4 requires backoff, quota handling, retry ceilings and dead-letter queues. No queue or workflow engine is selected (§1.2, §3).

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Database-backed durable job queue with leases, retries, dead-letter and replay; no broker product | No extra service; jobs are in the same transactional store as the data they change; survives restart | Polling, not push; throughput bounded by the database's single writer (ADR-0002); queue code is ours to test | No new network listener or credentials; queue rows share the operational database's access boundary |
| A message broker product | Push delivery; higher throughput; fan-out to several consumers | A service to run, secure and back up; delivery state lives outside the database, so exactly-once effects need extra care | New listener and credentials to protect; BP §10.2 would require it to stay private |
| A workflow engine product | Built-in multi-step state, timers and human-wait steps | Heavier operational footprint; a programming model that shapes the whole codebase | Another privileged component holding workflow state |
| In-memory queue with a scheduler | Trivial | Jobs are lost on restart | Fails NFR-008 and NFR-018; rejected |
| Host scheduler running scripts | Familiar | No leases, retries, dedupe or dead-letter | Failures are easy to miss; a missed run could be read as "clean" (BP §7.2) |

## Default chosen for the local build
`ciso.workflows` (`queue.py`, `tables.py`): one job table in the operational database. There is no broker and no worker thread in the module; a caller leases a job, does the work, then completes or fails it.
- Dedupe is on `(source, event_id)`, enforced by a unique constraint. The same event id from a different source is a different job. Dedupe still holds after the first job is done, dead-lettered or discarded. Repeating an identical event returns the existing job; the same key with a different kind, payload or ordering key is a `Conflict`.
- States are pending, leased, done, dead and discarded. A lease has an owner and an expiry. A lease that is not completed or renewed expires and the job becomes leasable again, so a job held by a crashed worker is picked up after restart. A worker that runs long calls `renew`. `complete` and `fail` succeed after expiry as long as nobody else has taken the job; once another worker has, the stale worker gets a `Conflict`. An attempt is counted when a job is leased, and every change is checked against a row version, so a lost race raises `Conflict` instead of reporting success.
- A failure schedules a retry after exponential backoff up to a cap. At the retry ceiling the job goes to dead-letter. A lease that expires on the last attempt also goes to dead-letter.
- Ordering: FIFO per `ordering_key`. A job is skipped while an earlier job with the same key is pending, leased or dead. A dead-lettered job blocks its key until a human replays or discards it, so a replayed event can never run after newer events for the same key. A dead job with no ordering key blocks nothing.
- Replay moves a dead-lettered job back to pending, and discard retires it while keeping its dedupe record. Both need a human `security_admin` and a reason. The caller is decided on the actor id resolved through the identity store at that moment, never on an object handed in. The order is an audit ATTEMPT record, the change, then a result record, and the audit log is never called inside a database transaction. If the attempt cannot be audited, nothing changes.
- The lease length, retry ceiling and backoff values come from settings and have no default. Leasing or failing a job while they are unset is refused (ADR-0019).
- A payload must be plain JSON and should hold references, not bulk content. A stored error is the error type and a short message, never the payload.
- `stats()` returns counts per state and the age of the oldest pending job.

Weaknesses of this default:
- A job can still run twice if a worker outlives its lease without renewing it, or if the clock jumps. Every handler must be idempotent.
- A dead-lettered job stalls every later job with the same ordering key until a human acts. That keeps order and also means one poisoned event can hold up a whole source. Nothing alerts a human beyond a counter and a log line when a job is dead-lettered.
- Jobs without an ordering key have no ordering guarantee.
- Lease expiry and backoff depend on the host clock.
- There is no multi-step workflow state in the queue. Waiting for a human approval is modelled in the approval service, not as a suspended job.
- Rows are never removed, because dedupe must outlive the job. The table grows until a retention rule exists (OD-17).
- If the operational database is unavailable, ingestion and the queue stop together.
- The queue cannot recover events that a source did not retain while the platform was down. That gap must be reported as a coverage gap (BP §10.3).

## Why this default is reversible
Seam: the `JobQueue` interface in `ciso.workflows` (enqueue, lease, complete, fail, dead-letter listing, replay, stats). Producers and handlers do not see the table. To switch: implement the same interface on a broker or workflow engine, drain the existing table, and re-run the resilience tests (restart, queue recovery, replay).

## Evidence needed to make this final
- Expected event rates and number of connected sources (BP §15.1).
- Which sources retain events and support replay, from the Phase 0 source-system matrix.
- Whether components are split across processes or hosts (ADR-0010, ADR-0015).
- Ordering requirements per source, including what must happen after a dead-letter.
- Measured job durations, to set the lease length (ADR-0019).
- Whether L3 playbooks (OD-15) need long-running multi-step workflows.

## Consequences
- One store to back up and restore (ADR-0014).
- Idempotent handlers are a standing rule for all job code.
- Queue depth, retries and dead-letter counts must appear in operator reporting (FR-032), since a silent backlog would look like a healthy system.
