# M2 review: execution broker, outbox tools, execution recovery

Date: 2026-11-18

## Scope

`src/ciso/execution/broker.py`, `gates.py`, `approval_gate.py`, `effects.py`,
`auditing.py`, `records.py`, `store.py`, `credentials.py`, `outbox_tools.py`,
`recovery.py`, the `execution_run` table in `tables.py`; tests
`tests/execution/test_broker_*.py`, `test_outbox_tools.py`, `broker_world.py`,
`tests/resilience/test_execution_recovery.py`.

Out of scope and not reported on: `tools.py`, `channels.py`, `src/ciso/write_adapters/`,
`src/ciso/approvals/` (read only to understand the call sites).

Measured against: blueprint 9.4, 9.5, 11.2, 19.3; plan gaps G5, G12, G13, G14, G20, rows
T2.3, T2.4 and the M2 exit gate; ADR-0010, 0016, 0018, 0021; `docs/plan/builder-rules.md`;
the four project rules (resolve the actor, no audit under the write lock, frozen authority
fields, every guard has a failing test).

## Method

- Read every in-scope source file line by line, and the tests.
- Wrote proof-of-concept scripts that drive the real code in the repository through the
  test `World` (real registry, real policy engine and ruleset, real approvals, fakes for
  audit, identity, kill switch, secrets). Scripts and their data live only in the
  scratchpad: `rev3-poc.py`, `rev3-poc2.py`.
- Guard removal: copied `src` and `tests` to a scratch directory (`rev3-copy`), applied 92
  single-guard mutations there one at a time (`rev3-mutate.py`), and ran `tests/execution`
  plus `tests/resilience/test_execution_recovery.py` against each. The copy was taken at
  about the middle of the review; later edits by the other agent are not in it. Nothing
  under `src/` or `tests/` in the repository was edited.
- Baseline in the repository: the seven in-scope test files, 184 passed, 1 skipped.

"Measured" below means a script ran and printed the quoted result. "Read" means the
conclusion comes from the code only.

No critical finding. Two high, nine medium, nine low.

---

## H1. An approval for one envelope can be spent on different arguments

File: `broker.py:141` (`isinstance(envelope, ActionEnvelope)`), `gates.py:121-142`
(the `ToolCall` is built at gate 2), `approval_gate.py:82-92` and `gates.py:186-193`
(hash recomputed from the caller's object at later gates).

What breaks: approval binding (blueprint 9.5, FR-025, G3). The broker trusts the
caller's object twice: it calls the object's own `envelope_hash()` method, and it reads
the object again at later gates after it has already built the tool call from it.

Sequence A (measured, P1), needs only the broker's public `execute`:

1. A human approves L4 envelope E1, arguments `{"note": "approved text"}`.
2. The caller defines `class Evil(ActionEnvelope)` whose `envelope_hash()` returns E1's
   hash, and builds it with E1's request id, idempotency key, actor and target but
   arguments `{"note": "NOT WHAT WAS APPROVED"}`.
3. `broker.execute(evil, approval_id)`. `isinstance` passes. Policy, the approval check,
   the consume and the row all use the lied hash.
4. Result: `RETURNED state=verified | tool ran with: ['NOT WHAT WAS APPROVED']`.

Sequence B (measured, P1c), no subclass, a plain `ActionEnvelope`:

1. Caller submits an envelope with unapproved arguments. Gate 2 builds the `ToolCall`
   from them.
2. Between gate 2 and gate 4 another thread swaps `envelope.__dict__["arguments"]` to the
   approved arguments (a frozen Pydantic model does not stop this). In the script the
   swap is injected at the gate 3 lookup to make the race deterministic.
3. Policy, approval, the stored hash, the stored envelope and every audit record now
   describe the approved envelope. The tool runs with the arguments from step 1.
4. Result: `RETURNED state=verified | tool ran with: ['EVIL ARGS'] | row hash == approved
   hash: True | stored envelope shows the approved text: True`. The record is wrong as
   well as the action.

A swap made after gate 4 is caught (measured, P1b: `policy_unavailable`), so the window is
gates 2 to 4.

ADR-0010 accepts that in-process isolation is a convention, and a caller with reflection
can reach the registry anyway. This is still worth fixing: it needs no reflection, the
module docstring says the broker "takes no decision from its caller", and the fix is two
lines.

Smallest fix: at the top of `execute`, refuse unless `type(envelope) is ActionEnvelope`,
then replace it with a private copy the caller holds no reference to
(`ActionEnvelope.model_validate_json(envelope.model_dump_json())`) and use only the copy.
Add tests for both sequences.

## H2. Start-up recovery that overlaps a live broker records `aborted` for a run whose tool was called

File: `recovery.py:85-95` (the change to `aborted` is conditional on the state only),
`records.py:56` ("The tool was never called for this row. Final.").

What breaks: the state machine (G5). `aborted` is final and settled, means "no side
effect", and is replayed to the caller. Here the side effect happened.

Sequence (measured, P4, file database, two threads standing in for two processes):

1. Broker claims the row (`pending`, no attempt id) and is writing the ATTEMPT audit record.
2. A second process starts and runs `recover_in_flight()`. It reads the row: `pending`,
   no `attempt_audit_ref`, so `never_called` is true. It writes its own ATTEMPT record.
3. Broker stores the attempt id on the row (`mark_attempt_audited` returns True; the row
   is still `pending`) and calls the tool.
4. Recovery runs `change(id, (pending,), state=aborted)`. The row is still `pending`, so
   it succeeds.
5. The tool returns; `_settle` finds the row changed; `ResultNotRecorded` is raised.
6. Result: `ResultNotRecorded(record.state=aborted) | tool calls: 1 | row state: aborted
   | attempt_audit_ref set: True`. The same key again: `RETURNED state=aborted`.

A caller, or an operator reading the row, concludes nothing happened and submits the
action again under a new key: a duplicate side effect with no warning. Nothing stops
recovery from running beside a broker: the docstring says "call once at start-up" and no
lock or check enforces it. A second process on the same database file is enough.

The other recovery direction is safe: a `pending` row with an attempt id moved to
`unknown_outcome` under a live broker only costs a `ResultNotRecorded`.

Smallest fix: pass `execution_run.c.attempt_audit_ref.is_(None)` as an extra condition
when the target is `aborted`; when that update misses, re-read and treat the row as in
flight (`unknown_outcome`). Add a test with the interleaving above. Separately, decide
whether a second broker process on one database is supported; if not, take an instance
lock at start-up.

---

## M1. Nothing is re-checked between gate 1 and the tool call; for the shipped tools the kill switch is consulted exactly once

File: `broker.py:156-169` and `224-226`, `gates.py:92-97`, `219-223`, `credentials.py:31`.

What breaks: blueprint 11.2 ("disable all write execution"), 9.5 ("immediately before
execution"), G12, G20. Between gate 1 and `invoke` the broker evaluates policy, resolves
identity, consumes an approval, runs the precondition checker, takes two database write
transactions and appends an audit record. Each can wait (the database busy timeout alone
is 5 s per transaction). The only mid-run control is the kill-switch-gated credential
accessor, and both shipped outbox tools declare no credentials.

Measured:

- P3: `writes` engaged while the ATTEMPT record is being appended:
  `RETURNED state=verified | tool calls after engage: 1 | switch reads: 1`.
- P21: envelope expires after gate 6 (clock moved during the ATTEMPT append):
  `RETURNED state=verified | expired at tool time: True`.
- P22: actor removed from the identity store after gate 4: `RETURNED state=verified`.

Smallest fix: one cheap re-check block immediately before `self._effects.perform` in
`_finish` (or as the last step of `_record_attempt`): kill switch (`writes`, and
`l3_runs` for level 3 and above), expiry, and `_require_active_actor`. On refusal abort
the row (`aborted`, the tool was not called) and audit the refusal. A test per check,
using the audit `during` hook that already exists in `PickyAudit`.

## M2. The approval is spent before refusals that have nothing to do with it

File: `broker.py:166-169`, `approval_gate.py:92`, `gates.py:248-251`.

What breaks: an approval is lost on a refusal that was knowable beforehand, and one actor
can make another actor's approval worthless. The envelope hash covers the request id and
the idempotency key, so the human has to approve a new envelope from scratch.

Measured (P2):

- Rate limit unset (the G14 default): `REFUSED rate_limit_unset`, then the same approval
  on a correctly configured broker: `REFUSED approval_invalid ('already_consumed',)`.
  A deployment with the knob unset silently eats every approval presented to it.
- Per-tool window filled by another actor (limit 1): victim `REFUSED rate_limited`;
  after the window is free again, same approval: `REFUSED approval_invalid`. The limit is
  per tool, not per actor, so any actor allowed to use the tool can do this on purpose.
- Stale precondition: `REFUSED precondition_failed`; once the precondition holds again:
  `REFUSED approval_invalid`.

The module docstring states the behaviour ("if a later gate refuses, a new approval is
needed"), so this is a design weakness rather than a slip. It is cheap to narrow.

Smallest fix: keep `check` and `require_matching_approval` where they are (the asserted
gate order does not change), and move `consume` to the last step before `claim`, after
expiry and preconditions. Refuse `rate_limit_unset` before the approval gate (it is a
static fact). A rate-limited claim after a consume can still happen; shrink it by
reading the count before the consume, or accept and document it.

## M3. Tool-supplied text that SQLite cannot encode escapes as a raw exception and leaves the row `pending`

File: `store.py:35-41` (`_closed` wraps `SQLAlchemyError` only), `effects.py:58-65`,
`broker.py:225-234` (catches `ExecutionStoreError` only).

What breaks: G5 "a row that is true as far as it goes", the result audit, and the
`ResultNotRecorded` contract.

Sequence (measured, P5): a tool returns `ToolResult(detail="bad \ud800 text")` (Pydantic
accepts a lone surrogate in a `str`). The side effect has happened. `_settle` binds the
text, the driver raises `UnicodeEncodeError`, which is not a `SQLAlchemyError`.
Result: `RAISED UnicodeEncodeError | tool calls: 1 | row state: pending | execute audit
outcomes: ['attempt']`; the same key again: `REFUSED prior_in_flight`. No result record,
no FAILED record, no `ResultNotRecorded`, and the row stays `pending` until a process
restart turns it into `unknown_outcome`. The same applies to a verifier's `detail` and
`observed` (read).

The envelope has an explicit UTF-8 check for this reason; tool output has none.

Smallest fix: in `_closed`, wrap every `Exception` that is not already an
`ExecutionStoreError`; and make `clip` (and the `observed` / `references` path) replace
unencodable characters (`text.encode("utf-8", "replace").decode("utf-8")`). Test with a
tool that returns a lone surrogate.

## M4. The full request, arguments included, is stored unredacted in `execution_run.envelope`

File: `gates.py:274` (`envelope.model_dump_json()`), `store.py:174`, `tables.py:57`.

What breaks: "no secrets in stored rows". The outbox draft is redacted; the database row
next to it is not.

Measured (P8): ticket body `password is hunter2-PRIVATE-KEY-0000`, redactor knows the
value: `secret in draft file: False | secret in execution_run.envelope: True`.

The text comes from the model or a user, so pasted credentials in a ticket body are the
expected case, not an exotic one. Every reader of the operational database and every
backup gets them. `tables.py` says the column holds the request "exactly as received" but
no document names it as sensitive content, and no retention rule covers it.

Smallest fix, pick one: (a) refuse at gate 2 an envelope whose arguments change under the
`Redactor` (the broker then needs a `Redactor`; the caller is told to remove the secret);
or (b) store the redacted arguments, record a hash of the stored text for recovery's
integrity check, and have `verify` work from the redacted form (the outbox content is
already built from redacted arguments, so the comparison still holds if the redactor is
idempotent). Until then, classify the column in the data inventory.

## M5. Verifier free text reaches the audit log, unvalidated and unbounded

File: `effects.py:90-104`, `auditing.py:52-53`; `Verification.observed` has no
validation (`tools.py`, noted only as the source).

What breaks: `auditing.py` promises "references and codes only: never the envelope's
arguments, never a secret". `residual_risk` for a mismatch embeds `seen.detail`, and
`observed` is copied as is; both go into the audit details of the result record.
`ToolResult.references` are validated as entity refs; `observed` is any strings, any
count, any length. `tool_detail` (tool free text, 500 characters) is stored on the row
and returned in the record.

Measured (P7): a verifier that puts its credential in `detail` and `observed`, plus one
100 000-character `observed` item: `secret in audit residual_risk: True | secret in audit
observed: True | audit details size: 100709`.

A tool author is trusted code, but a verifier that echoes what the target returned is
the normal way to write one, and the target's reply is not trusted content.

Smallest fix: keep verifier text out of `residual_risk` (use the fixed `RISK_MISMATCH`
text; the detail is already in `verification_detail` on the row); validate `observed`
like `references` (entity refs) and cap the count of both before storing; cap in
`effects.py` so it does not depend on `tools.py`.

## M6. A row left `executed_unverified` by a failing verifier cannot be verified without a restart

File: `recovery.py:133-134`, `effects.py:81-89`, `gates.py:165-169`.

What breaks: the refusal says "verify it before any retry", and nothing can. A verifier
that raises once (target unreachable) leaves `executed_unverified`. `recovery.verify`
accepts only `unknown_outcome`; `unknown()` does not list the row.

Measured (P6): `executed_unverified | recovery.verify -> Conflict: execution is
executed_unverified, not unknown_outcome | unknown(): 0 | retry: REFUSED prior_unverified`.

The only way out is a process restart (`recover_in_flight` moves it to
`unknown_outcome`). The practical risk is the workaround: a new idempotency key (a
duplicate side effect) or a hand edit of the row.

Smallest fix: let `verify` and `unknown()` accept `executed_unverified` rows as well
(`confirm` already handles any starting state), or have `confirm` move a row to
`unknown_outcome` when the verifier cannot answer. Test: verifier raises, then answers.

## M7. `execution_run` rows are unauthenticated: a database writer can turn a failure into `verified` or reset a key

File: `tables.py:45-76`, `store.py` (reads), `gates.py:146-170`.

What breaks: `succeeded` is read straight from the row. ADR-0018 gave kill-switch rows a
MAC for exactly this threat; execution rows have none and no document says so.

Measured (P14): after a `verification_failed` run, a plain `UPDATE ... SET state='verified'`:
the same envelope again `-> verified | succeeded: True | tool calls: 1`, audited as a
normal duplicate. After `DELETE FROM execution_run`: the same envelope runs again
(`tool calls: 2`), and the rate window is empty too.

Also read: `recovery._call_for` checks the stored envelope against `envelope_hash`, but
both live in the same row, so the check detects corruption, not tampering.

Smallest fix: state the limit in the `tables.py` and `store.py` docstrings and in
ADR-0010's weaknesses now; add a MAC over the identity and state columns (same key
handling as the kill switch) before any real write adapter exists; let replay
cross-check `result_audit_ref` against the audit log when that is cheap.

## M8. Guards with no failing test (rule 4)

Measured by mutation in the scratch copy (92 mutations, 79 killed, 13 survived; all tests
in `tests/execution` and the recovery file still passed with each of these removed):

| Guard | Where | Note |
|---|---|---|
| resolved actor id equals the envelope's | `gates.py:212` | type and `None` are tested, the id is not |
| approval with empty `required_roles` is refused | `approval_gate.py:49` | the subset test alone passes an empty set |
| attempt id stored only once (`attempt_audit_ref IS NULL`) | `store.py:197-206` | |
| result id stored only once (`result_audit_ref IS NULL`) | `store.py:208-215` | |
| unreadable row becomes `ExecutionStoreError` | `store.py:75-77` | |
| owed-result query skips rows with no audited attempt | `store.py:138-140` | |
| owed-result delivery skips unsettled rows | `recovery.py:184-185` | |
| `verify`: result audit failure raises `FailClosed` | `recovery.py:146-149` | |
| recovery's verifier gets kill-switch-gated credentials | `recovery.py:74` | replaced by the raw secret resolver, suite stays green |
| outbox: call with no channel refused | `outbox_tools.py:95` | |
| outbox: resolved directory's parent is the root | `outbox_tools.py:102` | the only test for it needs a symlink and is skipped on this machine |
| outbox: resolved name equals the outbox name | `outbox_tools.py:102` | each half of the `or` survives alone |
| `l3_runs` checked on the envelope's claimed level | `gates.py:112-113` | harmless today (the validator forbids understating), still untested |

The junction case itself is sound: measured (P18) with a real NTFS junction, the write is
refused and nothing lands outside the root.

Smallest fix: one test per row. For the link test, fall back to
`_winapi.CreateJunction` on Windows instead of skipping.

## M9. Refusals are audited in the name of whoever the envelope claims, before any identity check, with no limit

File: `broker.py:149-151`, `auditing.py:19-35`.

What breaks: audit attribution and audit volume. Gates 1 to 3 refuse before the actor is
resolved, and the rate limit counts claimed rows only.

Measured (P10): 51 refused envelopes, 50 claiming `human_admin` and one claiming an actor
that does not exist: `DENIED records written: 51 | named actors: ['human_admin',
'nobody_at_all'] | identity lookups made: 0 | rows: 0`.

Whoever can reach `execute` can write DENIED records under any actor id and fill the audit
log at will. Today the caller is the orchestrator, whose envelopes are built from model
output.

Smallest fix: mark the actor in refusal records as claimed (`details["actor_claimed"]`,
or audit as the broker with the claimed id in details) until `_require_active_actor` has
passed; the caller-side limiter (G22) must cover refusals. Record the decision either way.

---

## L1. A level 3 action recovered after a crash is never rolled back on a verification mismatch

File: `recovery.py:137` (`undo_on_mismatch=False`). Measured (P16): `unknown_outcome ->
verification_failed | rollbacks called: 0 | settled: True`, and the key then replays as
`verification_failed`. Documented ("never rolls back"), but it contradicts the level 3
contract in `effects.py` and leaves a final state with a possible partial change and no
automatic or prompted undo. No level 3 tool ships. Fix: for level 3 and above, end in a
state that demands a person (`rollback_failed`, or a new `needs_rollback`), or run the
rollback under the same conditions as the broker.

## L2. A transient audit outage at the ATTEMPT record burns the key and the approval for good

File: `broker.py:189-196`, `gates.py:163-170`. Measured (P17): `REFUSED
attempt_audit_failed`, then with the audit log back: `RETURNED state=aborted`, tool never
called. The replay is audited with outcome SUCCESS. Safe direction; the cost is that
every envelope submitted during an outage is dead and each `aborted` row also counts
against the rate limit. Fix: document, or let an `aborted` row be re-claimed by the same
envelope hash (the approval question from M2 then applies); audit the replay of a
non-verified row as FAILED.

## L3. Idempotency keys are one global namespace, and a replay is answered before policy and identity

File: `gates.py:146-170`, `broker.py:162-164`. Measured (P12): another actor uses the key
first; the owner then gets `REFUSED idempotency_conflict` permanently (and learns the key
exists). A replay by an actor since removed from the identity store returns the stored
record with `policy evaluated for it: 0`. Nothing runs, so the exposure is the record's
content (references, tool detail) to anyone who can reproduce the envelope. Fix: scope
the uniqueness to `(actor_id, idempotency_key)`, and run `_require_active_actor` before
`_replay`.

## L4. `verify_all` stops at the first row it cannot handle

File: `recovery.py:154-155`. Measured (P19): one row with an unreadable stored envelope
ahead of a good one: `IntegrityFailure | second row still: unknown_outcome`. Fix: collect
per-row failures and raise once at the end, as `recover_in_flight` does.

## L5. Outbox argument models accept unbounded and unvalidated items

File: `outbox_tools.py:48` (`related`: 32 items, no item length, not checked as entity
refs although the docstring says they are), `:55` (`owner`: "an entity ref", not
checked). Measured (P11): a 4 MiB `related` item with NUL and newline characters:
`RETURNED state=verified | draft bytes: 4194659 | row envelope chars: 4195002`. Nothing
in the broker caps envelope size, so each call stores the payload twice. Fix: constrain
the item type (`Annotated[str, Field(max_length=160)]` plus an `EntityRef` validator) and
add a total-size check on the envelope at gate 2.

## L6. The gated credential accessor checks `writes` only

File: `credentials.py:31`. Measured (P23): `l3_runs` engaged while a level 3 tool is
running, the tool asks for its credential: `['released']`. ADR-0018 only promises to stop
new runs, so this is a gap in depth, not in the stated guarantee. Fix: give the accessor
the call's authority level and check `l3_runs` as well for level 3 and above.

## L7. Store errors carry the SQL parameters in their cause chain

File: `store.py:40-41` (`raise ... from exc`), `gates.py:278-279`. Measured (P9): with
the insert failing, the formatted traceback of the refusal contains SQLAlchemy's
`[parameters: ...]` block, which includes the envelope JSON. In the run the long JSON was
truncated by SQLAlchemy and the argument text itself did not appear; a short envelope
would appear whole. `logger.exception` in `broker.py` and `recovery.py` prints the same
chain. Fix: `raise ExecutionStoreError(...) from None` in `_closed`, or create the engine
with `hide_parameters=True` (that file is outside this scope).

## L8. Outbox write: check-then-replace, no flush, stray temporary files (read)

File: `outbox_tools.py:132-148`. `final.exists()` followed by `temporary.replace(final)`
overwrites a file that appears in between (the idempotency row makes this unlikely, not
impossible: see M7). Nothing is flushed to disk before the rename, so after a power loss
a `verified` row can point at an empty file. A crash between open and rename leaves a
`.<name>.<id>.part` file with draft content that nothing cleans up. Fix: `os.link` (or an
exclusive create on the final name) instead of replace, `flush` and `os.fsync` before the
rename, and sweep `*.part` at start-up.

## L9. Docstrings that claim more than the code delivers (read, each backed by a finding above)

- `broker.py:4-5`: "takes no decision from its caller": see H1. "is the only way a tool
  runs": `ToolRegistry.invoke` is public and recovery calls verifiers; ADR-0010 says so,
  the docstring does not.
- `broker.py:26-27`: "Every refusal in 1 to 9 ... is audited as DENIED": not
  `invalid_request`, not the two audit-down reasons, and not the raw exception in M3.
- `records.py:56`, `recovery.py:7-8`: "never reached its tool": see H2.
- `effects.py:4-5`: "a crash at any point leaves a row that is true as far as it goes":
  see H2, M3.
- `auditing.py:1-2`: "References and codes only": see M5.
- `outbox_tools.py:12`: "no secret" is true of the file and silent about the row: see M4.
- `recovery.py:13-14`: "A change that could not be audited afterwards still stands,
  because it only moves a row to the side where the broker refuses to run it again": not
  true for the move to `aborted`, which the broker replays as a finished result.

---

## Suspicions (not made concrete)

- Verification of an outbox draft depends on the `Redactor` giving the same output at
  verify time as at write time. A redactor whose rules change across a restart would turn
  a correct draft into `verification_failed`. Not tested against the real redactor.
- `_directory` resolves the path and then writes: a local user who can replace the outbox
  directory with a junction between the check and the write would redirect one draft.
  Needs local write access to the outbox root; not attempted.
- Two broker processes configured with different `tool_rate_limit_per_minute` values
  share one count; the laxer one wins. Not attempted.
- In `recover_in_flight`, when the conditional change misses, an ATTEMPT record has been
  written and no result record follows. Cosmetic, but it is an audit record of something
  that did not happen.
- After `recovery.verify` settles a row that the broker had already given a
  `result_audit_ref` (tool raised, FAILED record written), the reference still points at
  the old FAILED record, because the id is stored only once. The verify record exists in
  the log; the row does not link to it.
- A failure between the result audit append and `mark_result_audited` makes
  `audit_owed_results` write a second result record later. At-least-once, flagged with
  `late=True`, nothing to tell a reader it is a duplicate.
- The in-memory test engine uses one shared connection (`StaticPool`); the concurrency
  guarantees were measured on a file database only.

## Checked and found sound

- Gate order and refusal on each of: kill switch engaged, kill switch unreadable or
  answering a non-boolean, invalid envelope, unknown tool, policy raise, policy answer
  for another envelope or request, deny, hold, actor unknown or of another type, missing
  or malformed approval id, expired envelope, stale or uncheckable precondition, unset
  rate limit, rate limit reached, attempt audit failure, attempt id not stored. Each
  guard's removal turned a named test red (measured, 79 of 92 mutations killed; the 13
  survivors are M8).
- Approval binding with a well-formed envelope: other arguments, other target, other
  requester id, other requester type, wider approver roles, another binding, pending,
  expired, revoked approver role, already consumed: all refused (existing tests; each
  check's removal is killed).
- Policy is evaluated on every call and never taken from the caller (read, and killed
  mutations G8a to G8c).
- Rule 1: the broker resolves the actor id itself after policy and decides on the answer
  (read; killed mutations). No privilege decision uses a `Principal` object handed in.
- Rule 2: no store method calls audit, identity, a tool or the kill switch; the broker,
  approval gate, effects and recovery call the audit sink only between transactions
  (read; the `LockSpy` test exercises it).
- Idempotency under concurrency: 8 threads, one key, file database: exactly one tool
  call, one row, the rest refused `prior_in_flight` or `prior_unverified` (measured,
  P13). Same key with another envelope: conflict. A prior `unknown_outcome`,
  `executed_unverified` or `pending` row blocks a rerun.
- Rate limit: per tool, counted from stored rows inside the claim transaction, survives a
  restart; a clock moved 30 minutes back still refuses; the window reopens only after
  real time passes on the clock (measured, P15).
- Kill-switch-gated accessor: checked on every `get`, fails closed on a reader error or a
  non-boolean answer; an undeclared reference is refused (existing tests; killed
  mutations C1 to C3, O10).
- `verified` is reachable only through a verifier answer that is exactly `True`; a
  verifier that raises, returns a non-`Verification`, or is missing never yields it; the
  tool's own reply never decides (read; killed mutations E1, E8).
- Rollback that raises or reports failure ends in `rollback_failed`; level 2 is never
  rolled back (killed mutations E2 to E7).
- `recovery.verify` never calls the tool body and never rolls back (read); it refuses a
  row in any state but `unknown_outcome`, an unknown id, and a stored envelope that does
  not match its hash (killed mutations R2, R3, R11).
- Outbox path handling: the file name is a fixed prefix plus hex; `../`, absolute paths,
  drive-relative names, mixed case, dots, trailing newline and Windows device names
  (`nul`, `con`, `aux`, `com1`, `lpt9`, `prn`) are refused; a real junction to a directory
  outside the root is refused with nothing written outside (measured, P18). Names are
  lower-case only, so case-insensitive collisions cannot be constructed.
- Outbox verification rebuilds the expected bytes and compares hashes; a missing file,
  altered bytes, other arguments under the same key and a revoked channel all give
  `matches=False`; an existing different draft is not overwritten on the normal path
  (existing tests; killed mutations O4 to O9).
- No network or subprocess import in the in-scope files; no secret value is written to a
  row, an audit record or an exception by the broker's own code (read). The exceptions
  are caller-supplied and tool-supplied text: M4, M5, L7.
- Numeric safety parameter: `tool_rate_limit_per_minute` has no default value other than
  `None`, and `None` refuses (killed mutation G14); `bool`, zero and negatives are
  rejected at construction.

## Not reviewed

- `tools.py`, `channels.py`, `src/ciso/write_adapters/`, `src/ciso/approvals/` (out of
  scope; another review covers them). The approval service's own behaviour under
  concurrent `consume` was taken on trust.
- `ciso.policy` (engine, ruleset, envelope validator), `ciso.common` (database engine,
  schemas, clock), the real audit log, redactor, kill switch and secret resolver: only
  their interfaces as the broker uses them.
- The composition root: whether `recover_in_flight`, `audit_owed_results` and `verify_all`
  are actually called at start-up, and in which order, was not checked.
- Two real operating-system processes on one database file: concurrency was exercised
  with threads holding separate connections to a file database.
- The whole test suite, mypy, ruff and the architecture tests were not run.
- The one in-scope test that is skipped on this machine (directory symlink) was not made
  to run; its guard was checked by hand with a junction instead.
