# M1 review: audit, kill switch, inference

Saved verbatim from the reviewing agent's report, 2026-11-17. Findings are tracked in
`docs/plan/followups.md`. Probe scripts named here lived in a session scratchpad and may be gone.

---

# Security review: `ciso.audit`, `ciso.killswitch`, `ciso.inference`

Under your threat model the anchor can be defeated (rolled back or reset) and the kill switch's audit outbox can forge audit records. A single power loss leaves the audit log permanently refusing writes, with no recovery path.

**What I ran:**
- All 128 tests in `tests/audit`, `tests/killswitch` and `tests/inference` pass.
- I wrote probe scripts that run against temporary databases. Each finding below is marked **[proven]** with the output I got, or **[reading]** if it comes from reading the code only.
- I changed no repo files. The probes ran with `PYTHONDONTWRITEBYTECODE=1`.

The probes are in `C:\Users\<user>\AppData\Local\Temp\claude\89363c7559032d42\1304fad4-2155-48c0-8a06-85e7efb17aae\scratchpad\`:
- `probe_audit.py`
- `probe_crash.py`
- `probe_ks.py`
- `probe_inf.py`
- `probe_misc.py`
- `mutplug.py`
- `probe_common.py`

---

## CRITICAL

**C1. Restoring an old database together with its old anchor rolls back history, and `verify()` reports `ok`. Deleting both erases history, and `verify()` also reports `ok`.** [proven]
- **Where:** `src/ciso/audit/anchor.py:104-135`, `src/ciso/audit/log.py:157-160`, `src/ciso/app/settings.py:138-140`
- **Why it works:** the default anchor is `data_dir/anchor/audit-head.json`, inside the data directory your attacker can write. The anchor holds only `{seq, head_hash, hmac}`: no counter that only goes up, no timestamp, no log id, no external witness. An old pair is still validly signed. Separately, `_require_anchor_at_head` accepts "anchor missing + empty log" as a fresh start.
- **Attack sequence:**
  1. Copy `audit.db` and the anchor at seq 3.
  2. Let records 4-6 be written (my probe used the action `secret.exfiltrate`).
  3. Copy both old files back.
- **Output:** `before rollback: ok 6` then `after rollback: ok 3 None`. For the wipe: delete `audit.db*` and the anchor, then append. Output: `append after wipe seq= 1 verify: ok None checked 1`.
- **Fix:**
  - The anchor needs a root the data-directory attacker cannot roll back: a periodic signed head (seq, hash, time) sent to an append-only store on another host or identity (syslog/WORM/remote service), checked by `verify()`. A monotonic counter in the secret store or OS-protected storage would also work.
  - Put a log instance id (created at genesis, kept in that external store) into the HMAC message, so an empty log with no anchor is refused unless an explicit, audited genesis was performed.
  - Until then, `settings.audit_anchor` must not sit under `data_dir`.

## HIGH

**H1. A crash between the anchor write and COMMIT leaves the log permanently refusing appends, and `verify()` labels the crash as tampering.** [proven]
- **Where:** `log.py:128-133`, `anchor.py:12-14`
- **Sequence:** a child process calls `os._exit` right after `HeadAnchor.write`.
- **Output:**
  - `verify after crash: failed truncated head 3`
  - `append: IntegrityFailure audit anchor (seq 4) does not match the head (seq 3)`
  - Public methods: `['append', 'query', 'verify']`. There is no recovery path.
- **Knock-on:** blueprint 9.5 requires fail-closed when the audit path is down. That means inference, kill-switch release and every audited write stop until someone hand-edits the anchor, which requires the HMAC key.
- **The other ordering has the same problem:** the rename is not followed by a directory fsync. If power loss drops the rename while the WAL commit survives, the anchor ends up one behind (`anchor_behind_head`) and appends are refused the same way.
- **Fix:**
  - Write a "pending" anchor `{seq: N+1, head, prev_seq: N, prev_head}` before commit.
  - On open, if the database head equals either the pending pair or the previous pair, finish the anchor update automatically and record a `audit.recovered` event.
  - Report this case with its own reason (`crash_recovered` / `anchor_pending`), not `truncated`.
  - fsync the directory after `replace` on POSIX.

**H2. The kill-switch outbox turns any operational-database writer into an audit forger.** [proven]
- **Where:** `src/ciso/killswitch/service.py:335-355`
- **Why it works:** `_deliver` copies `action`, `actor_id` and `actor_type` from the row without checking them.
- **Sequence:** insert a row into `killswitch_pending_audit` with `action='approval.grant', actor_id='exec_cfo'`, then call `retry_pending_audit()`.
- **Output:** `audit record: 1 exec_cfo human approval.grant success {...}`, and `verify: ok`.
- **Impact:** the audit database is kept separate so that ordinary writers hold no handle to it, and this goes around that. The record is chained, anchored and passes verification.
- **Fix:**
  - Hard-code `ENGAGE_ACTION` in `_deliver`.
  - Have the service add an HMAC over each outbox row using a key that agents don't hold.
  - Have break-glass rows marked `via=breakglass` only by the break-glass path, and delivered with an `unverified_origin` flag in `details`.

**H3. Kill-switch flags have no integrity protection, and a deleted row comes back clear at the next start.** [proven]
- **Where:** `service.py:226-243`, `service.py:173-187`, `killswitch/tables.py:4`
- **Sequence:** `engage_all`, then `DELETE FROM killswitch_flag WHERE capability='writes'`, then restart and `initialise()`.
- **Output:** `blocked after delete: True` then `blocked after restart initialise(): False`. The only audit action seen was the engage. The "no row = blocked" guarantee lasts only until the next start.
- **Broader point [reading]:** a plain `UPDATE ... SET engaged=0` by anyone who can write the operational database releases the switch silently, with an invented `changed_by`. That database is the one every module writes. Blueprint 11.2 says the switch must sit outside the LLM's authority; today that holds only as long as no code path the agent can reach writes that database.
- **Fix:**
  - `initialise()` should refuse to create rows once any flag row or outbox row exists. Write first-time rows only on a fresh schema, and audit that.
  - Use an HMAC over each flag row, or check flag state against the latest `killswitch.*` audit record on read, and fail to blocked on a mismatch.

**H4. Engage can fail with a raw database error, despite "stopping things must always work".** [proven, though whether it happens in practice depends on load]
- **Where:** `service.py:273-280` (release holds the operational-database write lock across `audit.append`), `gateway.py:175-177` (same pattern on every inference call)
- **Sequence:** a release waits on a slow audit sink for 7 s. A second engine calls `engage`.
- **Output:** `engage raised after 5.5s: OperationalError (sqlite3.OperationalError) database is locked`.
- **Realistic trigger:** `audit.append` itself can wait up to 5 s for the audit database lock. `verify()` holds that lock for the whole chain walk (see M5).
- **Fix:**
  - Never call the audit sink while holding the operational-database write lock. Use the outbox pattern for release too: write an ATTEMPT record first, then commit, then the result record.
  - Have `engage` retry on BUSY without a time limit, or use a dedicated kill-switch database file with no other writers.
  - Wrap failures in `FailClosed` rather than leaking `OperationalError`.

**H5. The inference timeout is whatever the provider says it was.** [proven]
- **Where:** `gateway.py:87-96`, and the docstring at `gateway.py:3`
- **Output:** a provider sleeps 3 s against a 0.5 s limit and reports elapsed 0. Result: `returned ok after 3.1s, latency recorded 0.0`.
- **Impact:** a hung runtime blocks the calling thread forever. Also, `timeout_seconds=nan` turns the check off: `nan timeout -> 1000000000.0`. `ProviderResponse.model_construct` with a NaN elapsed time also passes.
- **Fix:**
  - Measure time in the gateway with `time.monotonic()`.
  - Enforce the limit: run the provider in a worker or subprocess with a hard deadline, or pass a deadline the HTTP client must honour.
  - Reject timeouts that are not finite positive numbers (`math.isfinite`).

## MEDIUM

**M1. `bytes` (and any other object) in `details` skip redaction, then get turned into strings and kept forever.** [proven]
- **Where:** `log.py:142-153`, `common/schemas.py:29` (`default=str`)
- **Output:** `stored details: {'b': "b's3cr3t-token-value-XYZ987'", 's': '[REDACTED]'}`, using the real `SecretRedactor`.
- **Why it's worse here:** the log is append-only, so the secret can never be purged. This also contradicts the docstring at `log.py:27`.
- **Fix:** run `canonical_json` without `default=str` before redaction, and refuse anything that isn't a JSON-native type with `ValidationFailed`. Alternatively, convert to strings first and then redact.

**M2. Stored bytes are not what is hashed, so the database can be edited in ways `verify()` doesn't see.** [proven]
- **Where:** `log.py:361-365`, and `occurred_at` at `log.py:239-241`
- **Duplicate JSON keys:** `details='{"approved_by":"mallory","approved_by":"alice"}'` gives `verify: ok`. SQL `json_extract` returns `mallory`, while Python reads `alice`.
- **Timestamp text:** rewriting `occurred_at` with `T` instead of a space gives `verify: ok`, but `query(since, until)` changes from `[1, 2]` to `[2]`. The record drops out of time-window queries.
- **Fix:** in `_walk`, require that the stored `details` text equals `canonical_json(parsed)` byte for byte, and that `occurred_at` text matches the exact format written. Treat any difference as `row_invalid`. Reject duplicate keys with an `object_pairs_hook`.

**M3. The outbox has three further weaknesses.** [proven]
- **Poisoned row** (`service.py:303`, `340`): one row with `capabilities='["bogus"]'` makes both `pending_audit()` and `retry_pending_audit()` raise `ValueError`. Owed records then never get delivered. Fix: catch errors per row, quarantine the row, and log it.
- **Duplicate delivery:** two retry loops deliver the same row twice (`engage records in audit: [1, 2]`). The same happens if `_mark` fails after a successful append. Fix: claim each row with a conditional `UPDATE ... WHERE delivered_at IS NULL AND claimed_by IS NULL`, and put the outbox seq in `details` so duplicates can be spotted and removed.
- **Order inversion:** a release goes through while the engage audit is still owed. Result: `audit order: [(1, 'killswitch.release'), (2, 'killswitch.engage')]`. Fix: `release` must clear the outbox first and refuse if anything is still owed.

**M4. Break-glass accepts any existing SQLite file and reports success.** [proven]
- **Where:** `breakglass.py:72-79`
- **Sequence:** run with `--db audit.db`.
- **Output:** `exit 0 kill switch engaged for: writes, ... audit queued | ops writes blocked: False`. It also adds kill-switch tables to the audit database.
- **Fix:** require a `schema_version` row with `module='killswitch'` (that is, the operational database). Drop `create_all`. Read back through `KillSwitch.is_blocked` before printing success.

**M5. `verify()` holds the audit write lock for the whole chain walk.** [measured]
- **Where:** `log.py:192-202`
- **Measurement:** ~23 µs per row on this machine. A second engine's appends hit the 5 s busy timeout at about 220k records. Same-process appends wait on `threading.Lock` with no limit.
- **Fix:** walk the chain from a read snapshot. Take the write lock only to read the anchor and head, then compare against the snapshot.

**M6. Prompt and output bodies leak through exception chains.** [proven]
- **Where:** `gateway.py:136-138` and `193` (`from cause`); `records.py:129-133`
- **Evidence:**
  - A provider error that echoes the request: `marker in formatted traceback: True`.
  - `parse()` on invalid JSON: `message has marker: False | traceback has marker: True`, and the same for an invalid field value.
- **Why it matters:** `RedactingLogFilter` removes secrets, not prompt bodies. This breaks the 8.3 requirement and the claim at `records.py:127`.
- **Fix:** use `raise ... from None`, and record only the exception type name (already captured in `error_type`).

**M7. "One local provider" and "model pinned by sha256" are labels, not checks.** [proven]
- **Where:** `gateway.py:57-62`, `manifest.py:3`, `records.py:91`
- **Evidence:**
  - An object named `openai` with an `https://` endpoint attribute passes `isinstance(InferenceProvider)` and completes a request.
  - A manifest whose model sha256 is all zeros loads fine: `loaded with bogus model sha: [('stub-local', '00000000')]`. `ModelArtifact.sha256` is never compared with anything.
- **Fix:**
  - Use an explicit allowlist of provider classes (a nominal base class plus a registry), and have the provider report its endpoint so the gateway can assert it is loopback or a Unix socket.
  - Hash the artifact file (or the stub descriptor) when the gateway is built, and refuse a mismatch.
  - Read `model_id` and `version` once in `__init__` instead of on every call.

**M8. A record forged onto the end without the key gives `unverifiable`, not `failed`.** [proven]
- **Where:** `log.py:320-321`
- **Output:** `verify: unverifiable anchor_behind_head checked 4`.
- **Why it should be `failed`:** after H1 is fixed, an anchor behind the head can only come from tampering. Report it as `failed`.

## LOW

**L1. Unexpected exception type from `append`.** [proven] A lone surrogate in any event field makes `append` raise `UnicodeEncodeError`. The contract at `log.py:10-12` lists only `FailClosed`, `IntegrityFailure` and `ValidationFailed`. Fix: validate inputs as UTF-8-encodable and raise `ValidationFailed`.

**L2. A malformed provider response escapes unrecorded.** [proven] When a response is built with `model_construct(text=None)`, the gateway raises a raw `AttributeError` and writes no invocation record or audit event (`gateway.py:93-97`). Fix: wrap the post-call checks in the same failure path, and re-validate with `ProviderResponse.model_validate(response.model_dump())`.

**L3. `UntrustedModelOutput` is guarded by convention only.** [proven] `"{0._text}".format(out)`, `getattr(out, "_text")` and a subclass overriding `__str__` all return the raw text. `str`, f-strings, `+`, `%`, pickle, copy, deepcopy, `json` and Pydantic JSON dumps are all blocked. Logging it with `%s` loses the log line ("--- Logging error ---") rather than leaking it. Also:
- `repr` shows a 12-hex sha256 prefix.
- `output_sha256` is stored unsalted in the database and the audit log.

For low-entropy outputs this is equivalent to storing the text: `repr` of `"no"` gives `9390298f3fb0`, which is `sha256("no")`. Fix: use an HMAC with a deployment key, and mark the class `@final` (checked by the type checker).

**L4. `release` audits SUCCESS before the operational commit.** [reading] If the commit fails, the audit log says released while the flags are still engaged. That fails safe, but the record is false. The ATTEMPT-then-result pattern in H4 fixes it.

**L5. `Principal` is self-asserted.** [reading] Any in-process code can build `Principal(actor_type=HUMAN, roles={SECURITY_ADMIN})` and call `release`. Nothing ties it to an authenticated session. Fix: have `ciso.identity` issue it as a signed or opaque token that `KillSwitch` checks.

**L6. Anchor key has no id and no domain binding.** [reading] Rotating the key turns every anchor into `anchor_hmac_invalid`. Two environments sharing a key can swap logs.

## Tests that cannot fail, or don't test the guard

| Test | Mutation that still passes |
|---|---|
| `test_gateway.py:134-140` `test_routes_only_to_configured_provider` (and the `spy` in lines 162, 169, 177) | Add a config-driven fallback provider to the gateway. `never_passed` is never handed to the gateway, so its zero call count proves nothing. |
| `test_gateway.py:215-262` keyword scan | Add `self._fallback = OpenAIClient(...)`. Nothing contains the word "external", so it passes. |
| `test_gateway.py:264-268` `test_scan_detects_a_planted_word` | Delete the `ast.arg` branch from the real scan. This test checks its own two-line copy of the scan, not the real one. |
| `test_gateway.py:305` | Already passes while the cause chain carries the value (M6). It only checks `str(exc)`. |
| `test_anchor.py:37` | Move `settings.audit_anchor` next to `audit.db`. The test compares fixture paths, not the code. |
| `test_anchor.py:153` replay test | Replays the anchor alone. The pair replay (C1) is untested. |
| `test_anchor.py:193`, `test_killswitch.py:312`, `:411`, `test_append_verify.py:38` | These grep source, docstrings or names. Behaviour can change without breaking them. |
| `test_killswitch.py:76` | Covers re-initialising an engaged row, not a deleted one (H3). |
| `test_gateway.py:190` | NaN timeout is not covered. |
| All kill-switch tests | Run against `FakeAudit` only. Nothing exercises a real `AuditLog` that refuses appends (H1). |

## Docstring claims the code does not keep
- `anchor.py:7-8` (shortened chain undetectable without the key; replay is not covered, C1).
- `anchor.py:13-14` (crash outcome is an "intended fail-closed outcome"; there is no recovery and it reports as tampering, H1).
- `log.py:27` (redaction happens before hashing and storage; only for types the redactor handles, M1).
- `killswitch/tables.py:4` and `service.py:157-158` (H3, H4).
- `breakglass.py:14-15` (M4).
- `gateway.py:3` (H5).
- `records.py:91` and `manifest.py:3` (M7).
- `records.py:127` (M6).

## Checked and found sound
- The hash covers every column. Redaction runs before hashing for the types it handles.
- Edits, deletes and renumbering in the middle of the chain are caught.
- A full recompute of the chain without the key is caught. A forged anchor HMAC is caught, and `compare_digest` is used. Anchor parsing is strict.
- The anchor write is atomic (temp file, fsync, replace) and cleans up its temp file.
- Appends are serialised within the process and across engines. I confirmed the cross-engine part by changing `BEGIN IMMEDIATE` to `BEGIN` through a plugin, and `test_seq_is_gapless_across_two_engines_on_one_file` failed.
- A failed append rolls back cleanly, except in the H1 crash window.
- The kill switch treats every unreadable case as blocked: missing row, dropped table, broken engine, unknown capability.
- The role check is backed by an independent actor-type check, refusals are audited, break-glass has no release path, and break-glass refuses a missing file.
- The gateway has no fallback code path. Empty output, and a timeout that is missing, zero or negative, refuse.
- Inputs are redacted before rendering, and rendering is a single pass.
- No prompt or output body is stored in invocation rows or audit details.
- Manifest loading:
  - Paths are checked against `..`, absolute paths, drive colons and alternate data streams; it resolves the path and checks it stays inside the directory, so symlinks can't escape.
  - It reads each template once, so there is no check/use gap.
  - It rejects unknown keys and duplicates.

## Verdict
- **Fix before building on this:** C1 (anchor rollback/reset; also move the anchor out of `data_dir`), H1 (crash recovery), H2 (outbox forgery), H3 (flag integrity and `initialise`), H5 (timeout enforced by the gateway).
- **Fix soon:** H4, M1-M8, and the tests listed above that cannot fail.
- **Sound:** chain construction and in-database tamper detection, write serialisation, the kill switch's fail-closed reads, absence of a fallback route, and invocation records that hold metadata only.

8 critical/high findings (1 critical, 5 high, 2 of those uncertain-exploitability noted inline: H4), 8 medium, 6 low.

**Summary: 1 critical, 5 high, 8 medium findings** (plus 6 low).

Open items:
- **Blocked on you:** where the anchor (or an external witness) can live, outside the data directory. C1 and H1 depend on that choice.
- **Queued:** nothing.
- **Watch only:** probe scripts are in the scratchpad if you want to turn them into regression tests.
