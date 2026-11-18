# M2 review: approvals and the external inference gate

Date: 2026-11-18

Scope: `src/ciso/approvals/` and `src/ciso/inference/external/`, with `tests/approvals/` and
`tests/external_inference/`. `src/ciso/execution/` was not opened.

Method: every source file in scope read line by line; attacks then built as a standalone
script against the real classes (in-memory database, the repo's own fakes); guards switched
off in memory (monkeypatch, no file in the repo touched) and the two targeted test
directories re-run to see whether a named test turns red. Baseline: `241 passed`.

- Proof script: `C:\Users\<user>\AppData\Local\Temp\claude\3cfcfec24bc61f22\195baec2-9149-4e3c-abf0-1f9b23c4bb58\scratchpad\rev1-proofs.py`
  (run from the repo root: `uv run python -B <path>`). Proof ids P1 to P16 below are its sections.
- Guard-removal runner: `...\scratchpad\rev1-mutrun.py <mutation>` (same directory).

"MEASURED" means the behaviour was produced by running one of those. "READ" means it was
concluded from the code only.

Context that limits impact today: no transport implementation exists in `src`, the feature
flag defaults to off, and the API router that will call these classes is not built. Every
finding below is about what the classes allow once those three exist.

---

## C1. The gateway sends whatever `PayloadPreview` it is handed: minimization, redaction and the proposal step can all be skipped

Where: `src/ciso/inference/external/gateway.py:149-214` (`request_approval`), `218-267`
(`transmit`); `minimize.py:187-225` (`PayloadPreview._bytes_match`); `gates.py:79-86`.

What breaks: "minimization cannot be bypassed", "what is sent is what was previewed", "no
secrets or payload text in audit details or the database", and "every external path step is
audited".

`request_approval` and `transmit` take a `PayloadPreview` from the caller. Payload bytes are
not stored (by design), so the preview has to come back from outside the gateway at transmit.
The gateway never sees the proposal, never calls `minimize`, and never runs the redactor over
the outbound bytes (the redactor it holds is used only on the answer). The only checks are
the model validator (hash matches bytes; request id, provider, model, purpose and the
`(ref, classification)` pairs match the JSON) and the label check in `Gates.refusal`. Both
check labels the caller wrote. Nothing checks the item text, the set of keys in the JSON,
that the bytes are canonical, that the request id was ever proposed, or the shape of `ref`.

Sequence (P1, MEASURED): build `PayloadPreview` directly with one item labelled `public`
whose text is restricted content plus a registered secret, a request id that was never
proposed, and an extra top-level key `attachments`. `request_approval` accepts it, the owner
approves, `transmit` sends. Result: `transport calls=1 secret_in_sent_bytes=True
extra_key_sent=True propose/preview audit events=0`.

Related, same root cause:
- P1b (MEASURED): a secret placed in `purpose` is stored in
  `external_inference_authorization.purpose` (and would be copied to the record row); a
  `kept[].ref` holding free text with spaces and a newline is stored in the database and in
  the audit details of `inference.external.authorize`. `ItemLabel.ref`, `DroppedItem.ref` and
  `DroppedItem.classification` are unvalidated strings, so `dropped` is a free-text channel
  into the audit log.
- P15 (MEASURED): bytes with a duplicate JSON key (`"model":"other-model","model":"model-1"`)
  pass the validator, which reads the last one. A receiver that reads the first sees another
  model than the one recorded and approved.

What the approver can see makes this worse: the authorization row holds hashes, sizes, refs
and labels. The approver is shown labels the requester chose. ADR-0006 already says the
binding "does not guarantee that the approver read them"; this finding is different: the
labels and the "minimized" claim themselves are unverified.

Smallest fix: make the gateway the only producer of sendable bytes. `request_approval` takes
the `ExternalRequestProposal` (or a request id for a proposal held server side) and calls
`minimize` + `build_preview` itself with its own scheme, allowed set and redactor; `transmit`
rebuilds the bytes the same way (or reads them from a server-side store keyed by approval id)
and compares the hash. If the preview must stay caller-held, at minimum: re-serialise
`json.loads(raw)` canonically and require equality with `raw`; require the exact key set at
both levels; require `is_id(request_id, "xrq")` and `EntityRef.parse` on every ref; require
`redactor.redact(text) == text` for the purpose and each item; and have the proposal service
sign the preview with a keyed digest the gateway verifies.

---

## H1. `approve` / `reject` accept any hand-built `Principal`; nothing proves the caller is that person

Where: `src/ciso/approvals/service.py:160-193`; `tests/architecture/test_import_boundaries.py:52-54, 65-73`
(out of scope, read for context).

What breaks: "only a human can approve", "the language model is never a root of trust".

`_decide` takes `approver.actor_id` and `approver.credential_issued_by` from the object it is
given. Roles and actor type are resolved again (good), but identity itself is whatever the
caller typed. The import rules forbid `ciso.approvals` from importing the orchestrator; they
do not forbid `ciso.orchestrator` or `ciso.inference` from importing `ciso.approvals`.

Sequence (P4, MEASURED): `Principal(actor_id="human_owner", actor_type=ActorType.AGENT,
credential_issued_by="made-up")` passed to `approve` on an agent-requested approval. Result:
`approved_by=human_owner issuer=made-up`, and `consume` then succeeds. The object even says
it is an agent; that field is ignored.

Whether agent code can reach an `ApprovalService` instance depends on the composition root,
which is not wired yet. The class itself gives no protection.

Smallest fix: `approve`/`reject` should not take a caller-built `Principal`. Take a proof the
identity module issued (session or token reference that the service resolves through an
`Authenticator` protocol to actor id and issuer), or at least add an architecture rule that
only the approvals API router and the composition root may reference
`ApprovalService.approve`/`reject`, and add `ciso.approvals` to the orchestrator's and
inference's forbidden imports (they need `check`/`consume` at most through the broker).

---

## H2. Separation of duties is one-directional and binds the filer, not the author

Where: `src/ciso/approvals/rules.py:153-169` (`separation_refusal`); `service.py:113-156`
(`request` has no issuer input); `gateway.py:170-179`.

What breaks: "approving your own request through any path".

The rule refuses (a) approver == requester and (b) approver's credential issued by the
requester. It does not cover the mirror case, the requester's credential issued by the
approver, because `request` never learns who issued the requester's credential. On the
external path the requester is whoever calls `request_approval`; the proposer and the
previewer are not bound to anything and are not on the record.

Sequences:
- P2 (MEASURED): a second actor record `human_puppet` (role `employee`) files the request;
  `human_owner` approves and transmits. `status=approved self_approved=False sends=1`. If the
  owner controls that record (minted its token, or also holds `security_admin`, which BP 9.3
  allows), one person did everything and the record shows two.
- P3 (MEASURED): `human_owner` proposes and previews, a role-less `human_emp` only calls
  `request_approval`, `human_owner` approves and transmits. Record: `requested_by=human_emp
  approver=human_owner transmitted_by=human_owner`. The author of the payload is absent.
- READ: the issuer check is one hop. Requester R mints a token for X, X mints one for
  approver B: B's issuer is X, not R, and passes.

ADR-0016 lists "one person could hold two actor records" as a known weakness, so part of this
is accepted. The mirror-issuer case and the unbound proposer are not written down anywhere I
found, and both are cheap to close.

Smallest fix: `request` takes `requester_credential_issuer` and stores it; `separation_refusal`
also refuses when it equals the approver. On the external path, carry
`proposal.requester_actor_id` into the authorization and refuse an approver who is the
proposer, the previewer or the filer; record all of them on the transmission record.

---

## H3. A payload can be sent and leave no closing audit record and no final ledger state

Where: `src/ciso/inference/external/gateway.py:298-318` (`_send`), `320-343` (`_finish`).

What breaks: "a failure anywhere can lead to a send without an audit record". `_send`'s
docstring says "Never raises"; it can.

- P6 (MEASURED): the redactor raises on the answer (lines 313 and 317 are outside both `try`
  blocks). Result: `sends=1 raised=RuntimeError record.outcome=attempted
  transmit_audit=['attempt']`. The raw `RuntimeError` reaches the caller with whatever the
  redactor put in it.
- P7 (MEASURED): `complete_record` fails after the send (database down or locked). Result:
  `sends=1 raised=FailClosed record.outcome=attempted transmit_audit=['attempt']`. `_finish`
  raises before it reaches `_emit`, so the audit log is never told the payload left.

`ATTEMPTED` is documented as "possibly sent", so the row is not a lie, but the audit log, the
record of last resort, holds only an attempt for a payload that did leave.

Smallest fix: in `_send`, wrap the redaction and wrapping in the second `try` (outcome
`MALFORMED_RESPONSE`, type name only). In `_finish`, emit the result audit event in a
`finally`-style path: if `complete_record` raises or returns False, still emit
`inference.external.transmit` with outcome `FAILED`, `sent: true` and `record_incomplete:
true`, then raise.

---

## M1. A database writer can mint a usable approval; `decision_audit_ref` is only checked for presence

Where: `src/ciso/approvals/rules.py:178`; `store.py:185`; class docstring `service.py:60-64`
("grant audited").

Sequence (P5, MEASURED): update a pending row to `status='approved'`, `decided_by` = any
active human with the role, any non-empty `approver_credential_issuer`,
`decision_audit_ref='aud_does_not_exist'`. `consume` succeeds; `approve_audit_events=0`.

The docstring claims validity includes "grant audited". What is delivered is "a non-empty
string is in the column". A direct database writer is a strong attacker, but the audit log is
a separate database precisely so that it can catch this.

Smallest fix: either state the limit in the docstring and ADR, or verify at `consume`:
look the ref up through a read method on the audit side (record exists, action
`approval.approve`, outcome success, target this approval, actor `decided_by`) and refuse
with `GRANT_NOT_AUDITED` otherwise.

## M2. The kill switch is read once, at the top of `transmit`

Where: `gateway.py:229-233` vs the send at `266`.

Sequence (P8, MEASURED): the switch is engaged while the approval is being consumed (after
the gate, before the transport call). Result: `kill_blocked_now=True sends=1`. Between the
gate and the send there are two database writes and three audit appends, so the window is as
wide as the audit path is slow.

Smallest fix: call `self._gates` kill-switch check again immediately before
`transport.send`; if blocked, complete the record as not sent, audit `DENIED`
(`kill_switch_engaged`), raise.

## M3. Any human can file and any human can transmit

Where: `gates.py:73-78`; `gateway.py:161-165, 229-233`.

The gate asks only "human, known, now". No role is required to file an approval request, and
the transmitter need not be the requester, the approver or hold any role.

Sequence (P10, MEASURED): `human_emp` files, the owner approves, the read-only `human_aud`
(auditor) calls `transmit` with the same preview: `sends=1`. The class docstring leaves read
permissions to the caller explicitly; for `request_approval` and `transmit` it says nothing,
so a router author has no warning.

Smallest fix: `transmit` requires `caller.actor_id == stored.requested_by` (or a configured
transmitter role, unset means refuse). State in both docstrings what the router must check.

## M4. A request reported as "voided" can already be approved and stays usable

Where: `service.py:148-155`, `389-393`; `store.py:193-199`.

`_void` discards the boolean from `store.void` and only logs when it raises. If the row left
`pending` between the insert and the failed audit, nothing is voided and the caller is told
it was.

Sequence (P9, MEASURED): the SUCCESS audit of `request` fails after an approver (who saw the
row in `list_pending`) approved it. Result: `request said [ApprovalUnavailable: request could
not be audited; it was voided] ; row afterwards consumed=consumed`. The window is narrow in
practice; the message is wrong and there is an approved approval with no request record in
the audit log.

Smallest fix: `void` a request from any non-consumed state (`status IN (pending, approved)`),
check the return value, and change the message to say whether voiding happened.

## M5. Actor ids, binding fields and correlation ids take control characters; requester and approver are compared as raw strings

Where: `rules.py:60-93` (`_text_map`, `check_actor`), `125-128`, `163`; `service.py:144`;
`gateway.py:149-151, 218-220`.

Sequence (P12, MEASURED): requesters `'agent\nciso\x00\x1b[31m'`, `' human_owner'` and
`'human_owner\u200b'` are all accepted, with binding `{"k\n": "v\r\n\x00"}` and correlation id
`"c\nid"`. Each request is then approved by `human_owner` with `self_approved=False`.

Two effects: control characters and terminal escapes flow into audit records and logs; and
the self-approval rule is defeated by any caller that passes an unnormalised id for the same
person. `request` documents that the rule "is only as good as `requested_by`", but it could
check far more than it does.

Smallest fix: one identifier pattern (`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`, `fullmatch`)
for actor ids and correlation ids; printable-only for binding keys and values; and resolve
`requested_by` through `PrincipalResolver` in `request`, storing the resolved `actor_id` and
refusing an unknown requester.

## M6. No size limits on items, text, preview bytes or the answer

Where: `proposal.py:90-133`; `minimize.py:187-205`; `service.py:110-113, 151-155`;
`transport.py:32`.

Sequence (P14, MEASURED): 20,000 items plus one 5 MB item are accepted; the preview is
6,249,058 bytes and one audit event carries 1,409,155 characters of details (every ref is
listed twice per step, and again at authorize and transmit). The answer body has no cap
either (READ). Purpose is the only bounded field.

Smallest fix: constructor arguments `max_items`, `max_item_chars`, `max_payload_bytes`,
`max_response_bytes`, each `int | None` with `None` meaning refuse (they are numeric safety
parameters); cap the ref lists in audit details at a count plus a hash of the full list.

---

## L1. Expiry follows the clock in both directions

Where: `models.py:159-160`; `store.py:186`. P11 (MEASURED): expired at +2h, clock set back,
`consume` succeeds. Fix: store nothing new; refuse when `now < decided_at` (the clock is
behind a time this approval has already seen).

## L2. The decision note is stored as typed

Where: `service.py:174, 206-207`. P16 (MEASURED): a registered secret in `note` is in
`approval.decision_note`. The approvals service has no redactor. Fix: inject `Redactor` and
redact the note before `store.decide`.

## L3. Guards with no test

MEASURED with `rev1-mutrun.py`; each of these left all 241 tests green:
- `textmap-no-limits`: `MAX_BINDING_FIELDS` and `MAX_FIELD` (`rules.py:65, 71, 73`).
- `note-no-limit`: `MAX_NOTE` (`rules.py:126`).
- `actor-no-limit`: `MAX_ACTOR` (`rules.py:91`).
- `minimize-no-purpose-redaction`: the purpose redaction inside `minimize` (`minimize.py:152`).
  `propose` redacts first, so the tests never reach `minimize` with an unredacted purpose.

Also READ: `request`'s `[:128]` truncation of the correlation id (`service.py:144`) has no
test, and silently changes a caller's id instead of refusing it.

## L4. `list_pending(role=...)` lists rows whose stored role cannot approve

Where: `service.py:104-109`. P13 (MEASURED): a row with stored roles `["security_admin"]` is
listed for `role=SECURITY_ADMIN`; nobody can decide it (see "Checked and found sound"). A
display inconsistency only. Fix: filter on `role in record.required_roles and role in APPROVER_ROLES`.

## L5. Failures before the send leave an audit ATTEMPT with no closing event

Where: `gateway.py:264-265` (record insert fails after the attempt audit), `204` (authorization
insert fails after `approvals.request` succeeded: a pending approval remains that can be
approved and never used). READ. Nothing is sent in either case. Fix: emit `FAILED` on the
way out; void the orphan approval.

---

## Suspicions (not made concrete)

- `service.py:183, 205-209`: `now` is taken before the resolver and the attempt audit and is
  then used both as `decided_at` and in the `expires_at > decided_at` condition. A slow audit
  path lets a decision land after the real expiry with an earlier timestamp. `consume` uses a
  fresh `now`, so the approval cannot be used late; only the recorded decision time is off.
- Role revoked between `_validate` and the conditional UPDATE in `consume`
  (`service.py:263-268`): the UPDATE cannot re-check identity, so there is a window of one
  audit append. Inherent to the design unless identity lives in the same database.
- `service.py:386`, `393`: `logger.exception` writes the audit sink's traceback. If a real
  sink ever puts event details in its exception text, they reach the log.
- `gateway.py:308`: a transport returning a subclass of `TransportResponse` with a hostile
  `model_dump` is contained by the `try`, but the object's own code runs in-process. Only
  matters once a transport exists.
- `binding.py:95`: `approved_at=approval.decided_at or now` and `approver=... or ""` invent
  values if the approval row is malformed, instead of refusing. Unreachable through
  `state_refusal` today.

---

## Checked and found sound

MEASURED (guard removed in memory, a named test went red):
- Single use: each of the eight conditions in `ApprovalStore.consume` (status, not consumed,
  audit ref present, unexpired, kind, hash, binding, decider) is individually tested
  (`test_validity.py:282, 295`).
- `decide` only from pending and only unexpired; `confirm_grant` once; `void` only from the
  named state.
- A grant without its audit ref is unusable, including when voiding fails.
- Binding at transmit: `same_binding` and the approvals module's own subject check each catch
  a changed payload, provider, model, purpose or request id independently; the hash is taken
  again over the bytes (`fresh_binding`), not read from the preview.
- Gates at transmit with an approved request in hand: feature flag, kill switch, label not
  allowed, empty allowed set, non-human actor, identity unavailable.
- Self-approval and the issuer rule are re-checked at use from the stored record; an unknown
  issuer is refused.
- Stored roles outside `APPROVER_ROLES` never count (`covering_roles` intersection).
- Requester type `anonymous` refused; non-approver roles refused at request.

MEASURED (P13): a record whose stored required roles do not intersect `APPROVER_ROLES`
(`["security_admin"]`, `[]`, `["employee","auditor"]`) cannot be approved by the admin, the
owner or an employee: `approver_lacks_role` in all nine cases.

READ:
- Replay: `consume` is one conditional UPDATE under `BEGIN IMMEDIATE`; the transmission
  record has a unique `approval_ref`. Two approvals for one preview need two human decisions.
- Two approvers / approve vs reject: the loser gets `ALREADY_DECIDED` and a `DENIED` record.
- Expiry boundary is consistent: `now >= expires_at` is expired in the model, `expires_at > now`
  in every UPDATE.
- The audit sink and the resolver are never called inside a store transaction in either
  package; every store method opens and closes its own transaction.
- Audit failure states: attempt fails, nothing changes; request result fails, voided (except
  M4); grant result fails, voided and unusable anyway; consume result fails, stays spent;
  authorize result fails, authorization withdrawn; transmit attempt fails, no send.
- `binding`, `target`, `policy_decision`, `response_metadata` are frozen maps; models are
  frozen with `extra="forbid"`.
- TTL unset refuses request, approve, check and consume; no numeric default anywhere in scope.
- An unreadable row raises `RECORD_UNREADABLE` rather than being treated as an approval.
- Exceptions and reprs: item text and preview bytes are `repr=False`; validation errors name
  fields only; transport errors keep the type name only; the answer is wrapped and redacted;
  metadata is limited to identifier-shaped values and only its keys are audited.
- All five regex validators use `fullmatch` (re-read after the coordinator's note:
  `rules.py:51, 53`, `proposal.py:85`, `transport.py:41, 43`).
- No vendor, product or person names and no network library in the two packages.
- On the honest path (proposal service, then gateway) the bytes sent are the bytes previewed.

## Not reviewed

- `src/ciso/execution/` (excluded), the API router and the composition root (not built), so
  how `Principal`, previews and approval ids actually reach these classes is unknown.
- The blueprint text itself (sections 8.4, 9.3, 9.5, 11.1) was not read directly; the
  guarantees were taken from ADR-0006, ADR-0016, ADR-0021, the plan's gap and task rows,
  `builder-rules.md` and the brief.
- Tests were assessed by name, by the guard-removal runs above and by reading the fixtures,
  not line by line. `test_no_fallback.py` and `test_egress.py` were not examined.
- The real audit sink, the real identity resolver and `SecretRedactor`'s pattern coverage.
- Concurrency under a file-backed database with real threads (the repo has a two-consumer
  test; I did not add others).
- `mypy` and `ruff` were not run.
