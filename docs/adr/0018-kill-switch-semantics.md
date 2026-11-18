# ADR-0018: Kill-switch semantics
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (row MACs, outbox, initialise, reconcile, release order, break-glass identity)
Blueprint refs: §7.4, §9.5, §11 (resource exhaustion row: "operator stop control"), §11.2, §18 Phase 5, FR-030, NFR-017, Appendix D (kill switch bullet), OD-01, OD-15; plan gap G20

## Context
BP §11.2 requires "an operator-controlled emergency stop that can disable all write execution, disable external inference, revoke or suspend execution-broker credentials, pause active scans and prevent new L3 runs", with monitoring, evidence preservation and read-only investigation remaining available where safe. It "must be outside the LLM's authority and tested during acceptance". Appendix D adds that it disables "deep/active scans". The BP does not say what happens when the switch state cannot be read, when the audit log is unavailable at the moment of engaging, or when the API or identity layer is down. Those cases need defined behaviour (plan gap G20).

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Asymmetric: an engage persists even when its audit record cannot be delivered, and the record is owed; a release fails closed; unreadable state counts as blocked; host-local break-glass can engage only | Stopping works when the audit path is down; resuming needs everything healthy | For a time an engage may exist with no audit record delivered; a database fault blocks every guarded capability | Errs toward stopped in every failure case |
| Symmetric fail-closed: engaging is refused when its audit record cannot be written | Every state change has an audit record before it takes effect | An emergency stop that can fail to stop, at the moment the system is already misbehaving | Rejected |
| Symmetric permissive: releasing also proceeds without audit | The switch is never stuck | Writes could resume with no record of who resumed them | Contradicts BP §9.5 (fail closed when the audit path is unavailable); rejected |
| Break-glass that can also release | Recovery without the API or identity layer | Shell access to the host would be enough to resume writes | Bypasses the human `security_admin` check; rejected |
| A hardware or out-of-band switch (physical control, separate host, or a network-level cut) | Independent of this process and its database | Needs a host and network that are not decided (OD-01) | Strongest form of "outside the LLM's authority". Not available in a local build |

## Default chosen for the local build
`ciso.killswitch` (`service.py`, `integrity.py`, `outbox.py`, `persist.py`, `breakglass.py`, `tables.py`):

State and reading
- Four capabilities, each with its own stored flag: `writes`, `external_inference`, `active_scans`, `l3_runs`. A flag row holds the state, a version counter, who changed it, when, why, how (`api`, `breakglass`, `reconcile`, `initialise`) and an HMAC.
- Each flag row and each outbox row carries an HMAC-SHA256 over its content, made with a key the kill switch resolves itself (`killswitch_key_ref`). Without it, anyone who can write the operational database could release the switch with a plain UPDATE or plant an outbox row that becomes an audit record.
- Readers call `is_blocked(capability)` or `require_clear(capability)`. A capability reads as blocked when it is engaged, when its row is missing, when the row has no MAC or a MAC that does not verify, when the key is unset or cannot be resolved, and when the state cannot be read for any reason (unknown capability, dropped table, broken engine). Only a verified row that says not engaged reads as clear. With no key configured every capability reads as blocked.
- `active_scans` governs every active probe and also deep tests (BP §7.4); the discovery module must check it for both.

Setting up
- `initialise()` creates clear, MAC'd rows only on a genuinely new installation. It creates nothing when any flag row exists, when any outbox row exists, or, with a history reader wired in, when any `killswitch.*` audit record exists. A missing row then stays blocked and shows in `status()` as not recorded. It needs the key, is safe under concurrent callers, and records its own audit event. A database whose kill-switch rows were all deleted looks new unless the history reader is wired; the composition root wires it.
- At start-up the composition root runs `initialise()`, delivers owed engage records, then calls `reconcile()`. A refusal or a mismatch is listed in readiness.
- `reconcile()` compares each flag with the latest audit record for its capability. A flag that reads clear while the latest record says engaged, or while there is no record at all, is engaged again under the identity `system:reconcile` and reads blocked until a human releases it. A flag that reads blocked after a release is only reported. This catches a replayed older clear row, which the MAC alone cannot see. It also runs from `python -m ciso.app.admin killswitch-reconcile`.

Changing
- Engaging and releasing through the service require a human holding `security_admin`, decided on the actor id resolved from the identity store (`PrincipalResolver`) and not on the object handed in. An unknown, disabled, non-human or non-admin caller is refused, as is any resolver failure, and the refusal is audited. When identity is down, break-glass is the route to engage.
- Engage always stores its intent. The flags and an audit outbox row are written in one short transaction, retried on a busy database and wrapped in `FailClosed` if it still fails. After the commit nothing can turn the engage into an error: delivery to the audit log is tried at once, and anything owed stays in `pending_audit()` for `retry_pending_audit()`. Without the key the rows are stored without a MAC and so read as blocked.
- Release fails closed and never calls the audit log while holding the write lock. It needs the key and a verifiable current row. It delivers everything owed first and refuses if anything is still owed, so the log never shows a release before the engage it undoes. It then audits an ATTEMPT record (if that fails, nothing changes), changes the flags in a short transaction that refuses if a row changed since it was checked, and audits the result. If the result cannot be audited, the flags are engaged again and `FailClosed` is raised. If the change fails, a failed record is written and the flags stay engaged.
- The outbox. Each row is claimed with a conditional update before delivery, so two delivery loops cannot both deliver it, and the record carries the outbox entry id so a duplicate is recognisable. A claim older than the claim timeout (a safety setting) can be taken over. The action is always `killswitch.engage` and is never read from a row. Who the record names follows from how far the row can be trusted: a verified `api` row names the human who engaged; a verified `reconcile` row names the fixed reconcile identity; a `breakglass` row names the fixed `breakglass` identity with actor type `anonymous` and carries the typed operator name as `unverified_operator`; a row with no MAC is delivered as the fixed `unverified` anonymous identity. A row whose MAC fails or that cannot be parsed is quarantined: kept, never delivered, listed by `quarantined_audit()`. One bad row does not stop the others.
- Break-glass is a host command: `python -m ciso.killswitch.breakglass --db <path> --reason <text> --operator <name> [--key-ref secret://<name>]`. It checks that the file exists and is the operational database (it has a kill-switch schema version row), engages all four capabilities directly, queues the audit record in the outbox, and reports success only after reading every capability back through the same check `is_blocked` uses. With `--key-ref` it MACs the rows with a key from the process environment; without a key the rows are unsigned and still read as blocked. It has no way to clear a flag.
- "Suspend execution-broker credentials" is to be met by the broker resolving write credentials through an accessor that calls the kill switch (plan task T2.3). That accessor is not part of `ciso.killswitch` and is not built yet.
- The integrity gate in `ciso.ops` can additionally block `writes` and `l3_runs` when the audit log did not verify, and `external_inference` and `active_scans` when it is unverifiable or failed. It is built and not yet wired into the composition root (ADR-0014).

Weaknesses of this default:
- An engage needs a writable operational database. If the database cannot be read, every capability reads as blocked, but nothing is stored; the block ends when the database comes back.
- Break-glass authenticates nobody. The operator name is typed text, recorded as unverified under the `breakglass` identity. Anyone who can run the command and write the database file can stop the platform, under any name. That is accepted: stopping is cheap, resuming is controlled.
- The flags and the outbox live in the operational database, which is not tamper-evident. The MAC means a writer without the key cannot clear a flag undetected, and `reconcile()` catches a replayed old clear row only if the audit log holds a later engage. A writer who holds the key, or who deletes every kill-switch row, an outbox row and (by wiping it) the audit history, is not stopped. While all modules share one process (ADR-0010), the separation from the model is a policy rule, the MAC key and the absence of any tool for it, not an operating-system boundary.
- Restoring a backup restores the flags as they were at backup time. An engage made after that backup is gone after the restore, and `reconcile()` cannot see it because the restored audit log is old as well (ADR-0014).
- Delivery of an owed record is at least once. The entry id makes a duplicate recognisable and the claim makes one unlikely, but a failure between the audit append and marking the row can still leave a duplicate engage record. Release refuses while a record is owed, so a stuck delivery blocks the release.
- Suspending is not revoking. A credential stays valid at the target system. Real revocation needs the target system or a secret manager (ADR-0008).
- New work is stopped. This ADR does not claim that a tool call already in progress is interrupted.
- Deep tests share the `active_scans` flag, so one cannot be stopped without the other.
- A release needs the audit log, the key and an authenticated administrator. If the audit log refuses appends (ADR-0013), the key is lost or no administrator can sign in, the switch stays engaged until that is repaired by hand.
- One person can engage and release. Whether a release needs a second human is not decided (ADR-0016).
- The kill-switch key has no minimum length check yet; a minimum is being added for every key (ADR-0008).
- The API reads the switch state with the `killswitch.engage` permission, so only a security administrator can see it.

## Why this default is reversible
Seam: the `KillSwitchReader` protocol in `ciso.common.protocols`. Every guarded component reads through it and none knows where the state is stored. An out-of-band switch can be added as a second reader, with a capability blocked if either reader says so. The engage and release rules live in the `ciso.killswitch` service, so changing them does not touch callers.

## Evidence needed to make this final
- The approved host: who has shell access, and whether a physical or network-level stop is feasible (OD-01, ADR-0015).
- Whether the secret store can revoke or suspend credentials itself (ADR-0008).
- The broker's own identity after the process split (ADR-0010).
- The first real write target and its credential model (OD-13, OD-15).
- Who may engage and who may release, and whether a release needs a second person (`docs/phase0/role-and-approver-template.md`).
- An acceptance test of the switch on the deployed host, as BP §11.2 requires.

## Consequences
- With all four capabilities engaged, the broker, write credentials, external inference, active scans, deep tests and new L3 runs must be blocked, and reads, findings and health reporting must keep working. The acceptance test has to show both halves.
- Operator reporting must show owed and quarantined kill-switch audit records, since an undelivered record is otherwise invisible. Start-up reports mismatches found by `reconcile()` in readiness.
- The restore procedure must check kill-switch state before the platform is started again.
- A runbook must tell the operator how to engage through the API, how to use break-glass, and what must be healthy before a release can succeed: the key, the audit log, an administrator, and no owed records.
