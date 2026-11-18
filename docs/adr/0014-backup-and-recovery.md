# ADR-0014: Backup and recovery (online backup into an encrypted archive, plus a restore test)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (backup and restore built; archive format; restore rules; start-up recovery)
Blueprint refs: §3 (register item "Availability", AGREED INITIAL SIMPLIFICATION), §10.3, §11.1, §17.3, §18 Phase 1, §19.3 (resilience tests), NFR-007, NFR-008, NFR-018, OD-01, OD-16, OD-17, Appendix C #14, Appendix D; plan gaps G4, G5

## Context
The BP accepts that an office power or internet outage may interrupt the service and asks for safe handling and predictable recovery, not uninterrupted service (§10.3). It requires "encrypted, access-controlled backups of registry, policy, configuration and audit/evidence metadata; define retention and restore test", a documented recovery procedure, integrity verification, and replay or resynchronization of missed events. No secondary site or HA cluster is in scope. NFR-018 requires recovery "without silent loss or false 'healthy' status". Recovery time and recovery point objectives are not set (OD-16, before production rollout). The backup target is a Phase 0 item (OD-01).

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| SQLite online backup of each database file into an encrypted archive, plus an automated restore test | Consistent copy of each file while the service runs; no extra product; the restore path is exercised by a test | Tied to SQLite (ADR-0002); the files are copied at slightly different moments; no schedule, retention or off-host target defined | The archive is encrypted, so a leaked backup does not expose content unless its key leaks too |
| Stop the service and copy the files | Simplest; all files consistent with each other | Downtime for every backup | Same as above if the copy is encrypted |
| Host volume snapshots | Fast; covers all files at one instant | Depends on host and storage that are undecided (OD-01); encryption and access control are the host's | Snapshot access must be restricted like the data itself |
| Continuous replication or log shipping to a second location | Small data loss window | A second location is outside the accepted initial scope (BP §10.3) | A second copy to protect |
| Native tooling of a future production database | Mature and well understood | Depends on a database that is not chosen (ADR-0002) | Depends on that product |

## Default chosen for the local build
`ciso.ops` (`archive.py`, `backup.py`, `restore.py`, `integrity.py`, `lifecycle.py`) is built as a library. It has no command-line entry and no schedule: something has to call it.

Backup
- `BackupService.create` copies the named sources into one archive while the platform keeps running. SQLite databases are copied with the SQLite online backup API from a separate connection to the live file; nothing copies or renames an open database file.
- The audit database and its head anchor are captured together: the service holds the audit database's write lock while it reads the anchor and copies the database, so the pair is consistent. A source set with one and not the other is refused, because a restored audit log cannot be verified without its anchor (ADR-0013).
- Evidence blobs are a directory member: every regular file under it is archived and a symbolic link is refused. There is no evidence module yet, so the member is empty in practice.
- Plaintext copies of the databases exist only in a private temporary directory and are deleted in a `finally`. The archive is written under a temporary name and renamed when complete.
- Who may back up: a human holding `security_admin`, or a service such as a scheduler. Agents and other humans are refused, and the refusal is audited. The backup is audited as `backup.create`; if that audit write fails, the archive is deleted and the call raises `FailClosed`.
- The archive key is named by `Settings.backup_key_ref`, a `secret://` reference. With none, the call refuses; no key is ever generated.

Archive format (`ciso.ops.archive`, files end in `.cisobak`)
- Every record is encrypted with AES-256-GCM and a fresh random nonce. The key is derived by HKDF-SHA256 from the backup secret with a per-archive salt, so no two archives share a key. The associated data binds each member to the archive id, its position, its name and its size, and the manifest to the header, so a member cannot be renamed, reordered, resized or moved to another archive without a tag failing.
- The manifest (member names, sizes, SHA-256 of each plaintext, row counts, the audit log id and the key id) is the last record and must be followed by end of file, so a truncated archive has no valid manifest. The key id is derived from the secret and never reveals it, so a wrong key is reported as such before anything is decrypted.
- Member names mirror the data directory layout: databases under `db/`, the anchor under `anchor/`, evidence under `evidence/`.

Restore
- `RestoreService.restore` writes an archive's members into an empty directory, never over live files. Only a human holding `security_admin` may restore; a refusal is audited.
- The whole archive is authenticated (every tag, the manifest, member order, sizes, hashes) before anything is written. A failure leaves the target empty. The attempt is audited before any file is written; if that fails, nothing is written. If anything fails while writing, everything written is removed again. The result is audited; if that fails, the restored files are removed and the call raises `FailClosed`.
- After writing, the restored databases are opened read-only and their row counts are compared with the manifest, and the restored audit log is verified against its restored anchor, with the log id from the manifest as the expected id. The report says plainly whether the audit log verified. It always warns that a restore brings back the kill-switch flags as they were at backup time, and that the audit check cannot tell a legitimate restore from a rollback.
- Restore does not put anything in service. The operator has to move the restored files into place and start the platform. No command does either.

Start-up and shutdown recovery (`lifecycle.py`, `integrity.py`)
- `startup` runs, in order: operational schema check (refuses a version mismatch), kill-switch initialise, audit `verify()`, delivery of owed kill-switch audit records (only when the audit log verified `ok`), kill-switch `reconcile()`, component health registration, a sweep that counts leases that expired during the outage, and an `ops.startup` audit record when the log verified. Each outcome is recorded.
- The result feeds `IntegrityState`, and `GatedKillSwitch` adds it to every kill-switch answer: writes and L3 runs stay blocked unless the audit log verified `ok` and no start-up step failed; external inference and active scans are blocked when verification is `unverifiable` or `failed`. Reads, monitoring and evidence preservation are never blocked.
- `shutdown` stops accepting work, waits up to a caller-supplied deadline for in-flight leases, checkpoints the write-ahead log and disposes the engines.
- This is not yet wired. The composition root does not call `startup` or use `GatedKillSwitch`. It runs its own start-up steps for the kill switch (initialise, deliver owed records, reconcile) and opens the audit log, but a chain verification that fails does not block writes there today.
- RTO and RPO are not set.

Weaknesses of this default:
- No schedule, no retention period, no off-host target and no command to run a backup or a restore. A backup on the same disk does not survive loss of that disk.
- Without RTO and RPO, there is no definition of an adequate backup frequency or restore time.
- A restore needs keys that this build does not know how to recover: the archive key, the audit HMAC key and, for evidence, the evidence key. Without the audit key the restored log reads as `unverifiable` and appends are refused, which does not stop sign-in (ADR-0004). BP §11.1 requires key recovery to be documented.
- A restored audit database and anchor verify as `ok` even though they are older than what was lost. The restore test cannot tell a legitimate restore from a rollback (ADR-0013). The witness is deliberately kept apart from the archive and restore does not consult it. Read from the code, not measured: on a deployment with a witness, a legitimately restored older log would be refused as `rolled_back` at the next append, and there is no procedure for accepting a legitimate restore.
- A restore brings back the kill-switch flags as they were at backup time. An engage made after the backup is silently undone. The start-up reconcile compares the restored flags with the restored audit log, and both are old together, so it cannot see the loss. Only the operator can: the report says to engage the switch before the restored instance is used, and no runbook exists yet.
- The operational and audit files are captured at different moments, so a restored pair can disagree at the edges (for example an operational row whose audit record is missing).
- A backup made by a different code version may carry a different module schema version, and the application then refuses to start (ADR-0002).
- Whether evidence blobs are in an archive depends on the sources the caller names. BP §10.3 lists "audit/evidence metadata". A metadata row restored without its blob is a broken evidence reference, and nothing checks that yet because there is no evidence module.
- The restore test checks integrity and counts. It does not prove the restored data is semantically correct.
- After a restore, events that a source did not retain are gone. They must be reported as a coverage gap (BP §10.3).
- The integrity gate and start-up sequence are built and tested but not wired into the composition root, so "if verification fails, writes stay blocked" holds in the library and not yet in a running platform.

## Why this default is reversible
Backup and restore are operational tooling outside the domain modules (`ciso.ops`). Replacing the method means replacing that tooling and the recovery procedure. The invariant to keep through any change is the automated restore test: restore into an empty location, verify the audit chain and anchor, check counts, check kill-switch state, then resynchronize connectors from their checkpoints.

## Evidence needed to make this final
- Recovery time and recovery point objectives (OD-16).
- The backup target, its location and who has physical and logical access (OD-01).
- Retention for backups, consistent with retention for the data inside them (OD-17).
- Which sources can replay missed events and for how long, from the source-system matrix.
- Where each key is held and how it is recovered when the host is lost.
- A procedure for accepting a legitimate restore when a witness is configured.
- Any legal limit on where backups may be stored (OD-10).

## Consequences
- A tested backup and restore path exists for the local build. It is a library, run by code.
- A recovery procedure document, a schedule, a command-line entry and an off-host target remain to be written once OD-01 and OD-16 are answered.
- The recovery procedure must say what the operator does with kill-switch state and with the audit anchor and witness before starting the platform.
- The decision on including evidence blobs must be made together with ADR-0003.
- Wiring `startup` and `GatedKillSwitch` into the composition root is part of closing this ADR.
