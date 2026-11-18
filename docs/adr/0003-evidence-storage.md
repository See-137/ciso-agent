# ADR-0003: Evidence storage
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Blueprint refs: §4.5, §5.1 #9, §6.5 (evidence_ref), §6.6, §11.1, §13.2 (payload_ref), FR-011, FR-031, NFR-007, OD-09, OD-17, Appendix C #14; plan gaps G7, G8, G10

## Context
The BP requires an evidence store for "raw or minimally transformed supporting evidence, snapshots, reports and artifacts" with encryption, access controls, retention, redaction and integrity checks, and tells us to avoid unnecessary raw content (§5.1 #9). §6.6 recommends "an encrypted object/evidence store for larger artifacts and snapshots" and defers the product. Every important fact and finding must link to evidence (FR-011). Customer tenant boundaries must stay intact through evidence storage (§11.1). Data classes (OD-09) and retention schedules (OD-17) are unknown.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Encrypted, content-hashed blobs on the local filesystem, with metadata rows in the operational database | No extra service; encryption is under application control; integrity check by re-hashing | Key management is ours; no built-in versioning, lifecycle rules or replication; deletion on an ordinary filesystem is not secure erasure | Blob content is protected even if the disk or a backup leaks, as long as the key does not leak with it |
| Blobs stored inside the relational database | One store, one backup, transactional with metadata | Large rows inflate the database and its backups; harder to apply separate access rules | Evidence and operational data share one access boundary |
| An object storage service (product not chosen) | Versioning, lifecycle and retention features; scales independently | A service to run and secure, or an external dependency; assumes a host or provider that is not decided | Could add write-once retention; adds a network path and credentials |
| Plain files, relying on host disk encryption only | Simplest | No protection once the volume is mounted; backups carry plaintext unless separately encrypted | Weakest; any process that reads the directory reads the evidence |

## Default chosen for the local build
The evidence module is planned (tasks T3.1 and T3.2) and was not yet in `src` when this was written.
- Blobs are encrypted with AES-256-GCM, with a key id recorded per blob, and written under `data/evidence/`. No plaintext is written to disk. The content hash is checked on read and a tampered blob is refused.
- The key is named by `Settings.evidence_key_ref`, which must be a `secret://` reference (ADR-0008).
- Each blob has a metadata row with classification, source, `tenant_ref` and retention (G8).
- Classification labels are not built in. A label must belong to the configured scheme; a missing label is `unknown`, which ranks above every configured label (ADR-0017). The earlier wording "unknown is handled as restricted" no longer applies, because no label named "restricted" exists in code.
- Reading requires a purpose and a role. The most sensitive data, and anything `unknown`, also requires a purpose grant. A tenant filter applies. Every access is audited.
- Retention that is unset means no automatic deletion, and the item is flagged. A deletion leaves a tombstone and an audit record. Key rotation re-encrypts.
- In the ingestion pipeline the payload is stored as evidence first, so the event envelope and the source fact can carry its reference (G10).

Weaknesses of this default:
- The plan says a purpose grant is required for "restricted or unknown" classification. With no label names in code, the threshold has to be a configured ceiling, and that setting is not defined yet.
- One key from the development secret provider, with no documented recovery. Losing the key loses all evidence. BP §11.1 requires key ownership, recovery and rotation to be documented; that is not done.
- A content hash over plaintext lets anyone who can read metadata confirm a guess about low-entropy content. Whether the hash should be keyed is open.
- No retention schedule exists (OD-17). Until one does, nothing is deleted automatically and stored evidence only grows.
- The labels in the provisional settings file are placeholders, so every classification stored under them is provisional too (ADR-0017).
- A deleted or missing blob file is detected only when an integrity check compares metadata rows to files.

## Why this default is reversible
Seam: the evidence store interface in `ciso.evidence`. Callers hold an opaque evidence reference and never a file path. To switch backend: write a new implementation of the same interface, copy the blobs, and re-verify every content hash against its metadata row. Registry facts and findings keep the same references.

## Evidence needed to make this final
- Data classes and customer data categories (OD-09).
- Retention schedules for evidence and related records (OD-17).
- The rule for raw customer content in a specific incident: purpose, authorization, minimization, retention (BP §4.5).
- Host storage, disk encryption and backup target (OD-01).
- Who owns the evidence key, how it is recovered and how it is rotated (BP §11.1).
- Observed evidence volume and object sizes.

## Consequences
- Evidence handling can be built and tested now, including access checks, tenant filtering and audit of reads.
- Key management is the main gap and must be closed before real evidence is stored.
- Backups must treat blobs, metadata rows and the key as three things that are restored together (ADR-0014).
