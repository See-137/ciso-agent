# ADR-0002: Operational and audit storage
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (file layout, transaction mode, read-only connections)
Blueprint refs: §1.2, §3 (register item "Technology stack", DEFERRED), §5.1 #8 and #14, §6.3, §6.6, §11 (audit tampering row), NFR-006, NFR-007, NFR-011, NFR-016, Appendix C #14

## Context
The BP recommends "a relational store for canonical entities, relationships, policy records, jobs and findings" and says a relational graph representation is adequate for an initial registry (§6.6). It does not select a database product (§1.2) and says exact products remain deferred. It requires audit storage that is tamper-resistant and separate from agent write permissions (§5.1 #14) and separation of the audit store from other permissions (NFR-016). The foundation build needs working storage to test the registry, queue, policy records and audit path.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| SQLite files through SQLAlchemy 2.0 Core; audit in its own database file | No server to install; real transactions; whole platform testable on a developer machine; audit file can get its own file permissions | One writer at a time per file; no network access; no database-level roles; SQLite-specific features (pragmas, triggers, backup API) must be ported later | Access control is file permissions only. While all modules run in one process (ADR-0010) the "separate writer identity" for audit is not real. The database files are not encrypted by this build |
| PostgreSQL from the start | Concurrent writers; database roles per component; mature backup and replication tooling | A server to install, secure, patch and back up before any feature exists; assumes a host that is still OD-01 | Roles could enforce that only the audit writer inserts into audit tables; adds a network listener that must be kept private (BP §10.2) |
| One SQLite file for everything | Simplest; one backup unit | Audit shares a file and a writer with operational data | Fails the separation the BP asks for (§5.1 #14, NFR-016) |
| Dedicated graph database for the registry | Natural relationship queries | New product and query language; BP says it is not a prerequisite (§6.6) | No clear gain until query needs are observed |

## Default chosen for the local build
SQLAlchemy 2.0 Core (table definitions and SQL expressions, no ORM session state) on two SQLite files under `data_dir/db/`: `ciso.db` for operational data and `audit.db` for the audit log only. WAL mode and `synchronous=FULL` are enabled, with a busy timeout. `data/` is git-ignored. The audit head anchor and the optional witness are kept outside `data_dir/db/` (ADR-0013), and evidence, when it exists, under `data_dir/evidence/`.

Transactions (`ciso.common.db.create_db_engine`):
- The driver's own transaction handling is switched off and every transaction starts with `BEGIN IMMEDIATE`, so it takes the write lock at once. With the driver's default, the lock is taken only at the first write, and two processes could both pass a "does a row exist?" check and both insert. With the lock taken first, a check followed by a write inside one `engine.begin()` is serialised across processes. Two engines on one file are covered by tests for the audit log and the kill switch.
- A read-only helper, `read_connection(engine)`, starts a plain `BEGIN`, never takes the write lock and rolls back on exit. Code that only reads uses it, so readers do not queue behind writers. A write through it would bring the race back; that is a convention, not something the helper stops.
- Callers must not hold a transaction open across slow work (password hashing, a call to the audit log, network input and output), because every transaction is now a write lock. The identity, kill-switch, queue and inference code each read or verify first, then write in a short transaction, then call the audit sink outside any transaction.

Schema management for the operational database (`ciso.common.db`):
- The schema is created from the table definitions, not from migration scripts. Each module registers its own tables on one shared `operational_metadata` in its own `tables.py`. There are no foreign keys across modules; a cross-module reference is an `EntityRef` string.
- `init_operational_schema` creates every registered table and records one `schema_version(module, version)` row per module.
- If the stored version for a module differs from the version the code expects, the application refuses to start. There is no upgrade and no downgrade path in this build.
- The audit database has its own metadata and is created only by `ciso.audit`, so ordinary writers hold no handle to it.

Not chosen:
- The production database. PostgreSQL is the likely candidate. It is not selected.
- Migration tooling. A change to a module's tables means raising that module's version, and an existing data file then stops the application until someone migrates it by hand or discards it. This is acceptable only while no data file holds real company data.

Weaknesses of this default:
- "Portable to PostgreSQL through Core" is a prediction. It becomes a measurement only when the test suite runs against the candidate database. Known dialect-specific parts are listed below.
- BP NFR-007 requires encryption at rest. For the database files this build relies on host disk encryption, which is a Phase 0 item (ADR-0015). Evidence blobs are encrypted by the application (ADR-0003).
- Anyone who can write the files can bypass every application control, including the audit triggers (ADR-0013).
- Because every writing transaction is `BEGIN IMMEDIATE`, writers queue behind each other. A caller that holds a transaction too long makes others wait up to the busy timeout and then fail. The modules wrap that failure in `FailClosed`; the kill switch retries a locked database before it gives up.
- Only the SQLite behaviour was tested. Whether another database gives the same serialisation is a prediction until the suite runs there.

## Why this default is reversible
Seam: the engine factory in `ciso.common.db`. Each module owns its tables and talks to the database only through Core expressions. To switch database:
1. Change the engine configuration.
2. Port the dialect-specific parts: SQLite pragmas, the audit triggers (ADR-0013), the lease statements in the job queue (ADR-0007), the backup procedure (ADR-0014).
3. Choose migration tooling and write the first migration from the current table definitions. The `schema_version` rows give the starting version of each module.
4. Run the full test suite against the new database.

## Evidence needed to make this final
- Expected event rates, number of connected sources and retention needs (BP §15.1).
- Whether components are split into separate processes or hosts and need concurrent writers (ADR-0010).
- The approved host, disk encryption and backup target (OD-01).
- Retention schedules (OD-17), because they set data volume.
- Whether database-level roles are required to satisfy "separate writer identities" (BP §11).
- A test run of the suite against the candidate production database.

## Consequences
- The platform runs with no database server, which keeps the local build simple.
- Migration tooling must be chosen before the first deployment that stores real data.
- The move to a production database is a planned task, not a configuration change.
- Throughput is bounded by one writer per file; no performance target is set (BP §15.1).
