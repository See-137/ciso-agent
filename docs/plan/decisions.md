# Coordinator decisions on the plan

Date: 2026-11-17. The owner asked for an autonomous local build, so the three items the
planner marked "blocked on you" are decided here as reversible defaults and recorded in
ADRs for the owner to overrule. This file wins over `implementation-plan.md` where they
differ.

## Gap list (G1 to G33)

Accepted as written: G1, G2, G3, G4, G5, G6, G8, G9, G10, G11, G12, G13, G15, G16, G17,
G18, G19, G20, G21, G22, G23, G24, G25, G26, G27, G29, G30, G31.

Accepted with a change:

| Gap | Decision |
|---|---|
| G7 classification labels | `ciso.common.classification.ClassificationScheme` holds an ordered tuple of labels from configuration. `unknown` is built in and ranks above every configured label. No label names appear in `src`. Provisional labels live in `config/provisional-settings.json` and ADR-0017. |
| G14 numeric safety knobs | Fail closed when unset. Every knob lives in `ciso.app.settings.SafetySettings` with `None` defaults. `config/provisional-settings.json` holds provisional values and is loaded only when named explicitly. Tests set the values they need. ADR-0019. |
| G28 console | API only in this build. No UI framework is chosen. The OpenAPI document is the interface description. |
| G32 schema management | One shared `operational_metadata`; each module registers its own tables in its own `tables.py`; no foreign keys across modules (use `EntityRef` strings); `init_operational_schema` creates tables and a `schema_version(module, version)` row per module. A migration tool is not chosen (ADR-0002). |
| G33 self-approval | Forbidden by default. `SafetySettings.allow_self_approval` defaults to `False`. ADR-0016 puts the choice to the owner, because a one-person company cannot run human-initiated L4 actions under this default. |

## Deviations from the plan's file layout (already built in M0)

- Hashing helpers are in `src/ciso/common/schemas.py` (`canonical_json`, `content_hash`,
  `sha256_hex`), not a separate `hashing.py`.
- `Principal` is in `src/ciso/common/principal.py`.
- Shared types for cross-module calls are in `src/ciso/common/protocols.py`
  (`AuditEvent`, `AuditReceipt`, `AuditSink`, `KillSwitchReader`, `SecretResolver`,
  `Redactor`). `PolicyContext` and `PreconditionChecker` belong to `ciso.policy` and
  `ciso.execution`, which define them.
- Tests use `--import-mode=importlib` with the repo root on `pythonpath`, so helpers are
  imported as `from tests.fakes.core import ...`. Test directories have no `__init__.py`.
- The architecture rules are in one file, `tests/architecture/test_import_boundaries.py`,
  plus `tests/architecture/test_required_test_classes.py`.

## ADR numbering

The plan cites the planner's own ADR numbers. The authoritative list is
`docs/adr/README.md`:

| Topic | ADR |
|---|---|
| Language | 0001 |
| Operational and audit storage, migrations | 0002 |
| Evidence storage | 0003 |
| Identity | 0004 |
| Local inference runtime | 0005 |
| External inference | 0006 |
| Queue and workflow | 0007 |
| Secrets | 0008 |
| Policy engine and rule format | 0009 |
| Execution boundary, process decomposition | 0010 |
| Connector framework | 0011 |
| API and console | 0012 |
| Audit integrity | 0013 |
| Backup and recovery | 0014 |
| Deployment, host, network | 0015 |
| Separation of duties (self-approval) | 0016 |
| Provisional classification labels | 0017 |
| Kill-switch semantics | 0018 |
| Provisional safety parameters | 0019 |
| Observability | 0020 |

## Execution model

- One checkout, several builder agents per milestone, each owning the files named in its
  task rows and nothing else. `src/ciso/common/`, `pyproject.toml`, `uv.lock`,
  `tests/conftest.py`, `tests/fakes/core.py`, `tests/architecture/` and
  `src/ciso/app/`, `src/ciso/api/app.py` belong to the coordinator.
- Builders run only their own tests. The coordinator runs the whole gate once per
  milestone: in the working tree, then again on a fresh local clone with
  `uv sync --locked`.
- A local checkpoint commit is made on `build/baseline-platform` when a milestone gate
  passes. Nothing is pushed; the repository has no remote.
- Each milestone gate includes a mutation step: remove one guard by hand, watch the
  suite fail, restore it.

## Not achievable in a local build (stated, not ticked)

- Appendix D "office-hosted deployment runs with private service boundaries": needs the
  host (OD-01) and process separation (ADR-0010).
- Phase 0 exit gate: needs people. The instruments are in `docs/phase0/`.
- Phase 6: benchmarks, compliance mapping and procurement need evidence that does not
  exist yet.
