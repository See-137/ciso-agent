# Handover: M1 gate passed, 2026-11-18

Read this first, then check it against the tree. It replaces the 2026-11-17 handover,
which described a stop in the middle of M1.

## State

- M0 and M1 are built, gated and committed on branch `build/baseline-platform`
  (`git log --oneline` shows the commits). No remote exists; nothing was pushed.
- M2 to M6 are not started. The plan is `docs/plan/implementation-plan.md`;
  `docs/plan/decisions.md` wins where they differ.
- Open findings and owner decisions: `docs/plan/followups.md`. Reviews: `docs/reviews/`.

## M1 gate, as measured by the coordinator on 2026-11-18

| Check | Result |
|---|---|
| `uv run pytest` (working tree) | 1349 passed, 1 skipped, 3 xfailed |
| `uv run mypy` | no issues in 97 source files |
| `uv run ruff check src tests`, `ruff format --check` | clean |
| Disabled-guard search in `src/` | none |
| Hand mutations, one guard switched off at a time | 5 of 5 caught and restored: kill-switch outbox MAC, policy `agent_requestable`, API scoped permissions, inference nominal provider, audit rollback behind the witness |
| Fresh clone of commit `0a0188b` with `uv sync --locked` | 1349 passed, 1 skipped, 3 xfailed; mypy and ruff clean; no `data/` directory created |

The skip is the connector write-method check (no `ciso.connectors` yet). The three
expected failures are placeholders for test classes that arrive with later milestones
(`connector`, `adversarial`, `discovery_safety`).

Builders' own mutation runs, not repeated by the coordinator: audit 109 (103 caught, 6
argued equivalent), policy 27, identity 32 (1 equivalent), kill switch 16, queue and
observability 16, inference 10, vault 10, ops 7, composition root and API 20 plus 20 in
the final fix pass.

## What M1 contains

`src/ciso/`: `common` (contracts), `vault` (secret references, redaction, key length),
`audit` (hash chain, two-phase anchor, log id, witness), `killswitch`, `identity`
(bootstrap model, host-local recovery), `policy` (envelope, catalog, rules, engine),
`workflows` (durable queue), `observability`, `inference` (local gateway, stub), `ops`
(backup, restore, start-up, shutdown, integrity gate), `app` (settings, composition root,
host-local admin command), `api` (authenticated control-plane API).

## Known gaps carried out of M1

1. Accepting a restore that is behind the witness is designed, not built. Today such a
   restore is reported and the instance starts with writes blocked, which is safe but has
   no way forward except removing the witness. Design is in the final fix-pass notes in
   `docs/plan/followups.md` ("Later milestones").
2. No module consumes the gated kill-switch reader yet except the API. The M2 execution
   broker must take `container.killswitch_reader`, never the raw switch.
3. Self-approval is forbidden by setting but nothing enforces it until `ciso.approvals`
   exists (M2).
4. `src/ciso/audit/log.py` is 435 lines, over the size guideline.
5. Follow-up rows F13 (restore runbook), F27 (one untested kill-switch branch) and F28
   (data files in a built package) are open.
6. The witness file is read in full on every append; fine at this scale, needs an index
   before production. A size threshold setting was requested and not added.
7. The ADRs describe five items as "in progress" that are now done (witness wiring, scoped
   route permissions, 32-byte keys, logging traceback fix, audit stuck-state recovery),
   and do not yet mention the witness `repairs` field, the `witness_torn_tail` warning,
   the `killswitch.read` permission or the start-up report in readiness.

## Owner decisions

Decided on 2026-11-18 (details in `docs/plan/decisions.md`): commit locally at each
milestone gate; self-approval stays forbidden by default; a private GitHub repository is
wanted but only later: offer it to the owner at the M3 gate, and do not create or push
anything before the owner says go.

Still waiting: where the audit anchor and witness live (both default to the data
directory and are reported as a weakness); whether a console is wanted (the blueprint
lists one as required, the build is API-only); whether administrators minting tokens for
other people is acceptable until an identity provider is chosen.

## Next

M2: `ciso.approvals`, the execution broker and tool registry, the write-adapter contract,
and the external inference gate in `ciso.inference.external`. Builder rules are in
`docs/plan/builder-rules.md`; the four cross-cutting rules in `docs/plan/followups.md`
go in every brief.

## Things a new session must know

- The secrets interface package is `ciso.vault`. Writes under any directory named
  `secrets` and recursive deletes are denied on this machine: do not route around either.
- Builders test guards by switching one off. If a session ends mid-run a real check is
  left disabled on disk: run the disabled-guard search before trusting the tree.
- A formatter hook reorders imports differently from the repo's ruff configuration: run
  `uv run ruff check` after editing.
- Local databases from before 2026-11-18 must be recreated (schemas changed without a
  migration path).
- Do not assume any earlier builder agent can be resumed. Re-brief from the docs.
