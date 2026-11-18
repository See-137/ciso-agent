# Unified CISO Agent

Baseline platform built from `docs/reference/blueprint-v1.0.txt` (the blueprint). Local
build only: no remote, nothing deployed, no live company environment.

## Start here

1. `docs/plan/handover.md`: where the build stopped and what to do next. Read it before
   anything else and check its claims against the tree.
2. `docs/plan/followups.md`: open findings and owner decisions.
3. `docs/plan/decisions.md` (wins over `docs/plan/implementation-plan.md`),
   `docs/architecture/system-design.md`, `docs/adr/`.

## Commands (Git Bash, from the repo root)

- Tests: `uv run pytest` (addopts already include `-q`; a second `-q` hides the summary).
- Types: `uv run mypy`. Lint: `uv run ruff check src tests`.
- Before trusting or committing the tree, search for guards left disabled by an
  interrupted mutation test: `grep -rnE "^\s*(el)?if (False|True)\s*:" src/`.

## Rules specific to this project

- The blueprint forbids silently resolving deferred decisions. A technology or policy
  choice goes in an ADR as "Proposed"; numeric safety parameters have no defaults in code
  (unset means refuse) and provisional values live in `config/provisional-settings.json`.
- The language model is never a root of trust. Policy, approvals, execution, audit and
  the kill switch may not import inference or orchestration code;
  `tests/architecture/` enforces this.
- A `Principal` object is a snapshot: resolve the actor id through `PrincipalResolver`
  before deciding a privilege.
- Never call the audit sink while holding the operational database write lock.
- The secrets interface package is `ciso.vault`. Never create a directory named
  `secrets`: writes there are denied on this machine.
- Builders follow `docs/plan/builder-rules.md`. A guard is not done until switching it
  off turns a named test red.
- No network library in `src`. No vendor, product or person names in `src`.
