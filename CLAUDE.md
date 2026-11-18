# AI and Agent Security Governance

Governance and monitoring layer for a company's AI activity: organizational AI systems and
the agents employees operate. Built for the CISO of a startup that uses Claude Enterprise.
The scope is `docs/skill/spec-draft.md` (2026-11-18). It replaced the original whole-company
blueprint (`docs/reference/blueprint-v1.0.txt`); the core platform built from that
blueprint (audit, policy, approvals, identity, kill switch, vault) is reused.
Local build only: nothing deployed.

## Start here

1. `docs/skill/spec-draft.md`: what is being built, the milestones S0-S7, what is verified.
   `docs/plan/handover.md` is the latest handover; check its claims against the tree.
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
- Code that talks to the assistant environment (hooks, plugin, managed settings, central
  gate client) lives in `integrations/`; code that runs untrusted code lives in
  `services/sandbox/`. Vendor names, network and process code are allowed there only.
  They reach the core through `ciso.api`, never by import.
- An observed agent action is a claim. Who did it is decided by `ciso.agents`; whether it
  is allowed is decided by the fixed rules in `ciso.governance`, never by a model.
- Every enforcing hook sets `onFailure: "block"` (verified 2026-11-18: without it a slow
  or crashing hook lets the action through).
