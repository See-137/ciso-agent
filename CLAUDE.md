# CISO agent for a Claude organization

A Claude Code plugin that acts as an organization's CISO agent: a CISO skill plus local
hooks that decide every agent action with fixed rules before it runs, no servers
(`integrations/claude_code/ciso-plugin/`). It reuses the governance engine in `src/ciso`.
An optional central server and sandbox add-on is in `src/ciso/app`, `src/ciso/api` and
`services/sandbox` and is not finished. Nothing is deployed.

## Start here

1. `docs/plan/handover.md`: where the build stopped and what is open. Check its claims
   against the tree.
2. `docs/HANDOVER-CISO-AGENT.md`: the handover for an organization installing it.
3. `integrations/claude_code/ciso-plugin/README.md`: the plugin's full reference.
4. `docs/skill/spec-draft.md` (scope and rules that do not change),
   `docs/skill/review-queue.md` (findings queue; its status note lists what is open),
   `docs/reviews/`.

## Commands (Git Bash, from the repo root)

- Tests: `uv run pytest` (addopts already include `-q`; a second `-q` hides the summary).
- Plugin bundle: after a rule change run `uv run python config/derive_governance_ruleset.py`
  first; after any change to the bundled engine or rules run
  `uv run python tools/build_ciso_plugin.py`; `--check` must pass before a commit.
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
