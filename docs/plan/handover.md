# Handover for the next session, 2026-11-19

Read this first, then check it against the tree.

## What the product is now

This is a CISO agent for an organization on a Claude plan. On
2026-11-19 the request was for "just a skill we can add to our Claude organization to act
as a CISO agent", and the owner chose option A: one Claude Code plugin (a CISO skill plus
local enforcing hooks), no servers. The deliverable and its handover:

- `docs/HANDOVER-CISO-AGENT.md` (what it is, how an org installs it, limits).
- `integrations/claude_code/ciso-plugin/` (the plugin; its README is the full reference),
  `integrations/claude_code/managed-plugin/` (managed-settings templates and checker),
  `tools/build_ciso_plugin.py` (bundles the engine into the plugin; `--check` fails on
  drift; `--zip PATH` builds the Claude-apps skill zip).

History, in order: the repo started as a whole-company CISO platform (blueprint v1.0,
milestones M0-M6; M0, M1 and parts of M2 built). On 2026-11-18 the owner narrowed the
scope to governing the company's AI activity (`docs/skill/spec-draft.md`); a service,
sandbox and install pack were built for that. On 2026-11-19 the deliverable became the
plugin. The engine the plugin bundles is `src/ciso/{common,governance,inspection,intake,vault}`
plus `ciso.app.change_shape` and `change_decide` (see `lib/BUNDLE.json`).

## State

- Branch `build/baseline-platform`, no remote, nothing pushed. Product state is commit
  `dcb16c9` plus the documentation commits after it. A second branch, `wip/service-review-fixes` (`cbadf11`), holds half-done,
  untested fixes for the server add-on's review; it is not merged.
- Gate on 2026-11-19: the first fresh clone (of 3d5f93e) failed the plugin bundle check on
  Windows line endings; `.gitattributes` was fixed (dcb16c9) and a second fresh clone of
  dcb16c9 passed: 5,563 passed, 14 skipped, 2 xfailed; mypy and ruff clean; `tools/build_ciso_plugin.py --check` and
  `config/derive_governance_ruleset.py --check` current; disabled-guard search empty; four
  hand mutations (plugin `onFailure`, plugin stop flag, engine agent-config deny, the
  credential-path rule) each turned tests red and were restored.
- Real runs on this machine (Claude Code 2.1.316, model haiku, `--plugin-dir`, uv offline)
  are tabled in the plugin README and the handover, including re-runs on the final
  plugin. The managed marketplace install path was never run.
- Docker Desktop is installed here; on 2026-11-19 the owner allowed it and six base images
  were pulled for the sandbox add-on, but the derived images were not built and the
  sandbox was never run in a real container.

## Open, if the owner asks for more

- Plugin limits are listed in the handover: user-space files, hashes not enforced
  by `uv run` (an admin-installed runtime is the hardening step), local identity, no
  tests before a push, Windows-only real runs.
- `docs/skill/review-queue.md` (its status note says which rows are done): Q19 (a `*` pattern segment never meets a globbed path
  segment in `ciso.common.paths`), Q20 (duplicate bulk-write readers), Q21 (a push the
  client cannot upload makes no finding), plus long-option abbreviations still compared by
  full name for git subcommands other than push and rebase (`commit --am`, `reset --har`,
  `branch --forc`, `config`).
- Server add-on: finish `wip/service-review-fixes` against
  `docs/reviews/skill-service-adversarial.md`, then a real sandbox run.
- Pushing to a private GitHub repository is the owner's call; nothing is pushed until the
  owner says go.

## Things a new session must know

- Changing rules: edit `src/ciso/governance/rulesets/default.json`, run
  `config/derive_governance_ruleset.py`, then `tools/build_ciso_plugin.py`. Skipping the
  derive step changes nothing the plugin enforces and `--check` stays green.
- Writes under any directory named `secrets` and recursive deletes are denied on this
  machine; do not route around either.
- This machine's antivirus quarantines files containing complete attack command lines or
  realistic secrets: build such test strings at runtime from fragments.
- Builders' mutation passes run on a scratch copy of the code, never in place.
- `.gitattributes` keeps generated artifacts byte-identical across platforms; regenerate
  them with their scripts, never by hand.
