# CISO agent for your Claude organization: handover

Date: 2026-11-19. Built and tested on one Windows 11 machine with Claude Code 2.1.316.
Nothing is deployed. Everything below is in this repository.

## What you get

One Claude Code plugin, `ciso-agent`, that your organization adds from its own plugin
marketplace and turns on for everyone through managed settings. It needs no server.

It has two halves:

1. **The CISO skill** (`/ciso-agent:ciso`). Anyone can ask it to:
   - review a diff, a branch, files or a whole repository for secrets, sensitive files,
     risky code and tricks that silence security scanners, and write a findings report
     with severity and how to fix each one;
   - check a command or a planned action against the company rules and explain the verdict;
   - audit a repository's and a machine's agent setup (connector servers, instruction
     files, permission settings, hooks) for risky configuration;
   - summarise the local decision and findings logs;
   - give AI-use guidance: what may go to which AI tool, how to handle a refusal, how to
     ask for an exception.

   The skill advises. It cannot stop anything by itself.

2. **Local enforcement hooks.** Before the agent runs a shell command, writes or edits a
   file, calls a connector, pushes, commits, or sends a prompt, the hook decides on the
   engineer's machine with fixed rules (never a language model): allow, ask the person,
   or deny with a message saying what was found and what to do. Pushes and commits are
   scanned locally before they leave the machine. A company-wide stop flag in managed
   settings blocks every non-read action. Each machine keeps a hash-chained log of
   decisions and findings with no secrets, prompts or file content in it.

Where it lives:

| Path | What it is |
|---|---|
| `integrations/claude_code/ciso-plugin/` | The plugin. Its `README.md` is the full reference: layout, how decisions are made, push scanning, machine requirements, installation, limits, the documentation it relies on |
| `integrations/claude_code/managed-plugin/` | Managed-settings templates for Windows, macOS and Linux, and `check_managed.py`, which refuses a template that still has placeholders or weakens a control |
| `integrations/claude_code/.claude-plugin/marketplace.json` | The marketplace file listing the plugin |
| `integrations/claude_code/ciso-plugin/apps-skill/` | The skill alone, for Claude apps (chat, Cowork): instructions only, see below |
| `src/ciso/governance/rulesets/default.json` | The rules, as readable JSON. The plugin bundles a copy (`rules/governance-ruleset.json`) built by `tools/build_ciso_plugin.py` |

## What was proven, and how

Measured on this machine with the real Claude Code, the real hooks and model haiku:

| What the agent tried | Result |
|---|---|
| `git status`, reading a file | Allowed |
| Force push to `main` | Denied; the remote did not move |
| Writing the agent's own connector configuration (`.mcp.json`) | Denied; file not created |
| Writing a file containing a planted (fake) cloud key | Denied, naming file and line; file not created |
| Pushing a branch whose commits contain that key | Denied; the remote did not move |
| Re-pointing git at a clean copy of the repository, then pushing the secret branch | Denied; the remote did not move |
| Pushing a clean feature branch | Allowed; the remote moved |
| "Review this whole repository" through the skill | Report with the high finding; the key itself appears in no report or log |
| Stop flag on, then writing a file | Denied |

Automated checks: 5,562 tests pass, with type and lint checks clean, in this checkout
(fresh-clone result: see the end of this file). Every guard has a test that fails when the
guard is switched off.

Three independent adversarial security reviews covered this product, in `docs/reviews/`:
`skill-core-adversarial.md` (rules engine, inspection, identity) and
`ciso-plugin-adversarial.md` (the plugin) are fixed, apart from the limits below;
`skill-service-adversarial.md` covers the optional server add-on and is only partly fixed
(see the last section). The `m1-*` and `m2-*` reports in that folder belong to the
original whole-company design.

## How your organization installs it

The step-by-step is in the plugin README, section "How an organization installs it". In
short:

1. Host `integrations/claude_code/` in a company git repository every engineer can read
   (this is the marketplace).
2. Fill in `integrations/claude_code/managed-plugin/source.json` (marketplace URL,
   organization ID, admin-owned paths), rebuild, and run `check_managed.py` until it
   says `RESULT: READY`.
3. On each machine: install `uv` and git, and create the empty admin-owned folder the
   template names for git hooks.
4. Deliver the managed settings per platform (file, Windows registry or Group Policy,
   macOS profile). If you also use server-managed settings in the Claude admin console,
   put the same keys there or set `managedSourcesBehavior` to `merge`, because a
   server-managed policy otherwise hides the machine file.
5. Check on one machine: `/status` shows the managed source, `/plugin` lists
   `ciso-agent`, and a force push is refused with a "CISO decision" id.
6. Optional, Claude apps: an Owner uploads the skill zip (built with
   `tools/build_ciso_plugin.py --zip`) in Organization settings, Plugins & skills.

Machine requirements: Claude Code 2.1.316 or later, `uv` on the path (it provides Python
3.13 and five pinned packages, fetched once), git 2.31 or later.

## Limits, stated plainly

- **It runs in the user's own space.** The plugin files, its data folder and uv's cache
  are writable by the user. A determined engineer, or a local administrator, can edit the
  hook, the rules or the logs on their own machine. The rules deny the agent writing to
  those places, but people are not stopped. The logs reveal an edited line, not a log cut
  short or rewritten from scratch.
- **Package hashes are pinned but not enforced** by `uv run`, so the pins fix versions and
  the package index, not the exact file bytes. A fully locked runtime installed by IT is
  the hardening step.
- **Identity is the computer's login.** There is no central identity check, and no central
  record: each machine keeps its own log.
- **Tests are not run before a push.** Pushes are scanned for secrets, sensitive files,
  risky code and scanner-suppression tricks; running the project's tests needs the sandbox
  add-on below.
- **Coverage:** only Claude Code on machines with the managed settings. Other vendors'
  assistants, personal accounts, unmanaged machines and Claude's cloud sessions are not
  covered. In Claude apps the skill gives advice only, because that environment cannot
  run its checks.
- **Commands are judged by their text**, before they run, not by what they do once running.
- **Rules are provisional.** The default rules ask the person for most writes and deny the
  dangerous classes. In unattended runs an "ask" is a refusal. Tune
  `src/ciso/governance/rulesets/default.json`, then rebuild the plugin.
- **Each checked action adds about half a second to a second.**
- **Tested on Windows only.** macOS and Linux templates were built and checked, not run;
  the managed templates were not deployed through real Group Policy or MDM.
- Linked worktrees, submodule checkouts and separate-git-dir repositories cannot be pushed
  or committed through the agent (the scan refuses them); the person pushes by hand.

## The optional server add-on

The repository also contains a central version, built earlier and kept as an add-on:

- `src/ciso` (service), `services/sandbox/` (runs the project's tests and scanners in
  locked-down containers before a push), and `integrations/claude_code/{client,plugin,managed}`
  (its hook and install pack).
- It adds what the plugin cannot do alone: a central record and alerts across the company,
  tests run before every push, and the Claude Enterprise central gate that covers chats and
  cloud sessions.
- **State: not finished.** It passes its tests, but fixes for its last security review are
  half done and parked on the branch `wip/service-review-fixes`, and the sandbox has only
  been run with a stand-in, never in a real container. Do not deploy it as it stands.
