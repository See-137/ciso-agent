# CISO agent for your Claude organization: handover

Date: 2026-11-19. Built and tested on one Windows 11 machine with Claude Code 2.1.316.
Nothing is deployed. Everything below is in this repository.

## What you get

One Claude Code plugin, `ciso-agent`, that your organization adds from its own plugin
marketplace and turns on for everyone through managed settings. It runs no server of its
own (it needs package downloads on first use; see "Machine requirements").

It has two halves:

1. **The CISO skill** (`/ciso-agent:ciso`). Anyone can ask it to:
   - review a diff, a branch or a repository folder for secrets, sensitive files, risky
     code and tricks that silence security scanners, and write a findings report with
     severity and how to fix each one;
   - check a command or a planned action against the company rules and explain the verdict;
   - audit a repository's and a machine's agent setup (connector servers, instruction
     files, permission settings, hooks) for risky configuration;
   - summarise the local decision and findings logs;
   - give AI-use guidance: what may go to which AI tool, how to handle a refusal, how to
     ask for an exception.

   The skill advises. It cannot stop anything by itself.

2. **Local enforcement hooks.** Before the agent runs a shell command, writes or edits a
   file, calls a connector, pushes, commits, or sends a prompt, a hook decides on the
   engineer's machine with fixed rules (never a language model): allow, ask the person,
   or deny with a message saying what was found and what to do. Pushes, and commits made
   with `git commit -m`, are scanned locally before they leave the machine. A
   company-wide stop flag in managed settings blocks every non-read action. Each machine
   keeps a hash-chained log of decisions and findings that holds no prompts or file
   content (a secret placed inside a file name would appear as part of that path).

Where it lives:

| Path | What it is |
|---|---|
| `integrations/claude_code/ciso-plugin/` | The plugin. Its `README.md` is the full reference: layout, how decisions are made, push scanning, machine requirements, installation, limits, the vendor documentation it relies on |
| `integrations/claude_code/managed-plugin/` | Managed-settings templates for Windows, macOS and Linux, and `check_managed.py`, which refuses a template that still has placeholders or weakens a control |
| `integrations/claude_code/.claude-plugin/marketplace.json` | The marketplace file. It also lists `ai-governance`, the advisory plugin of the unfinished server add-on: remove that entry unless you deploy the add-on |
| `integrations/claude_code/ciso-plugin/apps-skill/` | The skill alone, for Claude apps (chat, Cowork): instructions only, see the limits |
| `src/ciso/governance/rulesets/default.json` | The rules, as readable JSON |

## Changing the rules

The plugin uses `rules/governance-ruleset.json`, which is built in two steps from the
default rules: the deployment version adds the assistant's own configuration files, and
the plugin build adds its credential files. To change a rule:

1. Edit `src/ciso/governance/rulesets/default.json`.
2. Run, from the repository root: `uv run python config/derive_governance_ruleset.py`
3. Then: `uv run python tools/build_ciso_plugin.py`
4. Run the tests (`uv run pytest`) and redeploy the plugin.

Skipping step 2 changes nothing the plugin enforces, and the build's `--check` does not
catch it.

## What was tested

**On a real machine.** Claude Code 2.1.316 with model haiku, the plugin loaded with
`--plugin-dir`, the Windows template's environment in a settings file and uv offline. The
managed install path (marketplace, force-enable, managed hooks) and uv's first online
download were never run; your first machine in step 5 below is the first real test of
them.

Measured on the final plugin (after its security review fixes):

| What the agent tried | Result |
|---|---|
| Reading a file | Allowed |
| Force push to `main` | Denied; the remote did not move |
| Re-pointing git (`core.worktree`) at a clean copy, then pushing a branch with a secret | Denied; the remote did not move |
| Writing the agent's own connector configuration (`.mcp.json`) | Denied; file not created |
| Writing a file containing a planted (fake) cloud key | Denied; file not created |
| Pushing a branch whose commit contains that key | Denied; the branch never reached the remote |
| Pushing a clean feature branch | Allowed; the remote now holds the local commit |
| Stop flag on, then writing a file | Denied; file not created |
| "Review this whole repository" through the skill | Report with the high finding; the key appears in no report or log |

In an earlier run the model repeated the joined fake key in its own answer. That text
stays in the session transcript, which the plugin does not control.

**Automated.** On a fresh clone of the final commit: 5,563 tests passed, 14 skipped,
2 expected failures; type and lint checks clean; the plugin bundle matches its sources.
Each build step ran a mutation pass (switching a guard off and checking a test fails);
four of those were repeated by hand on the final code.

**Reviews.** Three independent adversarial security reviews covered this product, in
`docs/reviews/`: `skill-core-adversarial.md` (rules engine, inspection, identity) and
`ciso-plugin-adversarial.md` (the plugin) are fixed, apart from the limits below; their
fixes were tested but not re-reviewed by a fresh reviewer. `skill-service-adversarial.md`
covers the optional server add-on and is only partly fixed (see the last section). The
`m1-*` and `m2-*` reports belong to the project's original whole-company design.

## How your organization installs it

The step-by-step is in the plugin README, section "How an organization installs it". In
short:

1. Put the contents of `integrations/claude_code/` in its own company git repository,
   readable by every engineer. That folder must be the repository's root: the templates
   point at the repository without a sub-path.
2. Fill in `integrations/claude_code/managed-plugin/source.json` (marketplace URL,
   organization ID, admin-owned paths), rebuild with `tools/build_ciso_plugin.py`, and
   run `check_managed.py` with BOTH folders until it prints `RESULT: READY`:
   `uv run python integrations/claude_code/managed-plugin/check_managed.py integrations/claude_code/managed-plugin integrations/claude_code/ciso-plugin`
   (with only the first folder it skips the check of the plugin's hook command).
3. On each machine: install `uv` and git, and create the empty admin-owned folder the
   template names for git hooks. git must be at the path the template sets in
   `CISO_GIT_PATH`; otherwise every push is refused.
4. Deliver the managed settings per platform (file, Windows registry or Group Policy,
   macOS profile). If you also set managed settings in the Claude admin console, those
   hide the machine file by default: put the same keys there, or set
   `managedSourcesBehavior` to `merge` there.
5. Check on one machine, in a throwaway repository: `/status` shows the managed source,
   `/plugin` lists `ciso-agent`, and asking the agent to write `.mcp.json` is refused with
   a "CISO decision" id. Do not test with a force push to a real branch: if the hooks are
   not active, the push really happens.
6. Optional, Claude apps: build the skill zip with
   `uv run python tools/build_ciso_plugin.py --zip dist/ciso-skill.zip` and have an Owner
   upload it under Organization settings, Plugins & skills.

## Machine requirements

- Claude Code 2.1.316 or later.
- `uv` on the path. On first use it fetches Python 3.13 and five pinned packages, so it
  needs access to PyPI and to uv's Python download host, or a pre-filled uv cache with
  `UV_OFFLINE=1`.
- git 2.31 or later, at `CISO_GIT_PATH`.

## Limits, stated plainly

- **It runs in the user's own space.** The plugin files, its data folder and uv's cache
  are writable by the user. A determined engineer or a local administrator can edit the
  hook, the rules or the logs on their own machine. The rules deny the agent writing to
  those places, but people are not stopped. The logs reveal an edited line, not a log cut
  short or rewritten from scratch.
- **Package hashes are pinned but not enforced** by `uv run`, so the pins fix versions and
  the package index, not the exact file bytes. A fully locked runtime installed by IT is
  the hardening step.
- **Identity is the computer's login.** There is no central identity check, and no central
  record: each machine keeps its own log.
- **Tests are not run before a push.** Pushes are scanned for secrets, sensitive files,
  risky code and scanner-suppression tricks; running the project's tests needs the server
  add-on.
- **Refused as not inspectable:** binary changes, file writes over 256 KiB, diffs over
  1 MB, and commit forms other than `git commit -m` (`-a`, `--amend`, `-F`): the person
  commits those by hand. Linked worktrees, submodule checkouts and separate-git-dir
  repositories cannot be pushed or committed through the agent either.
- **Coverage:** only Claude Code on machines with the managed settings. Other vendors'
  assistants, personal accounts, unmanaged machines and Claude's cloud sessions are not
  covered. In Claude apps the skill gives advice only, because that environment cannot
  run its checks.
- **Commands are judged by their text**, before they run, not by what they do once running.
  Some git long options are still matched by full name only (`commit --am`, `reset --har`,
  `branch --forc`, `config`); push and rebase options are resolved.
- **Not tested:** whether a user's own `disableAllHooks` setting turns off a force-enabled
  plugin's hooks, and whether the Claude desktop app's launch environment can override the
  stop flag.
- **Rules are provisional.** The default rules ask the person for most writes and deny the
  dangerous classes. In unattended runs an "ask" is a refusal. See "Changing the rules".
- **Each checked action adds about half a second to a second.**
- **Tested on Windows only.** macOS and Linux templates were built and checked, not run;
  the managed templates were not deployed through real Group Policy or MDM.

## The optional server add-on

The repository also contains a central version, built earlier and kept as an add-on:

- `src/ciso/app` and `src/ciso/api` (service), `services/sandbox/` (runs the project's
  tests and scanners in locked-down containers before a push), and
  `integrations/claude_code/{client,plugin,managed}` (its hook and install pack).
- It adds what the plugin cannot do alone: a central record and alerts across the company,
  tests run before every push, and the Claude Enterprise central gate that covers chats and
  cloud sessions.
- **State: not finished.** It passes its tests, but fixes for its last security review are
  half done and parked on the branch `wip/service-review-fixes`, and the sandbox has only
  been run with a stand-in, never in a real container. Do not deploy it as it stands.
