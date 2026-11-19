# CISO Agent for Claude

**A security-governance layer for AI coding agents, delivered as a single Claude Code plugin.**

Your engineers' AI agents run shell commands, edit files, call connectors and push code.
This plugin puts a CISO in that loop: before the agent acts, a hook on the engineer's
machine identifies who is acting, inspects what is about to happen, and lets **fixed,
tested rules** decide whether it may proceed. Alongside it, a **CISO skill** reviews code,
audits agent setups and answers security questions on demand.

No servers. No model in the decision path. Installed and locked by your organization's
managed settings.

> **Status:** built and tested; not deployed anywhere. Real runs were measured on Windows 11
> with Claude Code 2.1.316. Start with the [handover](docs/HANDOVER-CISO-AGENT.md) before
> installing.

---

## Contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [How a decision is made](#how-a-decision-is-made)
- [How a push is checked](#how-a-push-is-checked)
- [The rules](#the-rules)
- [The CISO skill](#the-ciso-skill)
- [What it has been tested against](#what-it-has-been-tested-against)
- [Installing it in your organization](#installing-it-in-your-organization)
- [Limits](#limits)
- [Repository map](#repository-map)
- [Development](#development)
- [The optional server add-on](#the-optional-server-add-on)

---

## What it does

| Your question | How the plugin answers it |
|---|---|
| **Who** is using AI? | The person is the logged-in OS account on a managed device, with a role from managed settings. The agent is classed as employee-operated or organizational. |
| **What** is the agent doing? | Every tool call (shell, file write and edit, file read, connector, sub-agent) and every prompt passes through a hook before it runs. |
| **Is it allowed?** | A deterministic rules engine answers **allow**, **ask the person**, or **deny**, with a reason the engineer can read. |
| **Is the code safe to ship?** | File writes, prompts, commits and pushes are inspected for secrets, sensitive files, risky code and tricks that silence security scanners. Pushes are scanned commit by commit before they leave the machine. |
| **What happened?** | Each machine keeps a hash-chained log of decisions and findings that holds no prompts, commands or file content. |
| **How do we stop everything?** | A company-wide stop flag in managed settings blocks every non-read action at once. |

---

## Architecture

```mermaid
flowchart TB
    subgraph ORG["Your organization"]
        MKT["Company plugin marketplace<br/>(a private git repository)"]
        MDM["Managed settings<br/>Group Policy · MDM profile · system file"]
    end

    subgraph DEV["Engineer's machine"]
        CC["Claude Code<br/>AI coding agent"]
        subgraph PLUGIN["ciso-agent plugin"]
            HOOK["Enforcing hooks<br/>PreToolUse · UserPromptSubmit"]
            SKILL["CISO skill<br/>/ciso-agent:ciso"]
            subgraph ENGINE["Bundled engine (no network)"]
                INTAKE["Intake<br/>normalise the action"]
                ID["Local identity<br/>OS account + role"]
                INSPECT["Inspector<br/>47 content rules"]
                GOV["Governance engine<br/>21 command classes<br/>20 rules + invariants"]
            end
            LOG[("Hash-chained logs<br/>decisions · findings")]
        end
        GIT["git, run safely<br/>for push and commit scans"]
    end

    MKT -- "install" --> PLUGIN
    MDM -- "force-enable · lock · stop flag · role" --> CC
    CC -- "every tool call and prompt" --> HOOK
    HOOK --> INTAKE --> ID --> INSPECT --> GOV
    HOOK -. "push / commit" .-> GIT
    GOV -- "allow · ask · deny" --> CC
    GOV --> LOG
    SKILL --> INSPECT
    SKILL --> LOG
```

**Three properties hold everywhere:**

1. **The model is never the root of trust.** Language models can be manipulated by what
   they read. Allow and deny come only from deterministic code and a versioned ruleset;
   the skill may explain a decision but cannot make one.
2. **Fail closed.** Each hook is declared `onFailure: "block"`. A crash, a timeout, a
   missing runtime, an unreadable account or an unwritable log stops the action; it never
   lets it through.
3. **Locked by the organization.** Managed settings install the plugin, force-enable it,
   restrict which marketplaces and hooks may run, and harden git, so a user cannot simply
   switch the controls off from their own settings.

---

## How a decision is made

```mermaid
sequenceDiagram
    autonumber
    participant A as AI agent (Claude Code)
    participant H as Plugin hook
    participant E as Bundled engine
    participant L as Local logs

    A->>H: About to run a tool or send a prompt (hook JSON)
    H->>H: Runtime guard: isolated interpreter, plugin-owned packages only
    H->>E: Normalise the action (kind, tool, target, command, content)
    E->>E: Identify the person (OS account, role) and the agent class
    E->>E: Inspect content: secrets, sensitive paths, risky code, suppression tricks
    E->>E: Classify the command (both POSIX and PowerShell/cmd readings)
    E->>E: Built-in invariants first, then the ruleset (strictest effect wins)
    E->>L: Append decision and findings (hash-chained, redacted)
    alt allow
        H-->>A: (no output) Claude Code's own permission rules still apply
    else ask
        H-->>A: The person must confirm, with the reason
    else deny
        H-->>A: Blocked: what was found, what to do, (CISO decision dec_...)
    end
    Note over H,A: Any failure on this path exits 2 and the action is blocked
```

**Built-in invariants**, applied before any rule and impossible to relax from the ruleset:

- the stop flag is on, or cannot be read → deny every non-read action;
- the identity is disputed (two different people claimed in one session) → deny every
  non-read action;
- the action changes the agent's own configuration or tampers with security tools → deny;
- inspection finds a critical problem → deny;
- an inspection a matching rule requires could not complete → deny;
- the command cannot be parsed with confidence → never allow, at most ask.

An identity that cannot be established at all is handled by the ruleset: every write,
shell command and push by an unknown person is denied.

**How commands are read.** Shell commands are read twice, once as a POSIX shell and once as
PowerShell/cmd, and the dangerous classes found by either reading are kept. A command
counts as a harmless read only when every program and every option is on an explicit
allowlist and no argument could expand into something else (substitutions, globs,
variables, non-ASCII look-alike characters). Everything else is at least "ask".

---

## How a push is checked

There is no server and no sandbox in this mode, so the hook scans the push itself:

```mermaid
flowchart TD
    P["Agent runs: git push origin feature"] --> S{"One plain push of a<br/>named branch to a<br/>configured remote?"}
    S -- "no: bare push, all branches,<br/>mirror, several refspecs, chains" --> D1["Deny: push one named branch"]
    S -- "yes" --> R{"Force push or<br/>protected branch?"}
    R -- "yes" --> RULE["Rules decide first<br/>(force to main: deny,<br/>to a protected branch: ask)"]
    R -- "no" --> C{"Repository safe to scan?<br/>plain layout, single URL,<br/>no redirecting git settings,<br/>no repository hook programs"}
    C -- "no" --> D2["Deny with a reason code"]
    C -- "yes" --> B["Scan base: the remote's real tip,<br/>confirmed by the local tracking ref;<br/>otherwise from the root (max 1000 commits)"]
    B --> I["Inspect every commit separately<br/>(a secret added then deleted is still found)"]
    I --> F{"High or critical finding,<br/>binary change, or<br/>incomplete scan?"}
    F -- "yes" --> D3["Deny: file, line and rule named,<br/>secret never shown"]
    F -- "no" --> A["Allow (verified person,<br/>non-protected branch)"]
```

git is run with a fixed argument list and no shell, with every `GIT_*` variable dropped,
repository hooks, fsmonitor, external diff and text conversion off, and no network
except the single `ls-remote` the push would contact anyway. A `git commit -m` is scanned
the same way. **The project's tests are not run** in this mode.

---

## The rules

The ruleset is readable JSON: [`src/ciso/governance/rulesets/default.json`](src/ciso/governance/rulesets/default.json)
(version `governance-default-2026.11.19-3`, provisional). It has 20 rules; the strictest
matching effect wins.

| Effect | What it covers |
|---|---|
| **allow** | reads and prompts by a verified person; read-only shell commands; a fully scanned, clean push by a verified person to a non-protected branch |
| **ask** | pushes to a protected branch (`main`, `master`, `release/*`, `prod*`) or an unknown branch; force pushes to feature branches; network transfers; package installs; bulk copies and archive extraction into the project or home; destructive deletes; anything no rule covers |
| **deny** | force pushes and history rewrites on protected branches; credential access, running downloaded code, privilege escalation, obfuscation and environment hijacking by employee-operated or unknown agents; writes by an unknown person; suspended agents; secrets in written content, commits or pushes; any high-severity finding in a scanned push or commit |

The engine sorts commands into 21 classes, including `git_force_push`,
`git_push_protected_ref`, `credential_access`, `remote_script_execution`,
`privilege_escalation`, `agent_config_change`, `security_tool_tamper`, `obfuscation`,
`environment_hijack`, `bulk_write` and `unparseable`.

The inspector has 47 content rules: 8 for secrets, 10 for sensitive paths (including the
agent's own configuration, CI pipelines, git hooks, SSH and cloud credentials, editor
auto-run files), 12 for risky code, 3 for scanner-suppression tricks, and 12 coverage
rules that mark content it could not fully inspect.

**Changing a rule:** edit `default.json`, run `uv run python config/derive_governance_ruleset.py`,
then `uv run python tools/build_ciso_plugin.py`, then the tests. Skipping the derive step
changes nothing the plugin enforces.

---

## The CISO skill

Invoke it in Claude Code with `/ciso-agent:ciso`. It runs one read-only tool and never
claims to approve or unblock anything.

| Ask it to | It does |
|---|---|
| Review a repository, a staged change or a branch range | Runs the inspector over every file or commit and writes a findings report with severity, `file:line`, rule and remediation |
| Check a planned command or file write | Runs the same engine the hooks use and explains the verdict and what to do instead |
| Audit the agent setup | Flags risky connector servers, instruction files, permission settings and hooks in the repository and, on request, the user's own configuration |
| Summarise | Counts decisions and findings from the local logs and reports what the hash chain can and cannot show |
| AI-use questions | What data may go to which AI tool, what to do after a refusal, how to request an exception |

A Claude apps edition (chat, Cowork) carries the instructions only, because that
environment cannot run the checks.

---

## What it has been tested against

**Real runs** with Claude Code 2.1.316 on Windows 11 (model haiku, plugin loaded with
`--plugin-dir`, the Windows template's environment), on the final plugin:

| What the agent tried | Result |
|---|---|
| Read a file | ✅ allowed |
| Force push to `main` | ⛔ denied, remote unchanged |
| Point git at a clean copy of the repository, then push a branch with a secret | ⛔ denied, remote unchanged |
| Write its own connector configuration (`.mcp.json`) | ⛔ denied, file not created |
| Write a file containing a (fake) cloud key | ⛔ denied, file not created |
| Push a branch whose commit contains that key | ⛔ denied, branch never reached the remote |
| Push a clean feature branch | ✅ allowed, remote updated |
| Write a file with the stop flag on | ⛔ denied |
| Review the repository with the skill | Report with the high finding; the key in no log or report |

**Automated:** 5,563 tests pass on a fresh clone, with mypy (strict) and ruff clean. Each
build step ran a mutation pass (a guard switched off on a scratch copy must make a named
test fail), and four of those were repeated by hand on the final code.

**Adversarial reviews:** independent reviewers attacked the rules engine, the inspector,
the identity model and the plugin, acting as a hostile agent. Their reports and every fix
are in [`docs/reviews/`](docs/reviews/) (`skill-core-adversarial.md`,
`ciso-plugin-adversarial.md`).

---

## Installing it in your organization

Full steps: [plugin README](integrations/claude_code/ciso-plugin/README.md) and the
[handover](docs/HANDOVER-CISO-AGENT.md). In short:

1. Publish the contents of `integrations/claude_code/` as its own private git repository
   (it must be the repository root). That is your plugin marketplace.
2. Fill in `integrations/claude_code/managed-plugin/source.json` (marketplace URL,
   organization ID, admin-owned paths), rebuild, and run the checker with both folders
   until it prints `RESULT: READY`.
3. On each machine install `uv` and git, and create the empty admin-owned git-hooks folder.
4. Deploy the managed settings per platform (Windows registry or Group Policy, macOS
   profile, Linux system file). If you also use managed settings in the Claude admin
   console, mirror the keys there or set `managedSourcesBehavior` to `merge`.
5. Verify on one machine, in a throwaway repository: `/plugin` lists `ciso-agent`, and a
   write to `.mcp.json` is refused with a "CISO decision" id.

**Machine requirements:** Claude Code 2.1.316+, `uv` (fetches Python 3.13 and five pinned
packages on first use, or use a pre-filled cache offline), git 2.31+.

---

## Limits

Stated plainly, because a security control is only as good as what you know about it:

- **It runs in the user's own space.** A determined engineer or a local administrator can
  edit the plugin, its rules or its logs on their own machine. The rules stop the *agent*
  from doing so; they do not stop *people*. The logs show an edited line, not a log cut
  short or rewritten.
- **Identity is the computer's login.** There is no central identity check and no central
  record: each machine keeps its own log.
- **Tests are not run before a push**; that needs the server add-on.
- **Coverage is Claude Code on managed machines.** Other vendors' assistants, personal
  accounts, unmanaged machines and cloud sessions are outside it.
- **Commands are judged by their text,** before they run.
- **Package versions are pinned, but file hashes are not enforced** by `uv run`; an
  IT-installed runtime is the hardening step.
- **Refused as not inspectable:** binary changes, writes over 256 KiB, diffs over 1 MB,
  commit forms other than `git commit -m`, linked worktrees and submodule checkouts.
- **The rules are provisional** and ask for most writes; tune them for your team.
- **Each checked action adds roughly half a second to a second.**
- **Real runs were on Windows only;** the marketplace install path and the macOS and Linux
  templates were built and checked but not run.

---

## Repository map

| Path | What it is |
|---|---|
| [`integrations/claude_code/ciso-plugin/`](integrations/claude_code/ciso-plugin/) | **The plugin**: hooks, skill, bundled engine and rules |
| [`integrations/claude_code/managed-plugin/`](integrations/claude_code/managed-plugin/) | Managed-settings templates (Windows, macOS, Linux) and their checker |
| `integrations/claude_code/.claude-plugin/marketplace.json` | The marketplace file |
| [`src/ciso/governance/`](src/ciso/governance/) | Command classifier, ruleset loader and decision engine |
| [`src/ciso/inspection/`](src/ciso/inspection/) | Content inspector: secrets, sensitive paths, risky code, diffs |
| [`src/ciso/intake/`](src/ciso/intake/) | Normalises hook payloads into one action record |
| [`src/ciso/common/`](src/ciso/common/) | Shared contracts and path normalisation |
| [`tools/build_ciso_plugin.py`](tools/build_ciso_plugin.py) | Bundles the engine into the plugin byte for byte; `--check` fails on drift |
| [`config/`](config/) | Deployment ruleset and provisional settings |
| [`docs/HANDOVER-CISO-AGENT.md`](docs/HANDOVER-CISO-AGENT.md) | Handover for the organization installing it |
| [`docs/reviews/`](docs/reviews/) | Independent security reviews |
| [`docs/skill/`](docs/skill/) | Specification, wire contract and the findings queue |
| `tests/` | The test suite, including adversarial, privacy and architecture tests |

---

## Development

From the repository root, in Git Bash or any POSIX shell:

```bash
uv sync --locked
```

```bash
uv run pytest
```

```bash
uv run mypy
```

```bash
uv run ruff check src tests integrations tools config
```

```bash
uv run python tools/build_ciso_plugin.py --check
```

Architecture tests enforce the trust boundaries: the rules engine may not import model or
orchestration code; nothing in `src` may start a process, and nothing may open a network
connection except the server add-on's single sandbox-client module; and the plugin's
bundled engine must match its source byte for byte.

---

## The optional server add-on

The repository also contains a central version, built before the plugin and kept as an
add-on: a governance service (`src/ciso/app`, `src/ciso/api`), a sandbox that runs the
project's tests and scanners in locked-down containers before a push (`services/sandbox/`),
and its own install pack. It adds a central record and alerts, tests before every push,
and the Claude Enterprise central gate for chats and cloud sessions.

**It is not finished**: the fixes for its last security review are half done on the branch
`wip/service-review-fixes`, and the sandbox has never run in a real container. Do not
deploy it as it stands.
