# Claude Code integration: managed policy pack (C1) and governance plugin (C2)

This folder connects engineers' Claude Code sessions to the company AI-governance service
(C3). Nothing in `src/` imports it. Vendor names, network code (standard-library
`urllib` only) and process information are allowed here and nowhere else (spec section 7).

The wire contract is `docs/skill/decision-api.md`. The product is `docs/skill/spec-draft.md`.

## What each piece does

| Path | Piece | What it does |
|---|---|---|
| `.claude-plugin/marketplace.json` | Company marketplace `corp-ai-governance` | Lists the plugin. Push this folder (or a copy of it) to the company git host; the managed pack registers it on every machine. |
| `plugin/.claude-plugin/plugin.json` | Plugin manifest, `ai-governance` | Names the plugin. Its full id is `ai-governance@corp-ai-governance`. |
| managed settings, `hooks` key | Hooks (enforcement) | Generated into every platform's managed settings from `pack_source.json` (`hook_timeouts`, `platform_hook`). **Decide** (sent to the service before the action, blocks on any failure): `PreToolUse` (matcher `*`, every tool), `UserPromptSubmit`, `SessionStart`. Each decide hook has an explicit `timeout` (15 s) and `"onFailure": "block"`. **Report** (sent afterwards, never blocks): `PostToolUse`, `SubagentStart`, `SubagentStop`, `Stop`, `SessionEnd`. Every hook runs an admin-installed interpreter in isolated mode (`-I`: no `PYTHONPATH`, `PYTHONSTARTUP`, user site directory or script-directory imports, so a user's environment cannot replace the client's code) on the admin-owned client copy (paths below), never a file in the user's data folder. The client itself sends nothing unless it runs isolated: decide mode blocks, report mode drops the record. `allowManagedHooksOnly` stays on, so user, project and plugin hooks cannot add to or replace them. |
| `plugin/hooks/hooks.json` | No hooks | Declares an empty `hooks` object. The checker refuses a plugin that declares any hook. |
| `plugin/skills/ai-governance/SKILL.md` | Advisory skill | Tells the agent the company's AI-use rules, that its actions are checked, how to read a refusal (the decision id) and what to do instead (ask the person, open a ticket). It advises only; the hooks enforce. |
| `client/hook_client.py` | Hook client | IT installs this file, unchanged, at the admin-owned path of `platform_hook.client`: `C:\Program Files\AIGovernance\hook_client.py` (Windows), `/Library/Application Support/AIGovernance/hook_client.py` (macOS), `/usr/local/lib/ai-governance/hook_client.py` (Linux). The vendor documents no location for hook scripts; these sit next to the token directory (macOS) or in the platform's admin-only program location. Single file, standard library only, targets **Python 3.10+**. Reads the hook JSON on stdin and adds the claims: `os_account` (`DOMAIN\user` on Windows from the environment, the account name elsewhere), the device (host name) and the surface. Posts to the service and maps the answer to the documented hook output. |
| `plugin/scripts/hook_client.py` | Obsolete copy | No hook references it any more. It is still byte-identical to `client/hook_client.py` (a test enforces this) until the owner approves deleting it. |
| `managed/pack_source.json` | Policy pack source | The one file IT edits. Values containing `REPLACE_ME` are placeholders. |
| `managed/build_pack.py` | Builder | Writes the per-platform artifacts below from the source. Its output is deterministic, and a test checks that the committed artifacts match the source. |
| `managed/check_pack.py` | Checker | Exit 0 means READY. Exit 1 means NOT READY: placeholders remain. Exit 2 means INVALID: a control is missing or weakened, the artifacts disagree, a managed decide hook lacks a timeout or `onFailure: "block"`, a hook runs a relative or user-writable interpreter or client path, or the plugin declares hooks. |
| `managed/{linux,macos,windows}/managed-settings.json` | File-based managed settings | Install as `/etc/claude-code/managed-settings.json`, `/Library/Application Support/ClaudeCode/managed-settings.json` or `C:\Program Files\ClaudeCode\managed-settings.json`. |
| `managed/windows/ClaudeCode-policy.reg` | Windows HKLM policy | REG_SZ value `Settings` under `HKLM\SOFTWARE\Policies\ClaudeCode`, holding the whole JSON. |
| `managed/windows/admx/` | Group Policy template | ADMX/ADML that writes the same `Settings` value. Written here; it was not tested in a Group Policy editor. |
| `managed/macos/com.anthropic.claudecode.mobileconfig` | macOS configuration profile | One payload for the `com.anthropic.claudecode` preference domain, with the same top-level keys. |

### Client behaviour

- Configuration comes only from environment variables that the managed `env` block sets. A managed value overrides the user's shell:
  - `AIGOV_SERVICE_URL`
  - `AIGOV_DEVICE_TOKEN_FILE`
  - `AIGOV_DECIDE_TIMEOUT_SECONDS`
  - `AIGOV_REPORT_TIMEOUT_SECONDS`
  - `AIGOV_CA_BUNDLE`, optional
  - `AIGOV_SURFACE`, optional
  - `AIGOV_LOG_FILE`, optional
  - `AIGOV_GIT_PATH`: absolute path of the admin-installed git, used for the pre-push upload
  - `AIGOV_HOOK_DEADLINE_SECONDS`: the client's whole time budget (the pack sets 14, below the 15-second decide hook timeout)
- The timeouts have no defaults. If one is unset, decide mode blocks and report mode drops the record.
- The device token is read from a file, never from the environment, because the environment reaches every command the agent runs. It is never printed or logged.
- TLS certificates are verified by default. A CA bundle can be configured. Plain `http` is refused to anything but `localhost` or `127.0.0.1`. Redirects are refused, because a redirect could carry the bearer token elsewhere.
- Requests over 256 KiB are blocked in decide mode and dropped with a log line in report mode.
- Decide mode, mapping of the service's verdict:
  - `PreToolUse`: `deny` and `ask` become `hookSpecificOutput.permissionDecision`, with the service's message plus `(AI-governance decision <id>)` as `permissionDecisionReason`.
  - `UserPromptSubmit`: `deny` and `ask` become `decision: "block"` with `suppressOriginalPrompt`. A prompt cannot be held for a person, so `ask` blocks.
  - `SessionStart`: a refusal becomes `continue: false` (see the limits below).
  - `allow` prints nothing, so the normal permission flow and the managed deny rules still apply.
- Decide mode, failures: any failure exits with code 2 and a fixed message on stderr. That covers:
  - no configuration or no token
  - connection refused, a TLS error or a timeout
  - a status other than 200
  - malformed JSON, an unknown verdict or a bad decision id
  - an oversized request or answer
- Pre-push upload (`docs/skill/decision-api.md`, "Pre-push change upload"): when a `PreToolUse` deny carries `needs_change`, the client builds the change with git in the hook's `cwd` and uploads it to `POST /v1/changes`, then asks `decide` again with `change_id` and `change_head` and applies that second answer.
  - git is the `AIGOV_GIT_PATH` executable (absolute; a bare `git` could be found in the agent's working directory), run from a fixed argv list without a shell, stdin closed, a per-step timeout, no `GIT_*` variables, and options that stop the repository's own configuration from running programs (`core.fsmonitor=false`, empty `diff.external`, `--no-ext-diff --no-textconv`, an empty hooks path, `protocol.allow=never`).
  - Push: the commits from the merge base with `<remote>/<branch>` (else the remote's `HEAD`, `main` or `master`) to the pushed branch (`source`, or HEAD for `HEAD:<branch>`); the diff (at most 4 MiB) and a complete bundle whose HEAD is the pushed commit (at most 32 MiB), built in a scratch bare repository that borrows the objects. Commit: `git diff --cached` and the staged tree id.
  - Only a push that names its remote and one branch is built. A bare `git push`, `--all`, `--mirror`, tags, deletes or refspec lists are refused by the service with a message to push one named branch at a time.
  - Every failure (git, size, upload, a bad answer) and running out of `AIGOV_HOOK_DEADLINE_SECONDS` blocks with a fixed message.
- Report mode posts to `/v1/activity` and expects 202. It retries once, then writes a local log line (time, mode, event, outcome code; no content) and exits 0.

## Deployment

The developer's machine needs Claude Code **2.1.316 or later** (the pack sets `requiredMinimumVersion`; `onFailure` needs 2.1.295+), the interpreter named in `platform_hook.command` (Python 3.10+, installed by IT: on Windows the pack expects `C:\Program Files\AIGovernance\python\python.exe`, for example the embeddable distribution; on macOS `/Library/Application Support/AIGovernance/python/bin/python3`; on Linux `/usr/bin/python3`), and read access to the company marketplace repository (for the advisory skill).

1. **Push the marketplace.** Put this folder in a company git repository and fill in `pack_source.json`:
   - `REPLACE_ME_MARKETPLACE_GIT_URL`: that repository's https clone URL.
   - `REPLACE_ME_ORG_UUID`: the Claude Enterprise organization UUID.
   - `REPLACE_ME_SERVICE_HOST`: the governance service host.
2. **Build and check.** From this folder, run `python3 managed/build_pack.py`, then `python3 managed/check_pack.py managed`. Deploy only on `RESULT: READY`.
3. **Install the client** (`client/hook_client.py`) and the interpreter at the `platform_hook` paths, owned by administrators and not writable by users.
4. **Issue a device token per machine** (see below) and write it to the token file:
   - Windows: `C:\ProgramData\AIGovernance\device-token`
   - macOS: `/Library/Application Support/AIGovernance/device-token`
   - Linux: `/etc/ai-governance/device-token`

   Set the file ACL to: administrators write, the machine's users read. Users must be able to read it, because the hook runs as the user.
5. **Deliver the policy:**
   - **Windows, domain-joined:** use a Group Policy Object, Computer Configuration.
     - Option a: import `windows/admx` into the central store and enable "Claude Code managed settings (JSON)" with the one-line JSON from `windows/managed-settings.json`.
     - Option b (simpler for long JSON): a Group Policy Preferences registry item that writes REG_SZ `Settings` under `HKLM\SOFTWARE\Policies\ClaudeCode`, with the value from `ClaudeCode-policy.reg`.
     - Without GPO, copy `windows/managed-settings.json` to `C:\Program Files\ClaudeCode\`.
     - The vendor publishes Group Policy and Intune starter templates at https://github.com/anthropics/claude-code/tree/main/examples/mdm. They were not fetched for this build; compare them before rollout.
   - **macOS:** upload `macos/com.anthropic.claudecode.mobileconfig` to the MDM (Jamf, Intune or similar) as a system-scope profile. Without MDM, install `macos/managed-settings.json` as `/Library/Application Support/ClaudeCode/managed-settings.json` (root-owned).
   - **Linux:** install `linux/managed-settings.json` as `/etc/claude-code/managed-settings.json` (root-owned, 0644) with the configuration tool you already use.
6. **If the organization also uses server-managed settings** (claude.ai admin console): with the default `managedSourcesBehavior` `"first-wins"`, a server-managed policy that has any key **hides this whole pack**, apart from `env` and the login keys. Either put the same keys in the console, or set `managedSourcesBehavior: "merge"` there. This is an owner decision.
7. **Confirm** on one machine:
   - `/status` shows the managed source.
   - `/plugin` lists `ai-governance@corp-ai-governance`.
   - A command the service denies is refused with a decision id.

### Device tokens

The contract (`docs/skill/decision-api.md`) says the service issues one device token per managed machine. The token belongs to an actor of type `service` named for the device, and is sent as `Authorization: Bearer <token>`. It proves which machine reported, not which person.

The service issues it:

1. A `security_admin` calls `POST /v1/devices` with `{"name": "<host name>"}`. The answer holds `device_id` and the `token`, shown once; the service stores only its hash, and the token expires within the service's `max_token_ttl_seconds`.
2. The token goes straight into the device's token file through the endpoint-management tool.
3. `DELETE /v1/devices/{device_id}` revokes the device and every token it holds. Re-register the machine to rotate.

The decide and activity routes accept only device tokens: a person's token is refused with 403. The service does not yet compare the token's device name with the request's `device` field.

## What this cannot see or stop

From the spec's coverage section (section 5), and from the docs:

- **Not covered at all:**
  - other vendors' assistants
  - personal accounts or unmanaged machines
  - locally run models
  - company agents on API keys that do not run these hooks

  The service must report these as gaps, never as "clean".
- **Commands:** a hook sees the text of a shell command, not what the command does when it runs. That is why the sandbox step (C5) exists.
- **Connectors:** the inside of a connector's own server is not visible.
- **Cloud sessions** in Anthropic-hosted environments do not read this machine's pack. They need server-managed settings or the central gate (C4).
- **Identity:** the `os_account` claim is read from the environment and is never marked verified. The user controls their own environment, so it is a hint for the service, not proof.
- **The device token can be read by the user,** because the hook runs as the user. The user could replay it from another tool. It identifies the machine only.
- **First session after rollout:** the hooks come with the managed settings, so they run from the first session. Only the advisory skill comes with the plugin; if the marketplace cannot be cloned the agent lacks the advice, not the checks. `CLAUDE_CODE_SYNC_PLUGIN_INSTALL=1` makes `-p` runs wait for the install. For seeded images see `CLAUDE_CODE_PLUGIN_SEED_DIR` in the org-plugins docs.
- **Pushes and commits are scanned before they run.** The client uploads the change (see "Client behaviour"); the service inspects the diff at once and the sandbox worker sends the bundle to the sandbox. Until the sandbox report is back the push is held (`checks_pending`: "retry the push in a minute"). The uploaded change is bound to the device and the SESSION: a retry in a new session uploads and scans again. A push inside a longer shell command, or one that does not name its branch, cannot be scanned and is refused.
- **The packaged default ruleset has no rule that allows a scanned push**, and none that denies failed tests: with it, a clean scanned push is asked and a push with failed tests is asked too. The real run below used a deployment ruleset with two added rules (`tests/e2e/prepush_ruleset.py`); adopting them is a governance decision.
- **PowerShell commands** (the assistant's `PowerShell` tool on Windows) are read by a POSIX shell grammar; syntax it cannot read is `unparseable` and is never allowed automatically.
- **Machine administrators** can edit or remove the managed source. MDM redeployment is the documented mitigation.
- **`SessionStart` cannot block.** Measured here: a `continue: false` from `SessionStart` did not stop a `-p` session. The prompt and tool hooks are what stop actions.
- **`SessionEnd` reports can be lost.** Claude Code gives all `SessionEnd` hooks a 1.5-second budget, and plugin timeouts do not raise it. In the local test the `SessionEnd` report was cancelled when the service was down.
- **Large reports are dropped.** A report over 256 KiB (for example a large tool output) is dropped with a local log line. The service sees the gap.
- **`claude -p` exits 0 even when a hook blocked the prompt.** Automation must not read exit 0 as "the work ran".

### Settings left for the owner

Each was considered and left out:

- `allowManagedMcpServersOnly` with `allowedMcpServers`: blocks MCP servers that users add.
- `strictPluginOnlyCustomization`: blocks user skills, agents and MCP servers.
- `disableAutoMode`.
- `sandbox`.
- `availableModels`.
- `cleanupPeriodDays`.
- `syncClaudeAiPlugins: false`.
- `forceRemoteSettingsRefresh`.

Each is a policy choice beyond "keep the controls on". Tool calls made through MCP servers and auto mode still pass through the `PreToolUse` hook.

## End-to-end test against the real service, measured 2026-11-19 (Claude Code 2.1.316, Windows 11, model haiku)

Setup: the governance API (`python -m ciso.api`) on `127.0.0.1:18766` with a scratch data
directory and the provisional settings (deployment ruleset
`config/governance-ruleset.provisional.json`); a test admin from
`python -m ciso.app.admin bootstrap`; an employee actor bound to this machine's
`DOMAIN\user` account; an approved employee-operated agent identified by the host name; a
device registered through `POST /v1/devices`, its token in a file. A throwaway `--settings`
file held the hooks exactly as `managed_hooks` generates them (venv interpreter with `-I`,
the real `client/hook_client.py`) plus the `env` block; `--setting-sources project`,
`--no-session-persistence`. The repository was a throwaway git repo with a local bare
remote.

| Run | Service decision | Result |
|---|---|---|
| 1, `git status --short --branch` | SessionStart, prompt, PreToolUse all `allow` (`rule_allow`, class `read_only_command`); PostToolUse, Stop, SessionEnd recorded | command ran, output returned |
| 2, `git push --force origin main` | `deny` (`rule_deny`, `inspection_incomplete`) | the agent showed "Blocked by company policy ... Pushes and commits by AI agents are held until the pre-push scan ... (AI-governance decision dec_...)"; remote unchanged |
| 3, Write tool on `.mcp.json` (`--allowedTools Bash,Write`) | `deny` (`critical_finding`, `agent_config_change`) | file not created |

Afterwards: four findings (both denials and their inspection findings, attributed to the
person and the agent), three alert files under `data/alerts`, and `GET /v1/audit/verify`
returned `ok`. `Stop` events are recorded as `turn_end`, and the default ruleset answers
them `ask` (no rule covers that kind yet).

## Pre-push run against the real service, measured 2026-11-19 (Claude Code 2.1.316, Windows 11, model haiku)

Setup: the governance API (`python -m ciso.api`) on `127.0.0.1:18767` and the sandbox
worker (`python -m ciso.app.sandbox_worker`) with the provisional settings on a scratch
data directory and the deployment ruleset written by `tests/e2e/prepush_ruleset.py`; a
stdlib stub of the sandbox's `POST /v1/jobs` on `127.0.0.1:18790` answering clean or with
2 failed tests; the REAL `client/hook_client.py` from hooks generated by `managed_hooks`
(venv interpreter, `-I`), `AIGOV_GIT_PATH` set to the machine's git; a throwaway repository
with a local bare remote (`main` pushed by hand; `feature-a` with one clean commit,
`feature-b` with a failing test). Docker was not used.

| Run | What happened | Result |
|---|---|---|
| 1 | The first attempt found a real bug: the scratch repository's `alternates` file was written in text mode, so on Windows git read a path ending in CR and the bundle step failed. The client blocked with the fixed pre-push message (fail closed). Fixed (bytes write) with a regression test. | remote unchanged |
| 2, `git push origin feature-a`, worker not started | upload (`governance.change.submit`), then `deny` `checks_pending` | remote unchanged |
| 3, same push in a NEW session after the report was in | held again: a new session uploads a new change (by design, changes are bound to their session) | remote unchanged |
| 4, push then retry in the same session | attempt 1 `checks_pending`; attempt 2 reused the uploaded change and got `allow` (`rule_allow`, rule `allow-scanned-push-known-people`) | bare remote `refs/heads/feature-a` = local `8528f09` |
| 5, `git push origin feature-b`, stub answers 2 failed tests, retry in the same session | attempt 1 `checks_pending`; attempt 2 `deny` (`rule_deny`, rule `deny-high-findings-in-scanned-push-or-commit`) | bare remote has no `feature-b` |

Every decision above is in the audit log with its reason codes and matched rules. Every
process started for the run was stopped and both ports were free afterwards.

## Local test, measured 2026-11-18 (plugin hooks, before the move to managed hooks) (Claude Code 2.1.316, Windows 11, model haiku)

Setup:

- The repo plugin was loaded with `--plugin-dir`.
- `--settings` gave the `env` block, with `--setting-sources project`, `--allowedTools Bash` and `--no-session-persistence`.
- A stdlib stub service listened on `127.0.0.1:18765`. It denied any command containing `marker_denied` and allowed everything else.

| Run | What happened | Result |
|---|---|---|
| 1, allowed command | The stub received SessionStart, UserPromptSubmit and PreToolUse (decide, all allow), then PostToolUse, Stop and SessionEnd (activity, 202). Every request carried the right token, `device` (the host name), and an `os_account` claim of the form `HOST\user`. | `marker_allowed.txt` created |
| 2, `echo x > marker_denied.txt` | PreToolUse was denied. The agent showed "Stub policy: ... (AI-governance decision dec_stub1)", did not retry, and offered to ask or open a ticket, as the skill says. | `marker_denied.txt` absent |
| 3, stub stopped | SessionStart and UserPromptSubmit failed with URLError. The prompt was blocked with the fixed message, and the session was not stopped at SessionStart. | `marker_offline.txt` absent |
| 4, stub stopped, after adding `suppressOriginalPrompt` to the failure output | Same block. The block message no longer repeated the prompt. | `marker_offline.txt` absent |

## Documentation used (fetched 2026-11-18)

- Hooks reference: https://code.claude.com/docs/en/hooks.md
- Plugins: https://code.claude.com/docs/en/plugins.md
- Plugin manifest reference: https://code.claude.com/docs/en/plugins-reference.md
- Plugin marketplaces: https://code.claude.com/docs/en/plugin-marketplaces.md
- Organization plugin management: https://code.claude.com/docs/en/plugins/org.md
- Managed settings: https://code.claude.com/docs/en/managed-settings.md
- Settings: https://code.claude.com/docs/en/settings.md
- Settings reference: https://code.claude.com/docs/en/settings-reference.md
- Example settings: https://code.claude.com/docs/en/settings-example.md
- Server-managed settings: https://code.claude.com/docs/en/server-managed-settings.md
- Skills: https://code.claude.com/docs/en/skills.md
- Permissions: https://code.claude.com/docs/en/permissions.md
- Managed MCP: https://code.claude.com/docs/en/managed-mcp.md
