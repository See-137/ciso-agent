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
| `plugin/hooks/hooks.json` | Hooks | **Decide** (sent to the service before the action, blocks on any failure): `PreToolUse` (matcher `*`, every tool), `UserPromptSubmit`, `SessionStart`. Each decide hook has an explicit `timeout` (15 s) and `"onFailure": "block"`. **Report** (sent afterwards, never blocks): `PostToolUse`, `SubagentStart`, `SubagentStop`, `Stop`, `SessionEnd`. |
| `plugin/skills/ai-governance/SKILL.md` | Advisory skill | Tells the agent the company's AI-use rules, that its actions are checked, how to read a refusal (the decision id) and what to do instead (ask the person, open a ticket). It advises only; the hooks enforce. |
| `client/hook_client.py` | Hook client, the source copy | Single file, standard library only, targets **Python 3.10+**. Reads the hook JSON on stdin and adds the claims: `os_account` (`DOMAIN\user` on Windows from the environment, the account name elsewhere), the device (host name) and the surface. Posts to the service and maps the answer to the documented hook output. |
| `plugin/scripts/hook_client.py` | Hook client, the bundled copy | Byte-identical to `client/hook_client.py`; a test enforces this. It exists because a plugin can only run files inside its own root. Edit `client/`, then copy the file. |
| `managed/pack_source.json` | Policy pack source | The one file IT edits. Values containing `REPLACE_ME` are placeholders. |
| `managed/build_pack.py` | Builder | Writes the per-platform artifacts below from the source. Its output is deterministic, and a test checks that the committed artifacts match the source. |
| `managed/check_pack.py` | Checker | Exit 0 means READY. Exit 1 means NOT READY: placeholders remain. Exit 2 means INVALID: a control is missing or weakened, the artifacts disagree, or a plugin decide hook lacks a timeout or `onFailure: "block"`. |
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
- Report mode posts to `/v1/activity` and expects 202. It retries once, then writes a local log line (time, mode, event, outcome code; no content) and exits 0.

## Deployment

The developer's machine needs Claude Code **2.1.316 or later** (the pack sets `requiredMinimumVersion`; `onFailure` needs 2.1.295+), `python3` on the PATH (3.10+), and read access to the company marketplace repository.

1. **Push the marketplace.** Put this folder in a company git repository and fill in `pack_source.json`:
   - `REPLACE_ME_MARKETPLACE_GIT_URL`: that repository's https clone URL.
   - `REPLACE_ME_ORG_UUID`: the Claude Enterprise organization UUID.
   - `REPLACE_ME_SERVICE_HOST`: the governance service host.
2. **Build and check.** From this folder, run `python3 managed/build_pack.py`, then `python3 managed/check_pack.py managed`. Deploy only on `RESULT: READY`.
3. **Issue a device token per machine** (see below) and write it to the token file:
   - Windows: `C:\ProgramData\AIGovernance\device-token`
   - macOS: `/Library/Application Support/AIGovernance/device-token`
   - Linux: `/etc/ai-governance/device-token`

   Set the file ACL to: administrators write, the machine's users read. Users must be able to read it, because the hook runs as the user.
4. **Deliver the policy:**
   - **Windows, domain-joined:** use a Group Policy Object, Computer Configuration.
     - Option a: import `windows/admx` into the central store and enable "Claude Code managed settings (JSON)" with the one-line JSON from `windows/managed-settings.json`.
     - Option b (simpler for long JSON): a Group Policy Preferences registry item that writes REG_SZ `Settings` under `HKLM\SOFTWARE\Policies\ClaudeCode`, with the value from `ClaudeCode-policy.reg`.
     - Without GPO, copy `windows/managed-settings.json` to `C:\Program Files\ClaudeCode\`.
     - The vendor publishes Group Policy and Intune starter templates at https://github.com/anthropics/claude-code/tree/main/examples/mdm. They were not fetched for this build; compare them before rollout.
   - **macOS:** upload `macos/com.anthropic.claudecode.mobileconfig` to the MDM (Jamf, Intune or similar) as a system-scope profile. Without MDM, install `macos/managed-settings.json` as `/Library/Application Support/ClaudeCode/managed-settings.json` (root-owned).
   - **Linux:** install `linux/managed-settings.json` as `/etc/claude-code/managed-settings.json` (root-owned, 0644) with the configuration tool you already use.
5. **If the organization also uses server-managed settings** (claude.ai admin console): with the default `managedSourcesBehavior` `"first-wins"`, a server-managed policy that has any key **hides this whole pack**, apart from `env` and the login keys. Either put the same keys in the console, or set `managedSourcesBehavior: "merge"` there. This is an owner decision.
6. **Confirm** on one machine:
   - `/status` shows the managed source.
   - `/plugin` lists `ai-governance@corp-ai-governance`.
   - A command the service denies is refused with a decision id.

### Device tokens

The contract (`docs/skill/decision-api.md`) says the service issues one device token per managed machine. The token belongs to an actor of type `service` named for the device, and is sent as `Authorization: Bearer <token>`. It proves which machine reported, not which person.

The issuing call belongs to the governance service's API and is being built by another lane. The contract does not name an endpoint, so none is named here. The expected flow:

1. An administrator authenticated to the service requests a token for a named device.
2. The token goes straight into the device's token file through the endpoint-management tool.
3. The token is rotated or revoked in the service.

The service then sees the device name both in the token's actor and in the request's `device` field, and can flag any mismatch.

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
- **First session after rollout:** if the marketplace cannot be cloned (no git access) or the plugin has not installed yet, no plugin hooks run, and the session is not checked. `CLAUDE_CODE_SYNC_PLUGIN_INSTALL=1` makes `-p` runs wait for the install. For seeded images see `CLAUDE_CODE_PLUGIN_SEED_DIR` in the org-plugins docs.
- **Plugin files are user-writable.** The installed plugin's files live in the user's own Claude Code data folder, so a user could edit the cached client. The pack denies the agent's own Edit tool there, but not the user.
  - A stronger option, for owner decision: put the same hooks in the **managed settings `hooks` key**, pointing at an admin-owned copy of the client with an absolute interpreter path. That also removes the dependency on `python3` being found on the user's PATH.
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

## Local test, measured 2026-11-18 (Claude Code 2.1.316, Windows 11, model haiku)

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
