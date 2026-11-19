# Decision API between the integrations and the governance service

The one wire contract between `integrations/` (hooks on engineers' machines) and the
governance service (`ciso.api`). Both sides code against this file; change it only through
the coordinator.

## POST /v1/governance/decide

Asked BEFORE an action runs (a pre-action hook, or a prompt about to be sent). Must answer
within the hook's own deadline; the hook sets `onFailure: "block"`, so no answer means the
action is stopped.

Authentication: `Authorization: Bearer <device token>`. A device token is issued per
managed machine by the service (an actor of type `service` named for the device). It
proves which machine reported, not which person.

Request body (JSON, at most 256 KiB):

```json
{
  "format": "assistant_hook_v1",
  "event": "PreToolUse",
  "surface": "cli",
  "device": "WS-0142",
  "claims": [{"kind": "os_account", "subject": "CORP\\jdoe", "verified": false}],
  "payload": { "...": "the hook's stdin JSON, unchanged" }
}
```

- `device`: optional (missing or `null` means no device name was read). When present it
  is the machine's host name, `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. The machine itself is
  proven by the device token, not by this field.
- `event`: the hook event name from the payload (`PreToolUse`, `UserPromptSubmit`,
  `SessionStart`, `PostToolUse`, `SubagentStart`, `SubagentStop`, `Stop`, `SessionEnd`).
  `Stop` and `SubagentStop` are recorded as `turn_end`; their final message is not read.
- `claims`: what the client read on the machine. `os_account` is `DOMAIN\user` from the
  operating system. The client never marks a claim verified; the service decides.
- `payload`: passed through unchanged. Verified on 2026-11-18 to carry `session_id`,
  `tool_name`, `tool_input` (`command` for shell), `tool_use_id`, `prompt_id`,
  `permission_mode`, `cwd`, `transcript_path`; the prompt event carries `prompt`.

Response 200 (JSON):

```json
{"verdict": "deny", "decision_id": "dec_01JD3Z6B8Q4W5X7Y9Z0A1B2C3D", "reason": "rule_deny", "message": "safe to show the engineer"}
```

- `needs_change`: present only on the deny described in "Pre-push change upload" below.

- `verdict`: `allow`, `deny` or `ask`.
- `decision_id`: always present, `dec_` plus 26 characters. It is the id the engineer
  quotes; findings and the audit log carry it. A refusal the service makes before any
  rule ran (a malformed request, a step that failed) still gets a fresh decision id.
- `reason`: the first reason code. `message`: fixed text per reason code, never an echo of
  the command or content.
- Only a device token is accepted here (an actor of type `service` registered as a
  device, holding `governance.report`); a person's token is refused with 403.

The client maps it to the hook's output: `deny` -> block with `message`; `ask` -> ask the
person; `allow` -> allow. Any other status, a malformed body, or no answer in time: the
client exits with code 2 (block) and prints a short fixed message.

## Pre-push change upload (push and commit)

A push or commit by an agent is decided on its CHANGE, which a hook report does not carry.

1. **First ask.** `decide` on a push or commit with no change attached answers `deny`
   (`inspection_incomplete`). When that is the ONLY reason and the command is one plain
   git command that names what it sends, the answer also carries
   `"needs_change": {"kind": "push"|"commit", "remote": ..., "branch": ..., "source": ...}`.
   - A push qualifies only when the command itself names exactly one remote, one source
     (HEAD or a local branch) and one destination branch: `git push <remote> <branch>`,
     `git push <remote> refs/heads/<branch>`, `git push <remote> HEAD:<branch>`,
     `git push <remote> <src>:<dst>` (options `-u`, `-q`, `-v` only). `source` is the local
     branch sent; `null` means HEAD. A push with no refspec or a bare `HEAD` (configuration
     such as `push.default`, `remote.<name>.push` or `remote.<name>.mirror` would decide
     what is sent), a refspec list, `--all`, `--tags`, `--mirror`, a delete, a tag, a force
     push, `-C`, a chain or an expansion never qualifies: plain deny, and the message asks
     the engineer to push one named branch at a time.
   - A commit qualifies as `git commit -m <message>` (options `--message=`, `-q`, `-s`,
     `-v` only; no `-a`, `--amend`, pathspecs).
   - The service reads the command itself (`ciso.app.change_shape`); the intake's
     `git_push`/`git_commit` refinement is accepted as the same command.
2. **Build (client, in the hook's `cwd`).** git is the admin-installed executable named
   by `AIGOV_GIT_PATH` (absolute), run from a fixed argv list (no shell), with a per-step
   timeout, no `GIT_*` variables from the environment, and `core.fsmonitor=false`,
   `diff.external=`, `--no-ext-diff --no-textconv`, an empty `core.hooksPath`,
   `protocol.allow=never`. Push: `head` = the commit of `refs/heads/<source>` (or HEAD);
   `base` = merge base with `<remote>/<branch>`, else with the remote's `HEAD`, `main` or
   `master`; `commits` = `git rev-list base..head` (newest first, at most 1000);
   diff = `git diff base head` (at most 4 MiB); bundle = a complete, cloneable bundle whose
   HEAD is `head` (built in a scratch bare repository borrowing the objects; at most
   32 MiB, the sandbox's archive bound). Commit: `head` = `git write-tree` (the staged
   tree), `base` = HEAD's commit or `null`, diff = `git diff --cached`, no bundle.
   Any failure, or the hook's deadline (`AIGOV_HOOK_DEADLINE_SECONDS`) running out: the
   client blocks (exit 2, fixed message).
3. **Upload.** `POST /v1/changes`, device token, JSON:
   `{"session_id", "kind", "remote", "branch", "source", "head", "base", "commits",
   "diff_b64", "bundle_b64"}` (commit: no remote, branch, source, commits or bundle).
   Body cap `((32 MiB + 4 MiB + 2) // 3) * 4 + 128 KiB` (`MAX_CHANGE_BODY_BYTES`).
   201 `{"change_id": "chg_<26>", "created": bool}`; 422 malformed; 503 store not
   configured or a failed step. The service stores diff and bundle as one AES-256-GCM file
   (key from `governance.change_key_ref`, HKDF-derived; unset: 503) for
   `governance.change_retention_seconds`, inspects the diff at once, and (push only)
   queues one sandbox job. An identical upload from the same device and session returns
   the stored change (`created: false`), so a retried push does not start a second scan.
4. **Second ask.** The same decide request plus `"change_id"` and `"change_head"`
   (the `head` uploaded). Answers:
   - `deny`, reason `change_refused`: the id is unknown, expired, from another device or
     session, or does not match the command (kind, remote, branch, source) or the head;
   - `deny`, reason `checks_pending`: the sandbox report is not back; the message tells
     the engineer to retry the push in a minute;
   - otherwise the rules decide on ONE inspection merged from the command text, the diff
     and the sandbox report (`from_sandbox_report` with `governance.required_sandbox_checks`;
     a sandbox run the queue gave up on is never complete). A commit has no sandbox run.
5. **Sandbox worker** (`python -m ciso.app.sandbox_worker --config <file>`): leases the
   job, sends the bundle to `POST /v1/jobs` of the sandbox (`governance.sandbox_url`,
   bearer from `governance.sandbox_token_ref`, `governance.sandbox_timeout_seconds`),
   stores the report; retries through the queue (`safety.queue_*`). Restart-safe through
   the queue's leases. A change's file is deleted once its report is in and its retention
   has ended.

## POST /v1/activity

Reported AFTER something happened (`PostToolUse`, `SubagentStart`, `SubagentStop`,
`Stop`, `SessionEnd`, telemetry). Same request shape and authentication. Response 202
`{"recorded": true, "action_id": "..."}`. A BEFORE event (`PreToolUse`,
`UserPromptSubmit`) posted here is refused with 422: it must be asked through decide.
Never blocks; a failure is retried by the client at most once and then dropped with a
local log line (the service sees the gap through the missing record).

## Central gate (Enterprise inference hooks)

The assistant platform calls the service directly; signature and frame format follow the
vendor's documentation (`ciso.intake.central_gate`). The verdict it returns is the same
decision as above.
