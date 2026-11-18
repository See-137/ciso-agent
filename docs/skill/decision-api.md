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
