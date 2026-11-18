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
  "claims": [{"kind": "os_account", "subject": "CORP\jdoe", "verified": false}],
  "payload": { "...": "the hook's stdin JSON, unchanged" }
}
```

- `event`: the hook event name from the payload (`PreToolUse`, `UserPromptSubmit`,
  `SessionStart`, `PostToolUse`, `SubagentStart`, `Stop`, `SessionEnd`).
- `claims`: what the client read on the machine. `os_account` is `DOMAIN\user` from the
  operating system. The client never marks a claim verified; the service decides.
- `payload`: passed through unchanged. Verified on 2026-11-18 to carry `session_id`,
  `tool_name`, `tool_input` (`command` for shell), `tool_use_id`, `prompt_id`,
  `permission_mode`, `cwd`, `transcript_path`; the prompt event carries `prompt`.

Response 200 (JSON):

```json
{"verdict": "allow" | "deny" | "ask", "decision_id": "dec_...", "reason": "short code", "message": "safe to show the engineer"}
```

The client maps it to the hook's output: `deny` -> block with `message`; `ask` -> ask the
person; `allow` -> allow. Any other status, a malformed body, or no answer in time: the
client exits with code 2 (block) and prints a short fixed message.

## POST /v1/activity

Reported AFTER something happened (`PostToolUse`, `SessionEnd`, `Stop`, telemetry). Same
request shape and authentication. Response 202 `{"recorded": true, "action_id": "..."}`.
Never blocks; a failure is retried by the client at most once and then dropped with a
local log line (the service sees the gap through the missing record).

## Central gate (Enterprise inference hooks)

The assistant platform calls the service directly; signature and frame format follow the
vendor's documentation (`ciso.intake.central_gate`). The verdict it returns is the same
decision as above.
