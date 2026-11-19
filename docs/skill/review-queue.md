# Findings queued for the review-and-fix round

Raised after the owning lane finished; to be fixed test first in the fix round, after the
integration lane, so no two builders edit the same files.

| # | Source | File | Finding |
|---|---|---|---|
| Q1 | Automated security review, 2026-11-19 | `src/ciso/governance/analysis.py` | HIGH. Bash evaluates some arguments arithmetically and runs any command substitution inside them: operands of `[[`, `test`/`[` (e.g. `-eq`), `-v` targets of `test`/`printf`/`read`/`declare`, `let` arguments, `((...))` bodies, and `$((name))` where `name` holds an expression. An argument of those programs containing `$(`, a backtick, `<(` or `>(` must add `unparseable` (never allowed) and clear read-only; an arithmetic expansion whose body is a bare variable name is `unparseable` too. |
| Q2 | Intake lane report | `src/ciso/intake` | Two `SessionStart` reports with the same session and source get the same action id. |
| Q3 | Inspection lane report | `src/ciso/inspection` | A shell redirect into a sensitive path is not a path finding (the classifier covers part); editor auto-run configs (`.vscode/tasks.json`) and Windows 8.3 short names are not in the path rules. |
| Q4 | Governance lane report | `src/ciso/governance` | `shell_lexer.py` (674 lines) and `analysis.py` (431) exceed the file-size guide; split. |
| Q5 | Automated security review of commit `fd4d760` | `src/ciso/governance/shell_lexer.py` | HIGH. PowerShell expandable here-strings (`@"..."@`) are read as literal text, so `$(...)` and `$var` inside them are never classified. Read them like double-quoted PowerShell strings; only `@'...'@` is literal. Also reconsider: when one of the two readings fails, mark the command `unparseable` instead of trusting the other reading's result. |
| Q6 | Integration lane report | `src/ciso/governance` | `turn_end` has no rule, so every `Stop` is answered `default_ask`; make it a pure-read kind or give it a rule. |
| Q7 | Integration lane report | `config/governance-ruleset.provisional.json` | Full copy of the default ruleset plus agent-config paths; no test pins it to `default.json`, and its description wrongly claims one does. |
| Q8 | Integration lane report | `src/ciso/app/governance_pipeline.py` | The device token's device name is not compared with the request's `device` field. |
| Q9 | Integration lane report | `src/ciso/intake` | The central-gate verdict uses the action id as `reference_id`; the decision id is more useful. |
| Q10 | Integration lane report | `src/ciso/api` | The central gate shares the general per-address rate limit; the platform posting from few addresses could hit 429. |
| Q11 | Fix lane FB report | `src/ciso/api`, `src/ciso/app` | Device assignment route: `AgentAdmin.assign_device` / `unassign_device`, list via `AgentRegistry.list_device_assignments`; the route must check `DeviceDirectory.is_device(device_actor)` first. |
| Q12 | Fix lane FB report | `integrations/claude_code`, `docs/skill/decision-api.md` | Accepted by the coordinator: optional envelope field `report_id` (made once per hook call, reused on retry); document it and the refusal of client claims of reserved kinds; the client must send it. |
| Q13 | Fix lane FB report | `src/ciso/inspection` | Switch inspection to the shared `ciso.common.paths` normaliser once lane FA lands it; directory and archive targets (`cp -r`, `tar -x`) are not path findings. |
| Q14 | Fix lane FB report | handover | Organizational agents must be registered with verifiable facts (`device_actor` or `assistant_account`); agents schema is version 2 with no migration (nothing deployed, so local databases are simply recreated). |
| Q15 | Fix lane FA report, coordinator decision | `src/ciso/governance` | Recursive copies, moves and archive extraction (`cp -r`, `robocopy`, `tar -x`, `unzip`, `Expand-Archive`) whose destination is the current directory, the repository root, a parent or the home directory: new class `bulk_write`, answered ask by the default ruleset (it can plant agent configuration that no path rule sees). |
| Q16 | Fix lane FA report, coordinator decision | `integrations/claude_code/managed` | C4 hardening in the managed pack's `env`: `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=safe.bareRepository`, `GIT_CONFIG_VALUE_0=explicit`, so git refuses a planted bare repository; checker requires it. |
| Q7 | (update) | `config/governance-ruleset.provisional.json` | Now also missing `turn_end` (default ruleset version `governance-default-2026.11.19-2`): regenerate from `default.json` plus the deployment additions, and pin with a test. |
