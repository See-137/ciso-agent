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
