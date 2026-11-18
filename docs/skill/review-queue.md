# Findings queued for the review-and-fix round

Raised after the owning lane finished; to be fixed test first in the fix round, after the
integration lane, so no two builders edit the same files.

| # | Source | File | Finding |
|---|---|---|---|
| Q1 | Automated security review, 2026-11-19 | `src/ciso/governance/analysis.py` | HIGH. Bash evaluates some arguments arithmetically and runs any command substitution inside them: operands of `[[`, `test`/`[` (e.g. `-eq`), `-v` targets of `test`/`printf`/`read`/`declare`, `let` arguments, `((...))` bodies, and `$((name))` where `name` holds an expression. An argument of those programs containing `$(`, a backtick, `<(` or `>(` must add `unparseable` (never allowed) and clear read-only; an arithmetic expansion whose body is a bare variable name is `unparseable` too. |
| Q2 | Intake lane report | `src/ciso/intake` | Two `SessionStart` reports with the same session and source get the same action id. |
| Q3 | Inspection lane report | `src/ciso/inspection` | A shell redirect into a sensitive path is not a path finding (the classifier covers part); editor auto-run configs (`.vscode/tasks.json`) and Windows 8.3 short names are not in the path rules. |
| Q4 | Governance lane report | `src/ciso/governance` | `shell_lexer.py` (674 lines) and `analysis.py` (431) exceed the file-size guide; split. |
