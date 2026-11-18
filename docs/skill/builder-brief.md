# Brief block for every builder on the AI-governance skill

Read this whole file before writing anything. Repo root: `C:\Users\<user>\Desktop\Projects\CISO_AG`.
Shell: Git Bash; run every command from the repo root.

## Read first
1. `docs/skill/spec-draft.md` (the product, its components C1-C5, the funnel, the rules
   that do not change, section 9 results already verified).
2. `docs/skill/decision-api.md` (the wire contract between hooks and the service).
3. `src/ciso/common/activity.py` (the shared contract: `ObservedAction`, `Attribution`,
   `InspectionInput`, `InspectionResult`, `GovernanceDecision` and friends) and the rest of
   `src/ciso/common/`, `tests/fakes/core.py`, `tests/conftest.py`.
4. `docs/plan/builder-rules.md`: the code rules and the final-report format still apply.
   Where it mentions the old plan's task rows, read this brief and your lane brief instead.

Several builders work in this checkout at the same time. Create and edit only the files
your lane brief lists. `src/ciso/common/`, `tests/conftest.py`, `tests/fakes/core.py`,
`tests/architecture/`, `pyproject.toml`, `uv.lock`, `docs/` and other lanes' packages are
read-only for you. Need a contract change? Do not make it: work around it locally and put
the request in your report.

## Cross-cutting rules (binding)
1. A `Principal` object is a snapshot. Anything that decides a privilege resolves the
   actor id through a `PrincipalResolver` and decides on the result.
2. Never call the audit sink (or a resolver) while holding the operational database write
   lock. Audit the attempt, change state in a short transaction, audit the result.
3. Dict and list fields that carry authority use `FrozenMap` / `FrozenJson` / tuples.
4. A guard is not done until switching it off turns a named test red. Run your mutation
   pass on a COPY of `src/ciso` (and of your own directory if it is outside `src`) under
   the scratchpad, with `PYTHONPATH` pointing at the copy; never mutate the repo files.
   Verify the repo files' hashes are unchanged afterwards. List guard -> test in your report.
5. Fixed, tested rules decide allow and deny. A model never decides and nothing here calls
   one.
6. Numeric safety parameters are constructor arguments defaulting to `None`, and `None`
   means refuse. Structural bounds (sizes, counts) are named module constants.
7. Never store or log secrets, prompt text or file content, except an encrypted evidence
   item where the spec allows it. `repr` of anything holding content must not show it.
8. Validators use `.fullmatch(`. Text that reaches audit or a person is clean text
   (`ciso.common.activity.clean_text`).
9. Write tests first, run them, see them fail for the right reason, then implement.

## Commands and discipline
- Targeted tests only, your directories (addopts already has `-q`; do not add another).
  Never run the bare whole suite.
- `uv run mypy -p <your package> --cache-dir=.mypy_cache_<lane>` (for code outside `src`,
  run mypy on the files: `uv run mypy <paths> --cache-dir=.mypy_cache_<lane>`).
- Ruff with literal paths only, never through a variable, never repo-wide fixes:
  `uv run ruff check <paths>` and `uv run ruff format <paths>`. A formatter hook may
  reorder imports: run `ruff check` after editing.
- Background work: wait on the PROCESS, not a log marker
  (`cmd > LOG 2>&1 & pid=$!; wait $pid; echo "exit=$?" >> LOG`); every run under
  `timeout`; one waiter per run.
- Scratch files only under
  `C:\Users\<user>\AppData\Local\Temp\claude\43d473e2d56a90eb\56f57e25-2b6b-4946-b3eb-af7c61ade842\scratchpad`
  with your lane prefix.
- Never create a directory named `secrets`. Never use recursive delete. If a write or
  delete is denied, do not route around it: report it.
- No git command that changes state. No package installs (`uv add`, `pip install`); report
  a missing dependency instead. No downloads.
- Run `grep -rnE "^\s*(el)?if (False|True)\s*:" src/` before finishing; nothing of yours
  may be left disabled.

## Final report
The builder-rules format, plus: the public API exactly as built (another builder wires it
next), the guard -> mutation -> test table, and what you could not do or verify, plainly.
