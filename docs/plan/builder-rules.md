# Rules for builder agents

You are one of several agents building in the same checkout at the same time. These rules
keep you from breaking each other. Repo root: `C:\Users\<user>\Desktop\Projects\CISO_AG`.
Shell: Git Bash. Run every command from the repo root.

## Read before writing

1. This file.
2. `docs/plan/decisions.md` (wins over the plan where they differ).
3. Your task rows in `docs/plan/implementation-plan.md` section 3, and every gap row
   (G1 to G33, section 1) that your rows or your brief cite.
4. Your module's section in `docs/architecture/system-design.md`.
5. The blueprint sections your task rows cite (the v1.0 blueprint is not included in
   this repository).
6. `src/ciso/common/*.py` and `tests/fakes/core.py`, `tests/conftest.py`: the contracts and
   fixtures you build on.

## File ownership

- Create and edit only the files your brief lists (plus new files inside the directories
  it lists). Everything else is read-only for you.
- Never edit: `src/ciso/common/`, `pyproject.toml`, `uv.lock`, `.gitignore`,
  `tests/conftest.py`, `tests/fakes/core.py`, `tests/architecture/`, `docs/`, or another
  lane's module.
- If you need a change to a shared contract, do not make it. Work around it locally if you
  can, and put the request in your final report under "Contract change requests".
- Module-specific fixtures go in a `conftest.py` inside your own test directory.

## Commands

- Tests, targeted only: `uv run pytest tests/<your dir> -q` . Never run the whole suite;
  the coordinator does that once per milestone.
- Lint and format, your paths only: `uv run ruff check <paths>` and
  `uv run ruff format <paths>`. Never `ruff format .` or `ruff check --fix .`.
- Types, your package only:
  `uv run mypy -p ciso.<your_module> --cache-dir=.mypy_cache_<your_lane>`.
- Never run `uv add`, `uv sync`, `uv lock`, `pip install`. If a dependency is missing,
  report it. Installed: pydantic 2, sqlalchemy 2.0, fastapi, uvicorn, cryptography,
  pytest, pytest-cov, httpx, ruff, mypy.
- No network access of any kind. No `git` command that changes state (no add, commit,
  checkout, stash, reset, clean). `git status` and `git diff` are fine.
- Background work: wait on the process, not on a log marker
  (`cmd > LOG 2>&1 & pid=$!; wait $pid; echo "exit=$?" >> LOG`). Every run under
  `timeout`. One waiter per run. At most `-n 4` test workers (xdist is not installed, so
  just run serially). Scratch files only under your scratchpad with a prefix of your lane
  name, never in the repo.

## How to work

- Test first: write the tests your task rows name, run them and see them fail for the
  right reason, then implement until they pass. Add tests for edge cases you find.
- Every test file sets a marker from the nine in `pyproject.toml`
  (`pytestmark = pytest.mark.<class>`). Pick the class the plan names for the file's
  directory (`tests/resilience/` is `resilience`, `tests/privacy/` is `privacy`, and so
  on); default is `unit`.
- A safety check must be able to fail. For each guard you write (a deny, a refusal, a
  fail-closed branch), have a test that reaches the guard and a test that proves the
  allowed path works, so a guard that always refuses or never runs is caught.
- Assert positive evidence (a count, a named row, a specific reason code), not just
  "no error".

## Code rules

- Python 3.13, full type annotations, mypy strict clean.
- Data classes are frozen Pydantic models built on `ciso.common.schemas.Model`. Return new
  objects; do not mutate inputs.
- No module-level mutable state and no singletons. A service is a class that receives its
  dependencies in `__init__`: `Clock`, `AuditSink`, `KillSwitchReader`, `Redactor`,
  `SecretResolver`, an `Engine`, settings values.
- Time comes from the injected `Clock`. Never call `datetime.now()` or `time.time()`.
- Ids come from `ciso.common.ids.new_id("<prefix>")`. Cross-module references are
  `EntityRef` strings, never foreign keys into another module's tables.
- Tables: define them in your module's `tables.py` on
  `ciso.common.db.operational_metadata`, use `UtcDateTime` for every timestamp column, and
  call `register_schema("<module>", 1)` there. (The audit module is the exception: it owns
  a separate database and its own metadata.)
- Raise the narrow error from `ciso.common.errors`. Never swallow an exception. A control
  that cannot be consulted means the operation stops (`FailClosed`).
- Numeric safety parameters (expiry windows, freshness thresholds, rate limits, grace
  periods, retry ceilings, backoff) are constructor arguments typed `X | None` with
  default `None`. `None` means the feature refuses to act; never invent a default number.
- No classification label names, vendor names, product names, cloud names or people's
  names in `src`. Classification goes through `ClassificationScheme`.
- No secrets in code, logs, audit details, exceptions or test output. Store references
  (`secret://name`) only.
- No `print`. Use `logging.getLogger(__name__)`.
- No `subprocess`, `os.system`, `eval`, `exec`, `socket`, `httpx`, `requests`, `urllib`
  in `src`. An architecture test fails the build if they appear.
- Close what you open: dispose engines, close files. `ResourceWarning` is an error in the
  test run.
- Files under about 400 lines, functions under about 50. Docstrings say what a caller must
  know, in plain words, and cite the blueprint section where a rule comes from.
- Windows: use `pathlib`, never `os.replace` on an open file, no POSIX signals.

## Final report (your last message)

1. Files created or changed (paths).
2. For each test directory you ran: the exact last line of pytest output.
3. The last line of your mypy run and of your ruff run.
4. Deviations from the plan or the design, with the reason.
5. Contract change requests (what, why, which file).
6. Open decisions (OD ids) you had to step around, and how.
7. Anything you could not finish or could not verify. Say so plainly; a partial result
   reported as partial is fine, a partial result reported as done is not.
