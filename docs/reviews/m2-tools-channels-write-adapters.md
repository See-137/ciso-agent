# M2 review: tool registry, channel registry, write-adapter contract, import boundaries

Date: 2026-11-18

## Scope

- `src/ciso/execution/tools.py`, `src/ciso/execution/channels.py`, the `execution_channel`
  table in `src/ciso/execution/tables.py`, `src/ciso/write_adapters/`.
- Tests: `tests/execution/test_tool_registry.py`, `tests/execution/test_channels.py`,
  `tests/architecture/test_write_adapter_isolation.py`, and the rules in
  `tests/architecture/test_import_boundaries.py` as they apply to `ciso.approvals`,
  `ciso.execution`, `ciso.write_adapters`, `ciso.inference.external`.
- Measured against: blueprint 9.4, 9.5, 13.1, 19.1; plan gaps G1, G5, G13, G20; tasks
  T2.2, T2.3, T2.5; ADR-0010, ADR-0011; `docs/plan/builder-rules.md`; the four project
  rules (resolve the actor, no audit under the write lock, frozen authority fields, every
  guard has a killing test).

Out of scope and not read for findings: the broker and its helpers (`broker.py`,
`gates.py`, `approval_gate.py`, `auditing.py`, `credentials.py`, `effects.py`,
`records.py`, `store.py`, `outbox_tools.py`, `recovery.py`), the `execution_run` table.

## Method

Line-by-line read of the files in scope, then probe scripts for every finding that could
be run. Nothing under `src/` or `tests/` was edited. Guards were switched off in memory
only (a script replaces the function on the imported module, then calls `pytest.main` on
the two execution test files); the technique was checked with two control mutations that
the tests do kill. Scanner gaps were measured by feeding planted source text to the
architecture tests' own helper functions (`_imports`, `implementations`,
`disallowed_imports`); the shell rule's predicate is restated in the script because the
test does not expose it as a function.

Each finding says MEASURED (a script printed the result quoted) or READ (reasoned from the
code, not run).

Baseline, measured: `uv run pytest tests/execution/test_tool_registry.py
tests/execution/test_channels.py tests/architecture` gives
`172 passed, 2 skipped, 3 xfailed`. The two skips are the connector rules
(`ciso.connectors is not built yet`).

Probe scripts (session scratchpad, may be gone later), run from the repo root with
`uv run python -B <script>`:

- `C:\Users\<user>\AppData\Local\Temp\claude\3cfcfec24bc61f22\195baec2-9149-4e3c-abf0-1f9b23c4bb58\scratchpad\rev2-tools.py`
- `C:\Users\<user>\AppData\Local\Temp\claude\3cfcfec24bc61f22\195baec2-9149-4e3c-abf0-1f9b23c4bb58\scratchpad\rev2-creds.py`
- `C:\Users\<user>\AppData\Local\Temp\claude\3cfcfec24bc61f22\195baec2-9149-4e3c-abf0-1f9b23c4bb58\scratchpad\rev2-channels.py`
- `C:\Users\<user>\AppData\Local\Temp\claude\3cfcfec24bc61f22\195baec2-9149-4e3c-abf0-1f9b23c4bb58\scratchpad\rev2-scanners.py` (takes the scratchpad directory as its argument)
- `C:\Users\<user>\AppData\Local\Temp\claude\3cfcfec24bc61f22\195baec2-9149-4e3c-abf0-1f9b23c4bb58\scratchpad\rev2-mutate.py` (takes a mutation name)

## Summary

No critical finding: nothing in scope lets an unapproved channel read as approved, and
nothing lets a non-admin or a non-human approve one. 3 high, 10 medium, 7 low.

The high findings are all "the guard exists but is narrower than what it claims": the
closed-schema check, the import-boundary rules, and the shell/network scanner.

---

## H1. The closed-argument-schema check admits free-form containers

File: `src/ciso/execution/tools.py:196-226` (`_is_free_form`, `_nested_models`,
`_schema_problem`).

What breaks: blueprint 9.4 "typed action and validated arguments; no free-form command
execution" and 9.5 "allowlisted and typed". The check refuses only the literal
annotations `Any` and `object` (found through `typing.get_args`) and nested
`BaseModel` classes that are not closed. Every other way to spell "anything" registers.

Sequence (MEASURED, `rev2-tools.py` P1): each of these argument models registered, the
registry sealed, and `bind_arguments` returned the nested payload
`{"cmd": ["sh", "-c", "id"], "env": {"A": {"deep": [1, None, {"x": True}]}}}` intact:

| Field annotation | Why it slips through |
|---|---|
| `options: dict` (bare) | no type arguments, so `get_args` is empty |
| `argv: list` (bare) | same |
| `payload: pydantic.JsonValue` | a type alias; `get_args` is empty |
| `options: Alias` where `type Alias = dict[str, Any]` | PEP 695 alias hides the `Any` |
| `options: TD` where `TD` is a `TypedDict` with an `Any` key | not a `BaseModel`, never inspected |
| `options: DC` where `DC` is a stdlib dataclass with an `Any` field | same |

`JsonValue` matters most: `ActionEnvelope.arguments` is `FrozenMap[str, JsonValue]`, so it
is the type a builder will reach for first.

Smallest fix: turn the check into an allowlist. Walk the pydantic core schema (or the
annotation after unwrapping `TypeAliasType.__value__`) and accept only: `str`, `int`,
`float`, `bool`, `None`, enums, `Literal`, dates, and `tuple`/`list`/`frozenset`/`dict`
whose parameters are themselves accepted, plus closed `Model` subclasses. Anything
unrecognised is `OPEN_ARGUMENT_SCHEMA`. Add the six cases above to
`test_a_free_form_argument_field_is_rejected`.

## H2. Import boundaries are a denylist of direct imports; a new or unlisted package joins the two sides

File: `tests/architecture/test_import_boundaries.py:19-80` (`FORBIDDEN`), `:184-195`
(`test_trust_boundaries_hold`).

What breaks: blueprint 9.5 and 19.1 (model orchestration, policy and execution are
separate trust domains) and ADR-0010, which says the in-process boundary is "a convention
plus a test". The test only looks at what each listed package imports directly, and only
packages named in `FORBIDDEN` have any rule.

Sequences (MEASURED, `rev2-scanners.py`; `violations=[]` means the rule stays green):

1. Re-export: `ciso/ops/bridge.py` does `from ciso.inference import gateway` (allowed,
   `ciso.ops` has no rule); `ciso/execution/x.py` does
   `from ciso.ops.bridge import gateway`. `violations=[]`. Same through
   `ciso.app.container` and `ciso.workflows`.
2. Attribute walk: in `ciso.execution`, `import ciso` then
   `ciso.inference.gateway.InferenceGateway` at call time. `violations=[]`.
3. A package with no entry: `ciso.agents.x` importing `ciso.inference`, `ciso.execution`
   and `ciso.write_adapters` together. `violations=[]`.
4. Nothing restricts who may import the execution side:
   `ciso.api.routers.chat` importing `ciso.execution.tools.ToolRegistry` and
   `ciso.write_adapters`, and `ciso.workflows.x` importing `ciso.execution.tools`, are
   both `violations=[]`. A router or workflow that holds the registry can call
   `registry.invoke()` with a hand-built `ToolCall` and never pass the broker.
5. `ciso.orchestrator.x` importing `ciso.approvals.store`, `ciso.vault` and
   `ciso.killswitch`: `violations=[]`. The model side may hold the approval store and the
   secret resolver.
6. `ciso.inference.external.x` importing `ciso.orchestrator`, `ciso.workflows`,
   `ciso.memory`: `violations=[]`. `ciso.approvals.x` importing `ciso.write_adapters`,
   `ciso.connectors`, `ciso.workflows`: `violations=[]`. `ciso.execution.x` importing
   `ciso.connectors`, `ciso.workflows`, `ciso.memory`: `violations=[]`.

State today (MEASURED, static import closure of the whole tree): no violation exists.
`ciso.execution` reaches only `common`, `policy`, `approvals`; `ciso.approvals` and
`ciso.write_adapters` reach only `common`; `ciso.inference.external` reaches `common`,
`approvals`, `inference`, `vault`. Nothing imports `ciso.execution`,
`ciso.write_adapters` or `ciso.inference.external` yet. So this is a hole in the fence,
not a breach.

Smallest fix, three parts:

- Check the transitive closure, not direct imports: build the module graph once (the
  helper already exists) and fail when any module of a guarded package can reach a banned
  package through any chain.
- Add importer allowlists in the style of `EXTERNAL_INFERENCE_IMPORTERS`:
  `ciso.execution` importable only by `ciso.app` and a named API router;
  `ciso.write_adapters` only by `ciso.execution` and `ciso.app`; `ciso.approvals.store`
  only inside `ciso.approvals`.
- Default deny: a test that fails when a top-level package under `src/ciso` has no entry
  in `FORBIDDEN`, so a new package cannot arrive without rules. Add `ciso.approvals`,
  `ciso.vault`, `ciso.killswitch` to the orchestrator's banned list.

## H3. The shell, network and dynamic-import scanners match a few spellings only

File: `tests/architecture/test_import_boundaries.py:84-100` (`NETWORK_MODULES`),
`:220-235` (dynamic import), `:238-260` (shell).

What breaks: blueprint 9.5 "arbitrary shell ... prohibited", 8.4 no network path, and the
builder rule "No `subprocess`, `os.system` ... An architecture test fails the build if
they appear". ADR-0010 names dynamic import as a known weakness; the items below are
ordinary static code, not reflection.

Sequences (MEASURED, `rev2-scanners.py`; each line is source that leaves the rule green,
controls for each rule were caught):

- Shell: `from os import popen; popen("id")`; `import os as o; o.system("id")`;
  `os.execv(...)`, `os.spawnv(...)`, `os.startfile(...)`;
  `asyncio.create_subprocess_shell("id")`; `multiprocessing.Process(...)`;
  `builtins.eval("1")`.
- Network: `asyncio.open_connection("h", 443)`; `import urllib` then `urllib.request`;
  `import http.server`, `import socketserver`; `xmlrpc.client`, `imaplib`, `poplib`;
  `multiprocessing.connection.Client`; a SQLAlchemy engine on a remote URL.
- Dynamic import in the guarded packages: `builtins.__import__("ciso.inference.gateway")`;
  `sys.modules["ciso.inference.gateway"]`; `pkgutil.resolve_name(...)`;
  `runpy.run_module(...)`.
- `test_write_adapters_import_only_common_stdlib_and_pydantic` allows the whole standard
  library: `os`, `sqlite3`, `asyncio`, `multiprocessing`, `urllib`, `shutil`, `pickle`
  give `disallowed: []`.

Smallest fix: (a) ban by module, not by spelling: `os` process functions through any
alias (resolve `import os as o` and `from os import ...` names, ban `system`, `popen`,
`exec*`, `spawn*`, `startfile`, `posix_spawn*`, `fork*`), plus `multiprocessing`,
`runpy`, `pkgutil`, `builtins`, `asyncio.subprocess`; (b) add `asyncio`, `urllib`,
`http`, `socketserver`, `xmlrpc`, `imaplib`, `poplib`, `nntplib`, `multiprocessing` to the
network list with an explicit allowlist of modules that may import `asyncio`; (c) ban
`sys.modules` subscripting and `builtins` in the `NO_DYNAMIC_IMPORT` packages; (d) give
`ciso.write_adapters` a short stdlib allowlist (`re`, `enum`, `typing`, `collections`,
`datetime`) instead of all of it. Add each spelling above as a planted case in
`TestTheCheckerItself`.

---

## M1. `invoke`, `verify`, `rollback` trust every `ToolCall` field except `arguments` and `credentials`

File: `src/ciso/execution/tools.py:370-380` (`_prepared`).

What breaks: the docstring of `call_for` says "the tool never depends on the caller's
copy". `_prepared` re-validates the arguments and re-scopes the credentials, but
`channel`, `actor_id`, `target_resource`, `scope`, `envelope_hash`, `idempotency_key` are
passed to the tool as the caller wrote them. The policy engine approved the channel named
in the envelope's arguments; the tool is told to use `call.channel`.

Sequence (MEASURED, `rev2-tools.py` P4): `call_for` an envelope with
`{"channel": "sec_ops"}`; `call.model_copy(update={"channel": "never_approved",
"actor_id": "human_admin", "target_resource": "x"})`; `registry.invoke(forged)`. The tool
received `('never_approved', 'sec_ops', 'human_admin', 'x')` for
(call.channel, arguments.channel, actor, target). No error.

Smallest fix: in `_prepared`, recompute `channel` from the re-bound arguments
(`getattr(arguments, tool.spec.channel_argument)`), and refuse when it differs from
`call.channel`. For the other fields either drop them from what tools may rely on, or
have `invoke` take the `CheckedEnvelope` and build the call itself so no caller-made
`ToolCall` is ever run.

## M2. `ScopedCredentials` hands the tool the unscoped accessor

File: `src/ciso/execution/tools.py:103-116`.

What breaks: "Lets a tool resolve only the references it declared" (G20, blueprint 9.5
least privilege). The wrapper keeps the real accessor in `_inner` and the allowed set in
a writable `_allowed`.

Sequence (MEASURED, `rev2-creds.py`): a tool declares `secret://outbox_key` only. Inside
`run`: walk `call.credentials._inner` down to the vault and call
`.get("secret://db_password")`: returns `p1`. Or set
`call.credentials._allowed = frozenset({"secret://db_password"})` and call `.get`:
returns `p1`. The vault recorded both requests. Through `call_for` the accessor is wrapped
twice (`ScopedCredentials -> ScopedCredentials -> vault`), which stops the second route
but not the first.

Smallest fix: hold nothing reachable by attribute. Build the accessor as a closure
(`def get(ref): ...` over local variables) wrapped in a class with `__slots__ = ()` and
`__setattr__` refused; wrap once (in `_prepared` only). State in the docstring that this
stops accidents and plain attribute access, not hostile in-process code (ADR-0010
weakness list).

## M3. A tool can return a result object that skips validation

File: `src/ciso/execution/tools.py:387-390`, `:398-401`, `:408-411`; `Verification` at
`:139-147`.

What breaks: "`matches` must be a real boolean" and the reference check on
`ToolResult.references`. The registry only tests `isinstance`.

Sequence (MEASURED, `rev2-tools.py` P3): a verifier returns
`Verification.model_construct(matches="no, it failed")`; `registry.verify()` returns it,
`bool(v.matches)` is `True`. A tool returns
`ToolResult.model_construct(outcome="definitely", references=("../../x",))`;
`registry.invoke()` returns it unchanged. Any caller that writes `if verification.matches:`
reads a failed verification as a pass.

Also READ: `Verification.observed` is never checked to be entity refs, while
`ToolResult.references` is (when validated).

Smallest fix: after the `isinstance` test, re-validate and return the validated copy:
`Verification.model_validate(outcome.model_dump(), strict=True)` and
`ToolResult.model_validate(result.model_dump())`; require `type(x) is Verification`.
Add an entity-ref validator to `observed`. Tests: the two `model_construct` cases.

## M4. `register` validates a snapshot of an object the caller keeps and can change

File: `src/ciso/execution/tools.py:229-257`, `:269-278`, `:280-284`.

What breaks: project rule 3 (authority-carrying fields are frozen) and "no way to add a
tool once the registry is sealed". The registry stores the caller's own `Tool` object,
does not check that it is a validated `Tool`, and sealing protects only the mapping.

Sequences (MEASURED, `rev2-tools.py` P5, P6):

1. After `seal()`, on the object the registering code still holds:
   `tool.__dict__["credential_refs"] = (..., "secret://db_password")` and
   `object.__setattr__(tool, "run", other)`. The next `call_for` resolves
   `secret://db_password` (`'p1'`), and `invoke` runs the swapped function.
   `registry.get(name) is tool` is `True`.
2. `Tool.model_construct(run="not callable", precondition_names=<a set>,
   credential_refs=<a list>, spec=OperationSpec.model_construct(channel_argument=
   "model_fields", ...))` registers. After sealing, `names.add("owner_confirmed")` and
   `refs.append("secret://db_password")` change the sealed tool. `call_for` derives
   `channel` from `str(arguments.model_fields)`.
3. An object that is not a `Tool` at all (a class with the same attribute names)
   registers.
4. `registry._sealed = False; registry._tools = dict(registry._tools)`, register
   `shell.run`, seal again: `names=('note.record', 'shell.run')`.

Sequence 4 is plain Python reflection and cannot be closed in-process; 1 to 3 can.

Smallest fix: at the top of `register`, require `type(tool) is Tool`, then rebuild it:
`tool = Tool.model_validate(tool.model_dump())` with
`spec = OperationSpec.model_validate(...)` so every validator runs again and the stored
object is one no caller holds; coerce `precondition_names` to `frozenset` and
`credential_refs` to `tuple`. Have `get()` stay internal (`_get`) so the stored object is
not handed out. Tests: the `model_construct` and duck cases above.

## M5. An approval binds to the target only, not to the proposal the administrator saw

File: `src/ciso/execution/channels.py:200-222` (`approve`).

What breaks: the docstring's claim "the approval is for what the administrator saw".
`purpose`, `proposed_by` and `version` are not part of what is approved.

Sequence (MEASURED, `rev2-channels.py` C2): agent proposes `sec_ops -> tickets` with
purpose "weekly ticket drafts" (v1); admin A opens it for review; admin B revokes it;
the agent re-proposes the same name and target with purpose "all raw findings incl.
restricted data"; admin A approves with `target="tickets"`. Result:
`approved v4 with purpose='all raw findings incl. restricted data'`.

Smallest fix: `approve(actor_id, channel, target, version)`; refuse with `Conflict` unless
`row.version == version`. Put `version` and `purpose` in the approve audit details.

## M6. The channel is live before its approval is on the audit log; a crash there leaves it approved, and the undo can report success without undoing

File: `src/ciso/execution/channels.py:340-355` (`_apply`), `:368-377` (`_restore`).

What breaks: G5 ordering for an authority-granting change. The row is committed as
`approved`, then the result is audited, then (on failure) undone. Three consequences:

1. MEASURED (`rev2-channels.py` C7): while the SUCCESS record is being written,
   `is_approved("sec_ops")` is `True` and `approved_target` returns `tickets`.
   `tests/execution/test_channels.py:344-361` shows the same state
   (`(SUCCESS, "approved")`).
2. MEASURED (C7): if the process ends at that point (simulated with `SystemExit` from the
   sink, which `except Exception` does not catch), the channel stays approved and the
   audit log holds `['attempt']` only. Nothing reconciles this at start-up.
3. MEASURED (C6): `_restore` never checks how many rows it changed. Propose; the SUCCESS
   audit fails; between commit and undo another session approves the row (version 2).
   The delete matches nothing, the proposer gets
   `FailClosed: the result could not be audited; the change was undone`, and
   `is_approved` is `True`. The outcome is acceptable (an admin did approve) but the
   message is false, and the propose has no result record.

Smallest fix: make approval two-step so the dangerous state is never the committed one
before its record exists: commit `status="approving"` (not usable), audit SUCCESS, then
commit `approved`; a row left in `approving` at start-up is returned to `proposed` and
audited. In `_restore`, read `rowcount` and raise the "could NOT be undone" branch with a
truthful message when it is 0. Tests for both.

## M7. The write-adapter scanner is evaded by ordinary static code, and a `Tool` needs no adapter at all

File: `tests/architecture/test_write_adapter_isolation.py:80-119` (`_contract_aliases`,
`implementations`).

What breaks: T2.5 "zero implementations in `src`" and ADR-0010's hard rule (no adapter to
a real system while the broker shares a process). The file's own "Limits" note covers
classes built at run time; these are static.

Sequences (MEASURED, `rev2-scanners.py`, each gives `found=[]`):

- The three methods split over two classes: `class Half` defines `apply`, `verify`;
  `class Real(Half)` defines `rollback`, `manifest`.
- Methods bound by assignment in the class body: `apply = _a; verify = _v; rollback = _r`,
  or as lambdas.
- Base reached through an assignment: `Base = contract.WriteAdapter; class Real(Base)`,
  or `from ciso.write_adapters import *; B = WriteAdapter; class Real(B)`.
- `Real = type("Real", (), {...})` at import time.
- A class with `run`, `verify`, `rollback`, which is exactly what `Tool` takes
  (`tools.py:183-189`): `found=[]`.

The last one is the real gap: a tool whose `run` writes to a real system satisfies the
registry and never touches `ciso.write_adapters`, so the isolation test guards a name.
READ: nothing in `tools.py` ties a writing tool to a declared target kind.

Also READ: both architecture files scan `src/ciso` only (`SRC`); `pyproject.toml` ships
`packages = ["src/ciso"]`, so a sibling package under `src/` would not ship, which makes
this harmless today.

Smallest fix: (a) resolve methods through base classes within the file set and count
`Assign`/`AnnAssign` targets as well as `def`; treat any name assigned from an expression
containing `WriteAdapter` as an alias; flag any occurrence of the name `WriteAdapter`
outside `ciso.write_adapters` and `ciso.execution`. (b) Close the real gap with the
network and process rules of H3 (a real-system write needs one of those modules), and
state in ADR-0010 that the hard rule is enforced by "no network or process module in
`src`", not by this scanner.

## M8. `AdapterOperation` accepts argument schemas and names the tool registry refuses

File: `src/ciso/write_adapters/contract.py:32-56`; `WriteRequest` at `:96-124`.

What breaks: the docstring "`args_model` is a closed schema". The validator checks
`extra="forbid"` and `frozen` on the top model only: no field inspection, no recursion,
no protected-name check, and `WriteRequest.arguments` is typed `Model` with nothing tying
it to the operation's `args_model`.

Sequence (MEASURED, `rev2-tools.py` P7): `AdapterOperation(name="host.run",
authority_level=L3, args_model=<Model with command: Any>, reversible=False)` and
`AdapterOperation(name="policy.update_rule", args_model=<Model with options:
dict[str, Any]>)` are both accepted.

Smallest fix: move the closed-schema walk (after the H1 fix) into `ciso.common` and use
it in `tools.py`, `OperationSpec._closed` and `AdapterOperation._closed`, so there is one
definition of "closed". The protected-name rule lives in `ciso.policy`, which this
package may not import: state in the contract that the broker must run each adapter
operation through `OperationSpec` before use, and test that when the broker binds
adapters.

## M9. Guards with no test that fails when they are removed

Files: `src/ciso/execution/tools.py`, `src/ciso/execution/channels.py`; project rule 4 and
builder rule "a safety check must be able to fail".

MEASURED with `rev2-mutate.py`: each guard below was switched off in memory and the two
execution test files still reported `118 passed`. Controls: emptying `_DEVICE_NAMES`
gave `2 failed`; removing the actor-id comparison in `_refusal` gave `1 failed`; removing
the `isinstance` test in `verify` gave `1 failed`; removing the outbox re-check inside
`approve` gave `1 failed`.

| Guard | Location | Why it survives |
|---|---|---|
| `is_protected_name(name)` half of the protected check | `tools.py:234` | the test passes `protected=True` and a protected name together |
| `spec.protected` half of the same check | `tools.py:234` | same test; no case with `protected=True` and an ordinary name |
| credentials re-scoped in `_prepared` | `tools.py:379` | the only credential test goes through `call_for`, which already scoped them; no test invokes a hand-built `ToolCall` holding a raw accessor |
| `seal()` replaces the dict with a read-only mapping | `tools.py:282` | tests only check the `_sealed` flag path |
| `not isinstance(self._tools, dict)` in `register` | `tools.py:271` | same; either half alone is enough for the test |
| version condition in `_restore` ("only if it is still the row this call wrote") | `channels.py:370` | no test changes the row between commit and undo |
| version condition in `_update` | `channels.py:258` | no test; cannot fire under `BEGIN IMMEDIATE` |
| `_MAX_TEXT` length bound | `channels.py:100` | only the blank case is tested |

READ, no test reaches them at all: the "could NOT be undone" branch
(`channels.py:348-352`); the generic database-failure branch in `_apply`
(`channels.py:337-339`); `FailClosed` from `records()` and `get()` on a read error; the
`(TypeError, ValueError)` branch of `bind_arguments` (`tools.py:340-343`); the `seen`
cycle guard in `_schema_problem`.

Smallest fix: one test per row. For the first two: a spec built with `model_construct`
that has a protected name and `protected=False`, and one with `protected=True` and the
name `host.wipe`. For the third: `registry.invoke(call.model_copy(update={"credentials":
raw_vault}))` and assert the undeclared reference is refused.

## M10. A tool cannot require a precondition; leaving it out of the envelope skips the check

File: `src/ciso/execution/tools.py:413-434` (`require_preconditions`).

What breaks: blueprint 9.5 "evaluate ... freshness and preconditions immediately before
execution". The method checks the preconditions it is handed. `precondition_names` on a
tool means "names I am able to check", not "names that must be present", and the list
comes from the envelope, which the requester (an agent) writes.

Sequence (READ): a tool declares `precondition_names={"still_open"}`. An envelope for it
arrives with `preconditions=()`. `require_preconditions(call, ())` loops zero times and
returns. Nothing in the registry or in `OperationSpec` says the name was required.

Smallest fix: add `required_preconditions: frozenset[str]` to `Tool` (subset of
`precondition_names`, checked at registration); in `require_preconditions`, every
required name missing from the supplied list goes into `failed`. Test: a required name
left out raises `PreconditionFailed`.

---

## L1. Two reserved device names pass as outbox names; channel names are not checked at all

File: `src/ciso/execution/channels.py:56-58`, `:95-96`.

MEASURED (`rev2-channels.py` C1): `is_outbox_name("com0")` and `("lpt0")` are `True`
(the platform reserves `COM0` and `LPT0` as well as 1 to 9). `_is_channel_name("nul")`,
`("con")`, `("com1")` are `True`: the device list is applied to targets only. Harmless
while neither is used as a file or directory name. Fix: `range(0, 10)`, and apply the
device check to channel names too.

## L2. One human can propose and approve a channel; proposals are unlimited

File: `src/ciso/execution/channels.py:167-222`.

MEASURED (C3): `propose(ADMIN, ...)` then `approve(ADMIN, ...)` gives
`proposed_by=human_admin decided_by=human_admin status=approved`.
`docs/plan/decisions.md` (G33) keeps self-approval forbidden by default for approvals;
G13 asks only for a `security_admin`, so this is a decision to record, not a broken
rule. MEASURED (C9): one agent created 300 proposed rows with no limit, and a proposed
name blocks anyone else from proposing it until an admin revokes it. Fix: note the
self-approval choice for channels in ADR-0016's follow-up; cap open proposals per actor
through a constructor argument typed `int | None` (unset means refuse).

## L3. Refused targets and names leave no audit record

File: `src/ciso/execution/channels.py:170-173`.

MEASURED (C8): three proposals with a URL, an e-mail address and a traversal path as
target were refused and `audit.events` stayed empty
(`tests/execution/test_channels.py:168` asserts this). An agent probing for an
exfiltration target leaves no trace. Fix: resolve the actor first, then audit a DENIED
record with a reason code (not the raw target) before raising `ValidationFailed`.

## L4. `purpose` and `reason` keep control and direction-override characters

File: `src/ciso/execution/channels.py:99-102`.

MEASURED (C4): a purpose of `'ok\n\x1b[2K\u202eAPPROVED by human_admin\x00'` is stored
and returned as written. It is agent-written text shown to the approving administrator
and copied into audit details. Fix: refuse characters in Unicode categories `Cc`, `Cf`,
`Zl`, `Zp` in `_text`.

## L5. `NaN` passes strict argument binding

File: `src/ciso/execution/tools.py:333-334`.

MEASURED (`rev2-tools.py` P8): `bind_arguments(..., {"ratio": float("nan")})` returns
`Num(ratio=nan)`; `json.dumps` writes `NaN` and the strict JSON validation accepts it.
`NaN != NaN`, so equality and re-validation comparisons on such arguments misbehave. Fix:
`json.dumps(..., allow_nan=False)` (the existing `ValueError` branch then reports it).

## L6. Tests that assert little, and rules that are green because their subject does not exist

- `tests/execution/test_tool_registry.py:256-282`
  (`test_shell_metacharacters_reach_the_tool_as_inert_text`) patches `subprocess.Popen`
  and `os.system` around a registry that imports neither and a tool body that only
  records its input. It can only fail if the registry itself starts a process. What it
  does prove is that the string arrives unchanged. READ.
- MEASURED: `src/ciso/connectors`, `src/ciso/orchestrator` and `src/ciso/memory` do not
  exist, so their `FORBIDDEN` rows, both connector tests (skipped) and the
  external-inference importer rule pass with nothing to check. The planted-source tests
  cover the scanners themselves, which is the right mitigation; the rules still need a
  real first run when those packages arrive.
- `WRITE_METHOD_PREFIXES` (`test_import_boundaries.py:124`), MEASURED: `apply`,
  `rollback`, `send_ticket`, `post_comment`, `put_tag`, `patch_rule`, `remove_user`,
  `set_state`, `isolate_host`, `block_ip`, `run`, `invoke`, `close_ticket`,
  `reset_password` are not flagged. ADR-0011 already calls this test a tripwire.

## L7. The direct-database limit is declared in a docstring and nowhere else

File: `src/ciso/execution/channels.py:17-18`.

READ: "anyone who can write the operational database can approve a channel without going
through this class" is stated honestly, and `tests/execution/test_channels.py:187-205`
shows a tampered target is not honoured. A tampered `status` is honoured. The limit is
not in `docs/plan/followups.md` and has no ADR, so it will be forgotten. Fix: add a
follow-up row; when the audit key is available to the broker process, store a keyed hash
over `(channel, target, status, decided_by, version)` and have `_approved_row` verify it.

---

## Suspicions (not made concrete)

- `_transact` builds the `ChannelRecord` after the transaction has committed
  (`channels.py:366`). If that validation ever raised, `_apply` would audit FAILED and
  raise "could not be changed" for a change that was committed. I could not make it
  raise: a direct write of a number into a text column is stored as text.
- `_authorise` resolves the actor before the transaction starts. An administrator whose
  role is removed in the gap still approves. The gap is a few statements long.
- `_update` relies on `BEGIN IMMEDIATE` for exclusion and ignores `rowcount`. On a
  database with weaker isolation the version condition would fail silently and the
  re-read would report another writer's state as this call's success.
- `ToolRegistry.catalog()` and `operation_specs()` work on an unsealed registry. A
  catalog taken before a late `register` lacks that tool. That fails closed (unknown
  operation).
- A registered tool named `shell.run` with a single `command: str` field passes every
  registry check. The registry cannot tell data from a command line; only review of the
  tool body and the H3 rules stand between that and blueprint 9.5.

## Checked and found sound

- `is_approved` returns exactly `True` or `False` for every input tried (`"sec_ops"`,
  unknown, `None`, `5`, `b"sec_ops"`, a list): MEASURED (C10). The policy engine compares
  with `is True` (`src/ciso/policy/engine.py:203-204`).
- Who may decide: the actor id is resolved through `PrincipalResolver` on every call; a
  resolver error is `FailClosed`; an answer for a different actor id, an anonymous actor,
  a non-human holding the role, and a narrowed grant are all refused, each with a test
  that the mutation run confirms can fail (control mutation on `_refusal` was killed).
- No audit call is made while the write transaction is open: the `change` callbacks do
  not audit, and both `_audit_quietly` calls in `_apply` run after `_transact` has left
  its `with` block. READ, plus the `LockSpy` test.
- Propose, approve and revoke each read and write the row inside one `BEGIN IMMEDIATE`
  transaction, so the interleavings propose/approve/revoke cannot produce an approved
  row without an approve call by a current admin. Re-proposal after revoke resets
  `decided_by` and needs a fresh approval. A live channel cannot be re-proposed, so its
  target cannot be swapped under an approval.
- Target and channel-name pattern: explicit ASCII classes with `fullmatch`, so a trailing
  newline, upper case, a Cyrillic look-alike, a full-width letter, a zero-width space, a
  trailing space and a NUL are all refused: MEASURED (C1).
- Attempt audit failure changes nothing; a failed result audit on approve or propose is
  undone in the ordinary case; a revoke stands. Tests exist and pass.
- `bind_arguments`: extra fields refused, no coercion between `str`/`int`/`bool`, exact
  type match on `call.arguments`, unvalidated argument objects re-validated. Tests exist.
- Precondition answers: only `is True` passes; an unknown name fails; a raising checker
  is `FailClosed`.
- `ciso.write_adapters` today imports only `ciso.common`, pydantic and the standard
  library; no class in `src` implements the contract. MEASURED (the architecture tests
  pass and the import closure agrees).
- `ciso.approvals` may not import `ciso.execution` or `ciso.policy`, and
  `ciso.write_adapters` is in the no-dynamic-import list: re-read after the coordinator's
  note, both present.
- No vendor, product or person names, and no network or process module, in the files in
  scope. READ.
- No guard left disabled in the files in scope: the `if False/True` grep over
  `tools.py`, `channels.py` and `write_adapters/` returned nothing.

## Not reviewed

- The broker and everything listed as out of scope above, so none of the findings were
  checked against how the broker actually calls the registry (M1, M3 and M10 depend on
  it: the broker may or may not build its own `ToolCall`, compare `matches is True`, and
  pass the envelope's preconditions).
- `ciso.approvals` and `ciso.inference.external` code. Only the import rules that apply
  to them were reviewed.
- The outbox tools: how an approved target name becomes a location was not examined, so
  the device-name and reserved-word questions in L1 are untested against real use.
- The identity store behind `PrincipalResolver`, the real audit sink, and behaviour with
  two operating-system processes on one database file (all probes used the in-memory
  engine with one connection).
- `mypy` and `ruff` were not run. The full test suite was not run, by instruction.
