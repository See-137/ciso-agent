# Adversarial review: skill service (decision API, pre-push path, hook client, sandbox)

Date: 2026-11-19

Scope: `src/ciso/app/` (governance pipeline, devices, central gate endpoint wiring, change
shape, store, crypto and decide, sandbox client and worker, risk acceptance, settings and
readiness, container), `src/ciso/api/` (governance, agents, findings and devices routers,
deps and permissions, body limit, error mapping), `src/ciso/intake/` as those paths use it,
`integrations/claude_code/` (hook client, managed policy pack, builder and checker, README),
`services/sandbox/` (job intake, archive handling, docker invocation, HTTP app), and the
tests under `tests/app`, `tests/api`, `tests/e2e`, `tests/integrations`, `tests/services`.
Out of scope (being edited by another agent): `src/ciso/governance`, `src/ciso/inspection`,
`src/ciso/findings`, `config/governance-ruleset.provisional.json`.

Method: read every in-scope module, then attacked it as (a) a prompt-injected agent on a
managed machine and (b) the engineer who wants the controls off. Each claim is marked:

- **Measured**: I ran the real code and saw the result. Service probes ran through the API
  test client on a container in a temp directory (`tests.api` fixtures, the e2e pre-push
  world with `tests/e2e/prepush_ruleset.py`, the real sandbox client and worker behind an
  `httpx.MockTransport` fake sandbox). Because the governance package was mid-edit by the
  other agent (the working tree's default ruleset did not load, every probe answered
  `ruleset_unavailable`), the probes ran against a `git archive HEAD` copy of `src/` and
  `tests/` (commit `436219b`) in the scratchpad. Client probes imported the real
  `integrations/claude_code/client/hook_client.py` and ran its `build_change` with the
  real `SubprocessGitRunner` and this machine's git 2.56.1 in throwaway repositories, and
  its `main()` with the real `UrllibTransport` against a local TLS-terminating proxy on
  127.0.0.1 (nothing left the machine; the service host name was never resolved).
- **Read**: concluded from source or from the vendor's documented behaviour, not executed.

No file under `src/`, `tests/`, `integrations/` or `services/` was changed; no git state was
changed; Docker was not started and the real `claude` CLI was not run. Throwaway files are
under the session scratchpad with the prefix `revS2-`. Secret-like test values were built
at runtime from fragments and are described here as `<secret>`.

Targeted suites on the same HEAD copy: see "Test run" at the end.

---

## C1. The hook client takes its proxy and its trust anchors from the inherited environment: a local proxy answers "allow" for everything and receives the device token

Files: `integrations/claude_code/client/hook_client.py:178-181` (opener built without an
empty `ProxyHandler`, so urllib reads `HTTPS_PROXY`/`https_proxy`, and on Windows the
per-user registry proxy), `:269-276` (`ssl.create_default_context()`, which honours
OpenSSL's `SSL_CERT_FILE`/`SSL_CERT_DIR`, and `cafile=AIGOV_CA_BUNDLE`), `:286`
(`AIGOV_CA_BUNDLE` read from the environment); `integrations/claude_code/managed/*/managed-settings.json`
`env` block (does not set `AIGOV_CA_BUNDLE`, `AIGOV_LOG_FILE`, or any proxy/CA variable);
`integrations/claude_code/managed/check_pack.py:299-319` (`_env_errors` checks only the URL,
the token file and the two timeouts).

What breaks: spec rule 3 and the whole of C2. The managed `env` block overrides only the
keys it names. Every other variable the client or its libraries read comes from the
environment Claude Code was started with, which the engineer controls (their shell,
`setx`, a wrapper script). The README (`Client behaviour`) states "A managed value
overrides the user's shell", which is true only for the listed keys.

Sequence (measured, `revS2-tls_exp.py`): a local proxy on 127.0.0.1 answers `CONNECT` itself
and terminates TLS with a certificate for the service host signed by a CA it generated; it
answers every request with `{"verdict":"allow","decision_id":"dec_forged","message":""}`.
Hook input: `PreToolUse`, Bash, `git push --force origin main`.

| Variant | Environment of the hook process | Result |
|---|---|---|
| C (control) | `HTTPS_PROXY=http://127.0.0.1:<port>` only | exit 2 (block); proxy saw TLS fail |
| A | `HTTPS_PROXY` + `AIGOV_CA_BUNDLE=<attacker CA>` | **exit 0, no output = allow**; proxy received `Authorization: Bearer <device token>` and the full 448-byte report |
| B | `HTTPS_PROXY` + `SSL_CERT_FILE=<attacker CA>` (no `AIGOV_CA_BUNDLE`) | **exit 0, no output = allow**; proxy received the bearer token |

Variant B works on Windows because `load_default_certs` ends with
`set_default_verify_paths`. `python -I` does not help: these are not `PYTHON*` variables.
The same proxy also answers `needs_change` pushes with "allow" on the first ask, so no
change is ever uploaded. For an agent (rather than the engineer) the route is narrower:
`setx HTTPS_PROXY ...` was `ask`, `setx SSL_CERT_FILE ...` and a project
`.claude/settings.local.json` with an `env` block were denied (measured, HEAD ruleset).

Smallest fix (client, about ten lines): build the opener with
`urllib.request.ProxyHandler({})` (or a proxy taken only from a managed `AIGOV_PROXY`);
build the context as `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` +
`load_verify_locations(cafile=...)` from an admin-owned path and never call
`load_default_certs`; make `AIGOV_CA_BUNDLE` required and pinned in every platform's managed
`env`, and have `check_pack.py` require every `AIGOV_*` variable the client reads
(`AIGOV_CA_BUNDLE`, `AIGOV_LOG_FILE`, `AIGOV_GIT_PATH`, `AIGOV_HOOK_DEADLINE_SECONDS`) to be
pinned. Add a test that sets `HTTPS_PROXY`, `SSL_CERT_FILE` and an unpinned
`AIGOV_CA_BUNDLE` and asserts exit 2.

---

## H1. The pushed range starts at a local remote-tracking ref the agent can move: commits that `git push` sends are never scanned, by the service or the sandbox

Files: `integrations/claude_code/client/hook_client.py:608-619` (`_base`: merge base with
`refs/remotes/<remote>/<branch>`, else the remote's `HEAD`/`main`/`master`), `:674-686`;
`services/sandbox/runner.py:181` (`gitleaks ... --log-opts <base>..HEAD`) and `:189`
(`semgrep --baseline-commit <base>`), which reuse the same base.

What breaks: "a push whose pushed commits differ from the scanned commits". What `git push`
sends is decided by what the remote lacks; what is scanned is decided by a local ref.

Sequence (measured, `revS2-git_exp.py` E1, local bare repository as the remote):
1. two unpushed commits on `main`: the first adds `creds.txt` with `<secret>`, the second a
   harmless `notes.txt`;
2. honest client build: 2 commits, server diff inspection finding `secret.assignment`;
3. the agent moves `refs/remotes/origin/main` to `HEAD~1`;
4. client build: 1 commit, diff contains only `notes.txt`, **no findings**; the sandbox
   would get `base=HEAD~1` and scan only the last commit;
5. `git push origin main`: the remote now has `add creds` and `creds.txt`.

How the agent moves the ref (measured against the HEAD ruleset): `git update-ref ...` and
`git fetch . HEAD~1:refs/remotes/origin/feature` are denied; `echo <sha> >
.git/refs/remotes/origin/feature`, a Write of that file, and
`git fetch origin +refs/heads/old:refs/remotes/origin/feature` are `ask` (the same verdict
as an ordinary source edit under the default ruleset, so one routine-looking approval).
Stale tracking refs after a server-side branch reset produce the same gap with no agent
action (read).

Smallest fix: stop trusting the local base for coverage. In the sandbox, drop
`--log-opts <base>..HEAD` and `--baseline-commit` (the bundle already carries the full
history; scan all of it, or scan from a base the SERVICE recorded as the last scanned head
it allowed for that remote and branch). In the service, treat the uploaded `base` as
untrusted: either record allowed heads per remote/branch and require
`base` to be one of them, or mark the diff inspection advisory and rely on the full-history
sandbox scan. Test: move the tracking ref, assert the secret is still reported.

---

## H2. The allowed push or commit runs the repository's own hooks and transport config: the commit gets content the scan never saw, and a pre-push hook pushes another branch

Files: `integrations/claude_code/client/hook_client.py:581-587` (the client disables hooks,
fsmonitor, external diff and protocols for ITS OWN git only); the push/commit the agent
then runs is the agent's command with the repository's configuration.

What breaks: the scan is of `git diff --cached` / `base..head`, but the command that runs
afterwards executes repository-controlled programs.

Sequence (measured, `revS2-hooks/`): `core.hooksPath=.githooks`, a `pre-commit` that writes
and `git add`s `extra.txt`, a `pre-push` that runs `git push origin side:refs/heads/side`.
Staged (what the client scans): `ok.txt`. Committed: `extra.txt`, `ok.txt`. After
`git push origin main` the remote has `main` **and `side`** (an unscanned branch). Same
class (read): `remote.<name>.pushurl` differing from `url` (scan against one repository,
push to another), `push.recurseSubmodules=on-demand` (submodule commits pushed unscanned),
`remote.<name>.receivepack` with a local-path remote and `core.sshCommand` (arbitrary
commands at push time). The agent needs `ask` approvals to set these
(`git config core.hooksPath ...`, `git config remote.origin.pushurl ...`, `git config
push.recurseSubmodules ...`, Write `.githooks/pre-push`: all `ask`, measured) or a repository
that already has them.

Smallest fix: in the client, before building, read the repository's effective config with
the admin git (`config --get-regexp` for `core.hookspath`, `remote\..*\.(pushurl|receivepack|uploadpack)`,
`push\.recursesubmodules`, `submodule\.recurse`, `core\.sshcommand`, `url\..*\.pushinsteadof`)
and list `.git/hooks` for non-sample files; any hit blocks with a fixed message ("this
repository runs its own programs on push; push it yourself"). Test per item.

---

## H3. The sandbox scanners take their configuration from the repository being scanned

Files: `services/sandbox/runner.py:177-192` (gitleaks `git` mode with `--config` only when
`gitleaks_config` is set; semgrep `scan` on the cloned tree); `services/sandbox/settings.py:261-273`
(`gitleaks_config` optional; "unset means gitleaks' built-in rules").

What breaks: report forgery by the scanned code itself, with no code execution.

- gitleaks without `--config` loads `<source>/.gitleaks.toml` (read: gitleaks v8 config
  precedence: flag, `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`, then the target's
  `.gitleaks.toml`); a committed file with an allowlist for every path empties the check.
  With or without `--config`, `.gitleaksignore` in the source and inline `gitleaks:allow`
  comments suppress findings (read).
- gitleaks `git` mode parses `git log -p`; a committed `.gitattributes` with `-diff` turns
  every matching file into `Binary files ... differ`. Measured on this machine: in a clone
  of a bundle, `git log -p -U0 <base>..HEAD` printed `Binary files /dev/null and
  b/app.cfg differ` for a file holding `<secret>` (read: gitleaks passes no `--text`).
- semgrep honours `.semgrepignore` at the scan root and `nosemgrep` comments (read).

Each of these is an ordinary file write; under the default ruleset a Write of
`.gitleaks.toml`, `.semgrepignore`, `.gitattributes` and an Edit adding `# nosemgrep` are all
`ask` like any edit (measured). The service's own diff inspection still sees a plain
`<secret>` in the diff, so this removes what the sandbox adds (gitleaks' rules, semgrep, and
everything the in-process inspector does not match), not the in-process check.

Smallest fix: make `gitleaks_config` required; add `--ignore-gitleaks-allow` and point
`--gitleaks-ignore-path` at an empty file baked into the image; in `BUNDLE_SCRIPT` remove
`.gitattributes`, `.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore` from the clone before
the scanner runs (or run gitleaks `dir` mode over the checked-out tree as well); run
semgrep with `--disable-nosem`. Have the service flag any change to those files as a
finding of its own.

---

## H4. Device name and person are the client's word, and the device token is readable by the agent: one engineer's token is attributed as another person on another machine and gets that person's allow

Files: `src/ciso/intake/hook.py:132-134, 223-225, 237` (the `device` field and the
`os_account` claim come from the request; only the device actor is verified);
`src/ciso/api/routers/governance.py:55-74` (the authenticated device is passed as an actor
id only; its registered name, `src/ciso/app/devices.py` `Device.name`, is never compared);
`integrations/claude_code/client/hook_client.py:296-316` (`os_account` from `USERNAME` and
`USERDOMAIN`, which the user sets); managed pack deny rule
`Read(//c/ProgramData/AIGovernance/**)` covers only the Read tool.

Sequence (measured, HEAD ruleset plus the pre-push test ruleset, e2e world: device
`WS-0142`, person jdoe bound to `CORP\jdoe`, jdoe's approved agent identified by the device
fact `WS-0142`):
1. a second machine `WS-0999` is registered and gets its own token;
2. with that token, decide `git push origin feature` as `device: WS-0999`,
   `os_account: CORP\mallory`: `deny rule_deny` (no needs_change), session attributed to no
   person, state `unknown`;
3. same token, `device: WS-0142`, `os_account: CORP\jdoe`: `deny inspection_incomplete` with
   `needs_change`; session attributed to jdoe's person ref and jdoe's agent, state
   `declared`; after upload and a clean sandbox report: **`allow rule_allow`**. The honest
   identity on the same flow stays `deny`.

The token is not hard to get: `cat /c/ProgramData/AIGovernance/device-token` was **allowed**
by the HEAD ruleset (`type ...`, `Get-Content ...` and a `python -c open(...)` were `ask`).
With it an agent can also post forged `PostToolUse` activity in another person's name
(findings and alerts against them) and burn its device's rate budget (every real hook then
blocks). The README admits the two facts separately (`Device tokens`: "does not yet compare
the token's device name"; `Limits`: the token can be read by the user); the measured result
is that together they flip deny to allow.

Smallest fix (service): set the device name from the device directory for the authenticated
actor and refuse a request whose `device` differs; accept an `os_account` claim for person
attribution only when the device has an active assignment for that person
(`AgentRegistry` already reads `assigned_people`), otherwise attribute "unknown person".
Pack: add Bash/PowerShell coverage for the token path to the deny list (a Bash-level guard
is a hint only; the real fix is the binding above, or a privileged local broker that holds
the token so the user cannot read it).

---

## M1. Pre-push uploads and sandbox runs ignore the kill switch and the integrity gate

Files: `src/ciso/api/deps.py:280-303` (`require_device` audits but never calls
`_writes_blocked`); `src/ciso/app/changes.py:99-129`; `src/ciso/app/sandbox_worker.py:225-252`.

Measured: with WRITES engaged through `POST /v1/killswitch/engage`, `POST /v1/changes`
answered 201 with a new change id, and `SandboxWorker.run_once()` leased the job and sent
the bundle to the (fake) sandbox. Decide itself answered `kill_switch_engaged`.

Spec rule 8 says the operator stop overrides everything; the same gate also signals a
start-up audit-integrity failure. Code still flows to a separate server and the database
takes writes.

Smallest fix: `/v1/changes` refuses with 503 `writes_blocked` while the gated reader blocks
WRITES (a `gated` flag on `require_device`, on for this route only); the worker checks the
gated reader before `lease` and before `run`, and idles while engaged. Test both.

---

## M2. Nothing on the server side ties the uploaded bundle and diff to `head` and `commits`

Files: `src/ciso/app/change_models.py` `ChangeUpload` (validates base64 and the bundle magic
only); `src/ciso/app/changes.py:231-240` (`SandboxInput` carries no head);
`services/sandbox/job.py` (`Job` has no expected head); the client builds the bundle and
the git output files in the user's `TEMP` (`hook_client.py:501, 719`).

Measured: the test bundle used in every probe (`tests/app/change_helpers.py:26`, header
naming `000...0 HEAD`) was accepted for an upload whose `head` is a different commit, and
the push reached `allow rule_allow` after the (fake) sandbox report. Read: the sandbox
scans whatever HEAD the bundle has, and the diff is scanned independently of the bundle.
So the integrity of "scanned == pushed" rests entirely on files the client writes into a
directory any process of the same user can rewrite while the hook runs (a background
process the agent started earlier can swap `change.bundle` between creation and read; not
measured).

Smallest fix: the service parses the bundle header and requires exactly the tip
`<head> refs/heads/aigov` (and `HEAD`), no prerequisites; send `head` and `commits` to the
sandbox, which checks `git rev-parse HEAD == head` and `git rev-list base..HEAD == commits`
after the clone and errors otherwise.

---

## M3. The client's diff honours `refs/replace` and repository or global diff configuration: the commit scan is "complete, clean" while the commit holds a secret

Files: `integrations/claude_code/client/hook_client.py:581-587` (prefix lacks
`--no-replace-objects` and output-shaping overrides; the user's global `~/.gitconfig` and
the repository config apply), `:648-654`, `:659-665`.

Sequence (measured, `revS2-replace_exp.py`, `revS2-git_exp.py` E3):
- `refs/replace`: stage `settings.py` with `<secret>`; control commit scan:
  `secret.assignment`. After `git replace <real blob> <benign blob>`: the commit scan shows
  `+DEBUG = False`, no findings, `complete: true`. The commit holds `<secret>`; the push
  scan diff is equally clean; the remote received the real blob. (`git replace` was denied;
  a Write of `.git/refs/replace/<sha>` was `ask`, measured.)
- `diff.relative=true` with the hook's `cwd` in a subdirectory: the push diff listed only
  `sub/ok.txt`; `creds.txt` with `<secret>` outside it was missing and there were no
  findings (`git config diff.relative true` was `ask`; the setting can also sit in the
  engineer's own global config).

A commit has no sandbox run, so for commits this is a full bypass of the content check.
For pushes the sandbox still sees the real objects unless H1 or H3 also applies.
(`.gitattributes -diff` was checked and held: the server marks the diff incomplete,
`inspection.binary_not_inspected`, measured.)

Smallest fix: add `--no-replace-objects` (or `GIT_NO_REPLACE_OBJECTS=1` after the
`GIT_*` strip), `GIT_CONFIG_GLOBAL` pointing at an empty file and `GIT_CONFIG_NOSYSTEM=1`,
`-c diff.relative=false -c diff.noprefix=false -c diff.mnemonicPrefix=false`, and run the
diff from `rev-parse --show-toplevel`. Test each.

---

## L1. The sandbox report's `job_id` is never compared with the change

Files: `src/ciso/app/sandbox_worker.py:247`; `src/ciso/inspection/sandbox.py`
`from_sandbox_report` (validates the shape of `job_id` only). Measured: a report naming
`some-other-job` was stored for the change as `done`. The call is synchronous, so a mix-up
needs a misbehaving sandbox or proxy; the fix is one comparison in the worker.

## L2. Fail-closed but sticky: a failed scan is returned for an identical retry, and a non-`CisoError` stops the worker

Files: `src/ciso/app/changes.py:105-108` (`_existing` returns the stored change whatever its
state; a change recorded `failed` after a sandbox outage keeps answering
`inspection_incomplete` for the same push in that session until retention ends);
`src/ciso/app/sandbox_worker.py:211-223` (only `CisoError` is caught; a database error from
`record_report` ends `run_forever`, and every push stays `checks_pending`). Read. Fix:
re-enqueue on an identical upload of a `failed` change; catch and log `Exception` per job.

## L3. One device can hold the single sandbox slot for the whole company

Files: `services/sandbox/app.py:120-122` (one job at a time, others 429);
`src/ciso/app/sandbox_client.py:88-89` (429 is `SandboxUnavailable`, retried, then
dead-lettered). A push whose tests run to the wall-time limit, repeated, makes other
engineers' jobs dead-letter and their pushes refused. Read. Fix: per-device fair queueing
before the sandbox, and treat 429 as "retry later" without spending an attempt.

## L4. Risk acceptance does not exclude the finding's own subject as approver

File: `src/ciso/app/risk_acceptance.py:79-103`. The requester and the accepting caller are
excluded; the person whose agent caused the finding is not, so an `executive_risk_owner`
can approve the acceptance of a risk their own agent created. Read. Fix: refuse when the
approval's `decided_by` resolves to the finding's person ref.

## L5. Pre-authentication rate limiting is per client address

File: `src/ciso/api/deps.py:145-157`. Behind a reverse proxy every engineer shares one
address; a flood of bad tokens fills that budget and every hook gets 429, which the client
turns into a block for everyone. Read. Fix: trust a configured proxy's forwarded address,
or keep the pre-auth budget per presented token hash as well.

## L6. Orphaned change files

File: `src/ciso/app/changes.py:120-122`. The encrypted file is written before the row; if
the insert fails, the file has no row and `purge` never deletes it (retention promise
broken). Read. Fix: write the row first in state `writing`, or delete the file on insert
failure.

## L7. Central gate replay memory is per process and keyed on `webhook-id`

Files: `src/ciso/intake/replay.py:228-250`, `src/ciso/app/governance_wiring.py:96`. Standard
Webhooks retries reuse the same id, so a platform retry after a slow answer is denied as
`replayed_message`; with several API worker processes a replay to another worker is
accepted and decided again (duplicate findings and audit). Read. Fix: shared replay store
in the database; on a repeat id return the stored verdict instead of a deny.

---

## Checked and held

- Decide never fails open: any exception in the pipeline becomes a deny with a fresh
  decision id (`governance_pipeline.py:212-220`). Measured incidentally: while the working
  tree's ruleset did not load, every probe answered `deny ruleset_unavailable`.
- Change references: unknown, foreign (other device or session), expired and mismatched
  (kind, remote, branch, source, head) ids are refused (`changes.py:195-214`); `change_id`
  and `change_head` are pattern-checked before the intake (`change_decide.py:68-82`).
- Push shape: chains, redirections, expansions, `-C`, option lists, refspec lists, bare
  `HEAD`, deletes, tags and force pushes give no `needs_change` (`change_shape.py`); git's
  own ref matching makes `main` ambiguous rather than silently a tag (read).
- `needs_change` is attached only when the sole reasons are the missing inspection.
- Sandbox report conversion is a closed, strict schema with size and count caps; a
  malformed report, an errored check or a missing or skipped required check is incomplete.
- Sandbox outages: unreachable, non-200, oversized or non-JSON answers are
  `SandboxUnavailable`, retried and finally `failed`, which decides as incomplete (deny).
- Client failure paths: not isolated, no configuration, bad URL, non-200, redirect
  (`_NoRedirect` -> `HTTPError` -> status check), oversized or malformed answer, unknown
  verdict, timeout, and a proxy without a trusted certificate (variant C above, measured)
  all block.
- Client git: `GIT_*` stripped; fsmonitor, hooks path, external diff, textconv and
  protocols overridden; a `-diff`/binary file makes the server diff incomplete (measured).
- Host name: `_CLUSTER_NETWORK_NAME_` does not change `socket.gethostname()` (measured).
- Device directory unreadable: 503; a person's token on decide: 403; a revoked device:
  refused (`deps.py:268-303`, `devices.py`).
- Central gate: body cap, signature before any parsing, constant-time compare, two
  spellings of a header refused, timestamp window, `request_id == webhook-id`, an unknown
  frame type allowed only after the signature held and the allow was audited.
- Sandbox container flags (`docker.py:48-103`): no network, read-only root, non-root user,
  all capabilities dropped, no-new-privileges, pid/cpu/memory caps, digest-pinned images,
  never pulled; archives: traversal, absolute and backslash names, links, devices, sparse
  files, duplicates, bombs and size limits refused (`archive.py`).
- Content and secrets out of logs, audit and errors: change audit details hold ids and
  counts only; error bodies are fixed per status; the sandbox client never logs the body
  or token; the change store encrypts diff and bundle (AES-GCM, key by reference).

## Suspicions (not proven)

- **Hook `cwd` vs the shell's directory.** The client builds the change in the payload's
  `cwd`. If Claude Code reports the session's start directory while the Bash tool's
  persisted shell has `cd`'d into another repository, the client scans one repository and
  the push runs in another. The service's head check cannot catch it: both the uploaded
  head and `change_head` come from the scanned repository. Needs one real-CLI run to see
  what `cwd` the hook receives after a `cd`.
- **C1 without any environment variable on Windows.** urllib reads the per-user registry
  proxy (`getproxies_registry`) and Python loads the Windows root stores, which include the
  current user's store (a user can add a root after one confirmation dialog). Not run: it
  changes the machine's registry and certificate store.
- **The push runs a different git.** The scan uses `AIGOV_GIT_PATH`; the agent's
  `git push` runs whatever `git` the shell resolves (PATH order, a shell function or alias
  from the user's shell profile captured into Claude Code's shell snapshot). Governance of
  profile writes is outside this scope.
- **Commands Claude Code runs outside PreToolUse** (`statusLine`, `apiKeyHelper`,
  `otelHeadersHelper`, project `.mcp.json` stdio servers). Writes of `.mcp.json` and under
  `.claude/` were denied (`critical_finding`, measured); whether user-level settings can
  still carry them under this pack was not checked against the CLI.
- **Central gate `tool_result` content as a list** of blocks (allowed by the platform's
  message format) is refused as malformed (`central_gate.py:279-291`): fail closed, but it
  may deny legitimate traffic.
- **Container runtime hardening** relies on Docker's default seccomp/AppArmor and a shared
  kernel; no user-namespace remap or gVisor-class runtime is configured.

## Not reviewed

- `src/ciso/governance`, `src/ciso/inspection`, `src/ciso/findings` internals and the
  provisional ruleset (other agent, mid-edit); `src/ciso/agents` matching internals beyond
  the measured attribution result; approvals, identity, authenticator, audit log and queue
  internals; `src/ciso/api/routers/approvals.py`, `external_inference.py`, `system.py`
  beyond route permissions.
- The real Claude Code CLI (how `env`, `cwd` and settings reach hooks), Docker itself,
  and the gitleaks and semgrep binaries (their behaviour above is from their documented
  configuration rules, not run).
- macOS and Linux packaging details (`.mobileconfig`, ADMX/registry form) beyond the JSON
  policies, and `build_pack.py` output beyond what `check_pack.py` enforces.

## Test run

`uv run pytest tests/app tests/api tests/e2e tests/integrations tests/services` on the
`git archive HEAD` copy (measured): 965 passed, 1 skipped, 1 failed. The failure,
`test_managed_pack.py::test_committed_artifacts_match_the_source`, compares bytes and failed
on CR vs LF from the archive extraction; the same file run in the real tree gave 25 passed
(measured). None of the findings above is covered by an existing test: every measured
sequence ran through the same code those suites exercise and reached the outcome described.
