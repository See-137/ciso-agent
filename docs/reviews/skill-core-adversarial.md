# Adversarial review: skill core (governance, inspection, attribution, findings)

Date: 2026-11-19

Scope: `src/ciso/governance/` (lexer, POSIX and PowerShell/cmd readings, program and option
tables, git argv rules, dangerous paths, loader, matcher, engine, `rulesets/default.json`),
`src/ciso/inspection/`, `src/ciso/agents/`, `src/ciso/findings/`, and their tests. Out of
scope: `src/ciso/app`, `src/ciso/api`, `integrations/` (being edited by another agent).

Method: read every in-scope module, then attacked it as a prompt-injected agent that knows
the rules. Each finding was proven by importing the real code and calling
`classify_command`, `GovernanceEngine.decide` (default ruleset, a known employee, declared
attribution, `target.branch=feature`), `AgentRegistry.attribute` (in-memory database, real
admin bindings) or `Inspector.inspect`. Where the claim is about what a shell or git does,
the shell or git was run locally on this machine (Windows 11, Git Bash 5.3.15, Windows
PowerShell 5.1, git) with a harmless marker payload. Throwaway scripts live in the session
scratchpad under `revS1-*`; no file under `src/` or `tests/` was changed. Targeted suites:
`uv run pytest tests/governance tests/inspection tests/agents tests/findings` = 875 passed
(measured), i.e. none of the findings below is covered by an existing test.

Attack strings are described with placeholders (`<cmd>`, `<download>`, `<shell>`), never as
working lines.

"Measured" = I ran it and saw the result. "Read" = concluded from source, not executed.

## The one fact behind the critical findings

`read_only_command` is the only class an allow rule accepts for a shell command
(`allow-read-only-shell-known-people`). Anything that can make the classifier say
`read_only_command` while the real shell runs code is a full allow of arbitrary execution,
for employee-operated and organizational agents alike. C1-C4 are four independent ways.

---

## C1. Bash `[[ ... -eq ... ]]` runs code through an array subscript, and `[[` is a "reader"

- File: `src/ciso/governance/safe_options.py:92` (`"[[": SafeSpec(...)`, letters include
  `e`,`q`,`l`,`t`,`g`,`n`, so `-eq/-ne/-lt/-le/-gt/-ge` pass as options).
- What breaks: in `[[ A -eq B ]]` bash evaluates both operands as arithmetic expressions.
  An operand of the form `<name>[<command-substitution>]`, even inside single quotes,
  expands its subscript and runs the substitution. Single quotes hide the substitution from
  the lexer, so no `subs` are recorded and the stage is a reader with safe options.
- Sequence: `[[ '<name>[$(<cmd>)]' -eq 0 ]]` (backtick form works too).
- Measured: classifier `['read_only_command']`; engine verdict `allow`
  (`allow-read-only-shell-known-people`) for employee and organizational agents; Git Bash
  5.3 printed the marker from `<cmd>` and exited 0.
- Smallest fix: remove `[[` from `SAFE` (it is never needed for an agent to read anything).
  Keep `test`/`[` only if a test pins that their arithmetic operators do not evaluate (bash's
  `test` does not; `[[` does). Regression test: the sequence above must not be
  `read_only_command`.

## C2. PowerShell double-quoted here-string body is never parsed

- File: `src/ciso/governance/shell_lexer.py:651` (`here_string` adds the body as literal
  text for both `@'` and `@"`).
- What breaks: in PowerShell `@"`...`"@` expands `$(<cmd>)`. The Windows reading records no
  substitution. The POSIX reading would see `$(`, but prefixing it with a backslash makes
  POSIX read `\$` as a literal dollar, while PowerShell treats `\` as an ordinary character
  and still runs the subexpression.
- Sequence: `Write-Output @"` NEWLINE `\$(<any PowerShell>)` NEWLINE `"@`.
- Measured: classifier `['read_only_command']`; engine `allow`; Windows PowerShell 5.1 ran
  the marker. With the payload `Remove-Item -Recurse ...` the result is still `allow`.
- Smallest fix: in `here_string`, when the quote is `"`, scan the body: if it contains `$(`
  (or `$` followed by `{`), raise `HiddenCommand` (or parse the subexpressions as
  `windows_double` does). Test with the backslash-prefixed form.

## C3. PowerShell honours Unicode "smart" quotes; the lexer does not

- File: `src/ciso/governance/shell_lexer.py:562-650` (`windows_char`/`windows_double`
  only know ASCII `'` and `"`); same gap in `posix_char`.
- What breaks: PowerShell tokenizes U+2018-U+201B as single quotes and U+201C-U+201E as
  double quotes. Both lexer readings treat them as ordinary letters. Wrapping an ASCII `'`
  in curly double quotes makes PowerShell see a one-character string and then real
  statements, while both lexer readings see one long single-quoted word.
- Sequence: `Write-Output <U+201C>'<U+201D> ; <any statement> ; <U+201C>'<U+201D>`.
- Measured: classifier `['read_only_command']` for a marker payload and for a recursive
  `Remove-Item`; engine `allow`; PowerShell 5.1 (UTF-8 with BOM script) ran the marker.
- Smallest fix: in both dialects, any of U+2018-U+201E (and the Unicode dashes of M2)
  outside a quoted region raises `ParseError`, so the command is never read-only. Better:
  in the Windows reading map them to their ASCII quote before reading.

## C4. "Read-only" git runs code from repository-controlled config (`git -C`, `cd`)

- Files: `src/ciso/governance/git_argv.py:203` (`_globals_read_only` keeps `-C <dir>`),
  `src/ciso/governance/safe_options.py` (`GIT_SAFE` `diff`/`log`/`show`, `cd` is a reader).
- What breaks: a directory holding `HEAD`, `config`, `objects/`, `refs/` is a bare
  repository to git (default `safe.bareRepository=all`). Its `config` is not named
  `.git/config`, so writing or committing it raises no class; it can also arrive in a cloned
  repo (the embedded-bare-repo pattern). `diff.external`, a textconv driver or
  `core.fsmonitor` in it makes `git diff` / `git show` / `git status` run a program.
- Sequence: repo contains `<dir>/{HEAD,config,objects,refs}` with `diff.external=<program>`;
  agent runs `git -C <dir> diff <a> <b>` or `cd <dir>; git diff <a> <b>`.
- Measured: both commands classify `['read_only_command']`, engine `allow`; locally,
  `git -C <bare copy> diff main~1 main` ran the configured program (marker printed).
- Smallest fix: `-C`, and `cd` followed by git in the same command, make git not
  read-only. The managed policy pack (C1) should also set `safe.bareRepository=explicit`
  and the hook should run with `GIT_CONFIG_NOSYSTEM`-style hardening; record that as an ADR
  item, since the classifier cannot see config content.

---

## H1. Credential-path checks are literal text: globs, Windows aliases and `cd` defeat them

- Files: `src/ciso/governance/analysis.py:186` (`path`), `src/ciso/governance/globs.py:110`
  (`normalize_path` does not undo trailing dots/spaces, streams or short names).
- What breaks: the shell expands globs, Windows strips trailing dots and spaces and
  resolves 8.3 names (this machine has `SSH~1` for `.ssh`, `CLAUDE~1` for `.claude`,
  measured with `dir /x`), and a preceding `cd` changes what a relative name means. None of
  these reach the pattern matcher.
- Sequences (all measured `read_only_command`, engine `allow` for an employee agent):
  `cat ~/.ss[h]/id_rs[a]`; `cat ~/.ss?/id_*`; `grep -r . ~/.ss[h]`;
  `Select-String -Path ~/.ss[h]/* -Pattern .`; `rg --hidden --no-ignore . ~/.ss?`;
  `cat .en[v]`; `type .git-credentials.`; `cd ~/.docker; cat config.json`. Control: the
  literal `cat ~/.ssh/id_rsa` is `deny` (measured). `git diff --no-index` on the globbed key
  gives no class (ask).
- Also uncovered by the list at all (read): gcloud `application_default_credentials.json`,
  `~/.config/gh/hosts.yml`, Azure token caches, `credentials.tfrc.json`; inspection's own
  list (`paths.py`) has several of them, governance's (`danger_paths.py`) does not.
- Smallest fix: (1) reuse `ciso.inspection.paths.normalise_path` rules (trailing dot/space,
  `:stream`, `\\?\`) in `globs.normalize_path`; (2) a path argument containing `*?[` or a
  segment matching `~[0-9]` is matched as a pattern against the danger patterns
  (segment-wise "could these two globs meet") or simply makes the stage not read-only;
  (3) `cd` together with any other stage makes the command not read-only; (4) align the
  two credential lists.

## H2. Environment secrets are readable through "readers"

- Files: `src/ciso/governance/danger_paths.py` (no `environ`), `safe_options.py:99` (`jq`),
  `argv_checks.py` `_credential` (`env:` prefix only), `analysis.py:303` (secret-variable
  check only for `PRINTERS`).
- Sequences, all measured `read_only_command` and engine `allow`:
  `cat /proc/self/environ`; `jq -n env`; `jq -n '$ENV'`;
  `Get-ChildItem Microsoft.PowerShell.Core\Environment::` (measured in PowerShell: lists
  all variables); `ls "$<SECRET_VAR>"` (the error message prints the value);
  `Get-Item $env:<SECRET_VAR>`. Control: `gci env:` and `echo $<SECRET_VAR>` are caught.
- Smallest fix: add `/proc/**/environ` to `CREDENTIAL_PATHS`; drop `jq` from `SAFE` or
  refuse read-only when the filter mentions `env`/`$ENV`/`input_filename`; add
  `environment::` to the env-dump fragments; apply `SECRET_VARIABLE_RE` to the variables of
  every program's arguments, not only printers.

## H3. An employee's agent can become an approved organizational agent by adding claims

- File: `src/ciso/agents/attribution.py:81-96` (`matches`, `match_agent`),
  `src/ciso/agents/registry.py` (`facts = keys | device`).
- What breaks: agent facts are matched against every claim the session sent, verified or
  not, plus the device the source reports. A session that adds the organizational agent's
  facts (an `api_key` id, the build host's device name) matches it. Organizational agents
  have no operator check, and every deny rule for credentials, remote scripts, privilege
  escalation and obfuscation names only `employee_operated` and `unknown`.
- Sequence: Alice's session sends `os_account=<alice>` plus `api_key=<release bot key id>`
  (unverified) with `target.device=<build host>`.
- Measured: attribution `actor:act_alice`, `organizational`, `declared`, no reasons.
  Engine with `organizational`: `cat ~/.ssh/id_rsa` and `<download> | <shell>` both become
  `ask` (they are `deny` for an employee agent). Findings are filed under the bot's
  `agent_ref`.
- Smallest fix: only verified claims (and a device the service itself observed) satisfy an
  agent fact; an organizational agent must require at least one verified fact; a session
  that shows another agent's facts alongside a bound person claim gets
  `agent_ambiguous`.

## H4. Reusing another person's session id inherits their attribution

- File: `src/ciso/agents/registry.py:110-117` and `_decide`.
- What breaks: attribution is keyed only by the `session_id` the action carries, and claims
  accumulate per session. An action with Bob's session id and no claims is attributed to
  Bob. A different device adds `session_device_changed`, but the state is not lowered and no
  rule reads that reason.
- Measured: Bob's session first sends a verified claim; a later action with the same session
  id, no claims and another device gets `actor:act_bob`, state `verified`, reasons
  `['session_device_changed', ...]`. In the engine that is a known person for every allow
  rule. Session ids appear in transcript paths and hook payloads.
- Smallest fix: a device change sets the state to `disputed` (deny for non-reads), or at
  least caps it at `inferred` so allow rules miss; and record in the intake ADR that a
  session must be bound to the authenticated channel that opened it (intake is out of scope).

## H5. Protected-branch push detection: short destination names and implied destinations

- File: `src/ciso/governance/git_argv.py:101` (only `refs/heads/` is stripped).
- What breaks: git resolves a destination like `heads/main` through its `refs/%s` rule to
  `refs/heads/main`. The classifier compares `heads/main` against `main`, `release/*`,
  `prod*` and finds no protected branch. Separately, `git push` / `git push origin` with no
  refspec takes the hook's `target.branch` (current branch) as the destination, although
  `push.default=upstream`, an upstream set to `main`, or `remote.<n>.push` can send it to
  `main`.
- Measured: local git, `git push <bare> HEAD:heads/main` moved `main` of the remote.
  Classifier: `git push -f origin HEAD:heads/main` gives `git_force_push, git_push`,
  branches `['heads/main']`, no `git_push_protected_ref`; with a clean, complete inspection
  the engine says `ask` (the same push to `HEAD:main` is `deny`). `git push -f` with
  `target.branch=feature`: `ask`.
- Smallest fix: normalise the destination by stripping `refs/heads/`, then `heads/`; any
  remaining destination that contains `/` and does not match a known branch pattern, or
  starts with `refs/` outside `refs/heads/`, counts as unknown (protected). A push with no
  explicit destination is unknown unless the source reports the resolved upstream, not the
  current branch.

## H6. Remote and computed code execution downgraded from deny to ask

- Files: `src/ciso/governance/wrappers.py:276-302` (`_posix_shell`), `_script`,
  `p.EVALUATORS`, `analysis.py` `interpreter`.
- Sequences, all measured with only `network_transfer` (or `git_config_change`), engine
  `ask` where `<download> | <shell>` is `deny`:
  `<download> | bash /dev/stdin`; `<download> | python3 /dev/stdin`;
  `<download> | node /dev/stdin`; `<download> | xargs -0 sh -c` (and a base64 decode piped
  the same way gives no class at all); `<download to a>; mv a b; sh b`;
  `icm -ScriptBlock ([scriptblock]::Create((<iwr>).Content))`;
  `& ([scriptblock]::Create(<WebClient download string>))`;
  `git -c alias.x='!<download> | sh' x`.
- Smallest fix: script arguments `/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`, `-` mean
  `reads_stdin`; an interpreter after `xargs` reads its code from stdin; add
  `invoke-command`, `icm`, `start-job`, `sajb` and the `[scriptblock]::create` fragment as
  evaluators (computed code); `git -c alias.<x>=!<code>` and `core.sshCommand`/`core.pager`
  values go through `nested`.

---

## M1. The agent-configuration invariant is literal-only and inconsistent with inspection

- Files: `src/ciso/governance/analysis.py:186`, `globs.py:110`,
  `src/ciso/inspection/paths.py` (separate list and separate normaliser).
- What breaks: `ALWAYS_DENIED` (`agent_config_change`) needs the literal path. Measured:
  file_write paths `.mcp.json.`, `.mcp.json::$DATA`, `proj/.claude/settings.json ` (trailing
  space) and `C:/Users/u/CLAUDE~1/settings.json` give no governance class (inspection
  catches the first three as critical, so a content-carrying file_write is still denied by
  invariant 5; a shell redirect is not inspected for paths). Shell measured with no class
  (`ask`): `echo x > .mcp.json.`, `echo x > ~/CLAUDE~1/settings.json`,
  `cd .claude && echo x > settings.json`, `cp x .mc[p].json`, `cp -r <dir>/. .`,
  `tar -xf <archive>`. The two lists also disagree (governance flags any
  `.<dir>/settings.json` and `AGENTS.md`; inspection flags `CLAUDE.md` and `.claude/**`).
- Impact: the invariant becomes an ordinary `ask`; a person approving sees a harmless looking
  command.
- Smallest fix: one shared normaliser (inspection's) and one shared list; treat `~[0-9]`
  segments, glob characters and directory/archive/checkout targets as "may touch" (not
  read-only, and `agent_config_change` when the target directory is a parent of a listed
  path).

## M2. PowerShell accepts Unicode dashes for parameters; the classifier does not

- Files: `argv_checks.py` (`startswith("-")` everywhere), `wrappers.py` `_ps_param`,
  `_start_process`.
- Measured: PowerShell 5.1 ran `Get-ChildItem <en-dash>Path . <en-dash>Filter ...` as
  parameters. Classifier: `Remove-Item <en-dash>Recurse <en-dash>Force <path>` gives no
  class (should be `destructive_delete`); `Start-Process <en-dash>Verb RunAs cmd` and
  `powershell <en-dash>enc <b64>` give only `unparseable` (so `ask`, not the
  privilege/obfuscation deny).
- Smallest fix: in the Windows reading, map U+2013, U+2014, U+2015 at the start of a word to
  `-` before analysis.

## M3. `unparseable` is ask, but the ruleset says it is a built-in invariant

- Files: `src/ciso/governance/engine.py:196`, `rulesets/default.json` `description`.
- What breaks: the description lists "unparseable commands" among invariants that "apply
  before these rules and cannot be relaxed", but the engine only turns an allow into an ask.
  Any construct that defeats both readings (M2, a here-document under the Windows reading
  plus a POSIX parse error, etc.) reaches a human as an ordinary question with every danger
  class dropped. Also `commands.py` reports neither `unparseable` nor `read_only` when only
  one reading fails, which hides the danger the failing reading would have found.
- Smallest fix: decide it and write it down (ADR): either deny unparseable shell commands
  for `employee_operated`/`unknown` agents in the engine, or correct the description. Add a
  test either way.

## M4. Secret scanner misses common real secrets

- File: `src/ciso/inspection/secret_scan.py:146` (`_KEY_WORDS`), `:164`
  (`_PLACEHOLDER_WHOLE`).
- Measured (file_write, complete result, no finding): `DB_PASS=<value>`,
  `SIGNING_KEY=<value>`, `password = "my-<value>"`, `password: env-<value>`,
  `password=$<value>` (any value starting with `$`), a bare assignment in a `.py` file,
  a YAML block-scalar password, a lower-cased cloud key id, a service token split over two
  added lines or two concatenated string literals. Caught: plain token shapes, JSON
  `client_secret`, base64 and reversed tokens (as `high_entropy`, medium only).
- Impact: with `missing_inspection=deny` the result is still `complete=True`, so a commit
  carrying these passes the secret rule. Against an agent that encodes on purpose no line
  scanner wins; this is why S5's sandbox step matters, but the misses above are not
  adversarial, they are ordinary config.
- Smallest fix: add `pass`, `pwd`, `[a-z_]*_key` (signing, encryption, master, hmac) to the
  key words; drop `my-`/`your-`/`env...`/bare `$name` from whole-value placeholders unless
  the value is exactly that shape with nothing else; case-insensitive cloud key prefix.

## M5. Unverified ("declared") attribution satisfies every allow rule; `verified` is sender-asserted

- Files: `rulesets/default.json` (`attribution_states: ["verified", "declared"]` on both
  allow rules), `src/ciso/common/activity.py` `IdentityClaim.verified`,
  `src/ciso/agents/attribution.py` `decide_person`.
- Measured: a claim `os_account=<bob>` with `verified=true` from a device that is not Bob's
  gives `actor:act_bob`, `verified` (capped to `inferred` only when the device matches a
  registered employee agent of someone else). Whether the intake strips `verified` from hook
  posts is in `src/ciso/api` (not reviewed).
- Smallest fix: the attribution layer, not the intake, decides `verified`: accept it only
  for claim kinds configured as issuer-verified (for example the central gate's account) and
  ignore it otherwise; consider `verified` only for shell allow rules.

---

## L1. The subject of a finding can quiet its future alerts

- Files: `src/ciso/findings/rules.py` `may_transition`, `models.py` `ACTIVE_STATUSES`,
  `service.py` `_fold`.
- Read: the person may acknowledge their own finding; `acknowledged` stays active, so later
  occurrences with the same fingerprint fold into it and a HIGH/CRITICAL inspection finding
  raises no new severe alert (only a before-phase deny still alerts).
- Fix: when folding into an `acknowledged` finding at HIGH or worse, raise a
  `severe_finding` alert again (or reopen it).

## L2. Inspection's sensitive-path list lacks key-planting and other assistants' files

- File: `src/ciso/inspection/paths.py`.
- Measured: `.ssh/authorized_keys`, `.vscode/settings.json`, `.cursor/rules/*`,
  `.github/copilot-instructions.md`, `AGENTS.md` produce no inspection finding (governance
  flags some of them).
- Fix: fold into the shared list of M1.

---

## Checked and held

Measured:
- `cat ~/.ssh/id_rsa` deny; `<download> | bash` deny (`remote_script_execution`);
  `git push -f origin HEAD:main` deny; `gci env:` and `echo $<SECRET_VAR>` give
  `credential_access`; `[ '<name>[$(<cmd>)]' -eq 0 ]` is read-only but harmless (bash
  `test` does not evaluate); a plain `$(<cmd>)` in a PowerShell here-string without the
  backslash is seen by the POSIX reading; `git -c alias.c=commit c` gives
  `git_config_change`; `cp x .mcp.json` gives `agent_config_change`.
- Attribution: conflicting bound claims give `disputed`; an unknown agent is recorded as
  `observed`/`unknown`; an employee agent used by another person gives
  `operator_mismatch` and `inferred`.
- Inspection: binary changes and malformed diffs make the result incomplete; plain token
  shapes, JWTs, private key headers and connection strings are found.

Read (not executed):
- Lexer: unquoted here-document with substitution, `${..$(..)}`, `$((..$(..)..))`,
  process substitution, `${IFS}` (obfuscation), ANSI-C quoted command names (obfuscation),
  dynamic command names (unparseable), cmd caret inside a command name (obfuscation),
  `%VAR:~x,y%` names reach the secret-variable check, CRLF handled as whitespace.
- Interpreters: `sh -c`, `cmd /c`, `powershell -Command`, `-EncodedCommand` and its
  prefixes and `/` form decoded and re-read, `python -c` scanned, `find -exec`, `rg --pre`,
  `sort --compress-program`, `tar --to-command`, `source -`, `bash <(<download>)`,
  `bash -c "$(<download>)"`.
- Git: `-c`/`--config-env` set config-change (hooks keys add hooks change), `--no-verify`,
  rewrite subcommands, `+`/`:` refspecs, `--force-with-lease`, combined `-fu`, `--all`,
  `--mirror`, wildcard destinations, remote URL in place of a name.
- Rules: loader refuses duplicate keys, BOM-only differences, deep nesting, oversize files
  (deny-all); allow rules must name kinds and trusted states; unknown facts never satisfy
  an allow and always satisfy a restriction; strictest effect wins; restrictive patterns
  compare case-insensitively; `defaults.other` cannot be allow; kill switch and disputed
  attribution deny non-reads; an inspection for another action id is ignored.
- Diff parser: stray lines outside hunks after the first file are refused; hunk counts are
  enforced; text after `-- ` is skipped the same way `git apply` skips it.
- Findings: list/summary/alerts need admin or auditor; `get` by a non-admin needs the
  finding's person to equal the caller's linked person (person-less findings are
  admin-only); `list_own` refuses a caller-supplied `person_ref`; only admins make
  transitions other than acknowledge; closed findings never absorb new occurrences.

## Suspicions (not proven)

- `.gitattributes` `filter=` with a configured clean filter can run on `git status` / `git
  diff` (read-only commands); same root cause as C4, not executed.
- Other Unicode whitespace (no-break space, U+2028) as PowerShell separators; `#`/`<# #>`
  comments are not modelled in the Windows reading (over-reports today, but may desync with
  future fixes).
- The intake redacts the command before classification (`ObservedAction.command`); a
  redaction that rewrites part of a command could change its class. Intake not reviewed.
- `target.branch`, `target.path`, `target.device` are source claims trusted by the engine
  and the registry; a hook that misreports them changes protected-branch and device logic.
- Decision findings for shell commands have an empty location, so all denies of one check
  by one person in one repository fold into one finding; alerting still fires per deny.

## Not reviewed

- `src/ciso/inspection/sandbox.py` and `src/ciso/inspection/code_scan.py` beyond a skim.
- `src/ciso/agents/admin.py` concurrency (`tests/agents/test_race.py` exists).
- Alert delivery retries in `src/ciso/findings/alerts.py`.
- Everything in `src/ciso/app`, `src/ciso/api`, `integrations/` (out of scope), including
  how the hook builds `identity_claims`, `verified` and the diff it sends.
