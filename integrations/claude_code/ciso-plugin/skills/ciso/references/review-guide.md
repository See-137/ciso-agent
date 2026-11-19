# Review guide: what each finding means and how to fix it

The review tool runs the same deterministic inspector as the hooks. Each finding has a
rule id, a severity, a location (`file:line[:column]`) and a fixed remediation. It never
contains the secret or the content itself.

## Severity

| Severity | Meaning | What the hooks do with it |
|---|---|---|
| critical | Hands control of the machine, the assistant or the pipeline to someone else, or exposes a private key | Any action carrying it is denied |
| high | A live credential, or a well-known code-execution or injection pattern | A file write, edit, commit or push carrying a high secret is denied; a push or commit with any high finding is denied |
| medium | A weakening that needs a reason, or something that could not be inspected | Reported; an incomplete inspection blocks pushes and commits |
| low | Worth a look, rarely a problem on its own | Reported |

## Rule families

- `secret.*`: token shapes (private keys, cloud key ids, signed web tokens, bearer and
  basic credentials, service tokens with known prefixes, connection strings with
  passwords, literal values assigned to password/secret/token-like names) and long
  random values (`secret.high_entropy`, medium). Fix: remove the value, rotate the
  credential (treat it as exposed once it was written anywhere), load it from the secret
  store. Removing it in a later commit does not help once it is in history: rewrite the
  unpushed history or rotate.
- `path.*`: the file itself is sensitive: the assistant's own settings and instruction
  files, `.env` files, key files, cloud and registry credentials, CI pipelines, SSH
  access, editor auto-run files, git hooks. In a whole-repository review these findings
  say "this file is in a sensitive place", not that it was just written; check whether
  it belongs in the repository at all (key and env files never do).
- `suppression.*`: a change that blinds a scanner: scanner config or ignore files,
  `.gitattributes` lines that make files diff as binary or through a driver, inline
  "ignore" markers. Fix: remove the marker or the attribute and fix what the scanner
  reports; scanner settings belong to the security team.
- `code.*`: risky patterns in added lines: TLS verification off, `eval` of text, shell
  commands built from formatted strings, SQL built by string formatting, unsafe
  deserialisation, world-writable permissions, download piped to a shell, hard-coded
  hosts or IPs, wildcard CORS, debug mode on, suppressed security lint.
- `inspection.*`: coverage: content too large, lines too long, binary files, malformed or
  empty diffs. These make a push or commit count as not inspected, so it is held.
- `setup.*` (audit-setup only): see setup-audit.md.

## Writing up a review

1. One line with the scope and the counts by severity.
2. Critical and high findings first, each with `file:line`, what it is, the fix.
3. Repeated findings grouped ("4 suppression markers in scripts/hook_client.py").
4. What was not covered: binary and oversized files, encoded or split secrets, and
   tests (never run here; the optional sandbox add-on runs them).
5. The saved report path.
