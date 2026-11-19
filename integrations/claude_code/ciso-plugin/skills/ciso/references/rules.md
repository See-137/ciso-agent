# The rules the hooks apply

The hooks run the organization's governance engine and its ruleset on this machine
(`rules/governance-ruleset.json` in the plugin). This page restates them for people;
the file is what decides. Every rule is provisional until the security team confirms it.

## Always denied (built in, no rule can relax them)

- Any action while the organization stop flag is set, except reads and prompts.
- Any action whose content holds a **critical** finding (for example a private key, or
  a write to the assistant's own settings, hooks, plugins or instruction files).
- Changing the agent's own configuration: `.claude/**`, `CLAUDE.md`, `.mcp.json`,
  `.claude.json` and similar.
- Disabling or weakening security tools (antivirus, firewall, logging, history).
- Any decision that cannot be made or recorded (rules unreadable, identity unreadable,
  audit log unwritable, a crashed or timed-out hook).

## Denied for employee-operated agents

- Reading or copying credentials (keys, tokens, `.env` files, credential stores,
  environment dumps).
- Running code fetched from the network (download piped to a shell).
- Raising privilege (`sudo`, `runas`, adding administrators, privileged containers).
- Obfuscated commands (decoded payloads, encoded commands) and variables that choose
  what code runs.
- Force pushes and history rewrites on protected branches (`main`, `master`,
  `release/*`, `prod*`; a branch that cannot be told counts as protected).
- File writes, edits, commits and pushes whose content has a high-severity secret; pushes
  and commits with any high finding.
- Pushes and commits that cannot be scanned: anything but one plain `git push <remote>
  <branch>` or `git commit -m <message>`; repositories whose git settings redirect or
  widen a push, or that run their own hooks during it; more than 1000 commits; binary
  changes.

## Need the person's confirmation (ask)

Pushes to protected branches, force pushes to any branch, network transfers from the
shell, package installs and package runners, recursive deletes, bulk copies or archive
extraction into the working tree, and anything no rule covers (most file writes, most
non-read-only shell commands, connector calls, web fetches, sub-agents).

## Allowed

- Reads (Read, Grep, Glob), prompts, and shell commands made only of known read-only
  programs with safe options, for the person logged in to this device.
- A plain push of one named non-protected branch whose commits were scanned and found
  clean.
- Loading this skill and running its read-only tool in the exact documented form.

## What "allowed" does not mean

Allowed by the hook means only "not refused by policy"; Claude Code's own permission
prompts still apply. The hook reads the text of a command, not what it does once it
runs; that is why pushes are scanned and why the optional sandbox add-on exists.
