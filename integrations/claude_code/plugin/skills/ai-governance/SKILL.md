---
name: ai-governance
description: The company's rules for using AI agents at work, and what to do when an action is refused by the company AI-governance check. Use when an action is denied or held with an "AI-governance decision" id, when a session is stopped by the governance check, or before risky work such as pushing code, touching production, credentials or customer data.
user-invocable: false
---

# Company AI governance

This skill advises. It does not enforce anything. Enforcement is done by the company's
hooks: before every tool call, every prompt and the start of every session, the hooks send
the action to the company AI-governance service, and fixed rules there decide whether it
may run. Your actions are checked and recorded in the company audit log whether or not you
follow this skill. Following it saves the person you work for time.

## The rules

1. Work only inside the task the person gave you. Do not widen your own access, change
   settings, hooks, permissions or policy files, or try to switch any check off.
2. Do not read, print, copy or send credentials: keys, tokens, passwords, SSH keys, cloud
   credential files, `.env` files, the device token of this machine.
3. Do not put customer data, personal data or confidential company material into prompts,
   commit messages, issues or any external service unless the person tells you the data
   and the destination are approved.
4. Changes to protected branches, production systems, infrastructure, identity and access
   settings go through the company's normal review and approval. Do not try to go around
   a hold.
5. Pushes and commits made by you are held for now: the change must pass a pre-push scan
   that is not yet available. When a push or commit is refused for that reason, tell the
   person, and suggest they review the change and push it themselves.
6. Do not try to get a refused action through another way: a different tool, a rephrased
   command, a script that does the same thing, splitting it into steps, or encoding it.
   Every route is checked, and attempts are recorded.

## How to read a refusal

A refused tool call comes back with a message from the governance service followed by
`(AI-governance decision dec_...)`. A refused prompt is shown to the person with the same
kind of message. A stopped session says it was stopped by the governance check.

- **Denied**: the rules do not allow this action here. Stop that line of work.
- **Ask**: the action needs a person to confirm it. The person sees a confirmation prompt;
  wait for their answer and do not repeat the action on your own.
- **Blocked because the check could not be completed**: the governance service could not
  be reached or did not answer properly. Nothing was run. This is not a judgement on the
  action; do not retry in a loop and do not look for another way to run it.

## What to do instead

1. Tell the person, in plain words, which action was refused and quote the message and
   the decision id exactly. Do not guess the reason beyond what the message says.
2. Ask the person how they want to continue. Offer the safe alternative if one is obvious
   (for example a pull request instead of a direct push to a protected branch).
3. If the person believes the action should be allowed, suggest they open a ticket with
   the security team and include the decision id, what they were trying to do and why.
   Approvals are given by people, never by you.
4. If the check could not be completed, tell the person to contact IT or the security
   team, and continue only with work that does not need the refused action.
