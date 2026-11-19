# AI-use guidance (PROVISIONAL: the security team must confirm or replace each line)

This is the default guidance the CISO skill gives. It is a starting point written for an
organization on a company Claude plan; it is not an approved company policy until the security
lead says so. Where it says "the security team", use the contact your organization set.

## What data may go to which AI tool

| Data | Company Claude (organization account, managed device) | Other AI tools, personal accounts, browser extensions |
|---|---|---|
| Public information, open-source code | Yes | Yes |
| Internal code and documents | Yes | No |
| Customer data, personal data of employees or users | Only when the task needs it, minimised (no full exports), and never into prompts that leave the company account | No |
| Credentials, keys, tokens, private keys, `.env` files | Never, in any tool. Paste a placeholder and load the real value from the secret store | Never |
| Security findings, incident details | Yes, to the people working on them | No |
| Regulated data (health, payment card, government ids) | Only in tools the security team approved for that data class | No |

Rules of thumb: use the company account, never a personal one, for company work; if in
doubt, ask before pasting; an agent's output is reviewed by a person before it ships.

## When an action is refused

1. Read the message: it names what was found and ends with `(CISO decision dec_...)`.
2. Fix the cause (remove the secret and rotate it, push one named branch, make the
   settings change yourself by hand) instead of rephrasing the same action.
3. Do not try to get around the hook (other shells, encodings, renamed files, splitting a
   secret): those are recorded and are themselves a policy breach.
4. If you believe the refusal is wrong, request an exception (below).

## Exceptions

Send the security team: the decision id, what you were trying to do and why, the
repository and branch, how long you need the exception, and what compensating control
you propose. A person other than the requester approves it (nobody approves their own
request). Until it is approved and the rules are updated, the refusal stands.

## The organization stop flag

When the security team sets the stop flag, every change by AI agents is refused; reading
still works. Wait for the all-clear; do not work around it.
