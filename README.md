# CISO agent for a Claude organization

A Claude Code plugin that acts as an organization's CISO agent: a skill that reviews code
and agent setups for security problems, and local hooks that decide every agent action
with fixed rules before it runs. No servers.

- Start with `docs/HANDOVER-CISO-AGENT.md` (what it is, how to install it, its limits).
- The plugin and its full reference: `integrations/claude_code/ciso-plugin/README.md`.
- An optional central server and sandbox add-on is in `src/ciso` and `services/sandbox`;
  it is not finished (see the handover).
