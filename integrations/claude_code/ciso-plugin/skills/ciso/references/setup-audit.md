# Agent setup audit: what is checked and the safer setting

| Rule | Where | Why it is risky | Safer setting |
|---|---|---|---|
| `setup.mcp_plain_http` | MCP server `url` with `http://` to a non-local host | Traffic and tokens can be read or changed on the way | `https://`, or remove the server |
| `setup.mcp_unpinned_package` | MCP server started through a package runner without a version | A new release of the package runs automatically, with your access | Pin the version (`pkg@1.2.3`, `pkg==1.2.3`) |
| `secret.*` in `env` / `headers` | MCP server definitions, settings `env` | A credential written in a settings file is readable by every program and often committed | Reference the secret store or the OS credential manager |
| `setup.broad_allow_rule` | `permissions.allow` with `Bash`, `Bash(*)`, `*` | The agent may run any shell command without asking | Allow named commands only |
| `setup.permission_mode` | `permissions.defaultMode` `bypassPermissions` / `dontAsk` | Prompts are off | Leave the default mode |
| `setup.disableallhooks` | `disableAllHooks: true` | Turns hooks off (organization hooks force-enabled by managed settings keep running, per the vendor documentation) | Remove it |
| `setup.enableallprojectmcpservers` | `enableAllProjectMcpServers: true` | Every MCP server a cloned repository defines is trusted | Approve servers one by one |
| `setup.hooks` | `hooks` in user or project settings | Commands run on this machine on every event | Review each command; organization hooks come from the plugin |
| `setup.apikeyhelper` | `apiKeyHelper` | A program supplies credentials | Confirm IT approved it |
| `setup.statusline` | `statusLine` | A command runs on every refresh | Review it |
| `setup.instruction_risk` | `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`, `.cursorrules`, `.cursor/rules/*` | Text that tells an agent to ignore instructions, pipe downloads to a shell, skip checks or disable hooks (a prompt-injection or a weakening) | Remove the instruction; instruction files are reviewed like code |
| `setup.unreadable_config` | Any of the above | Cannot be reviewed | Fix the file |

`--home` adds `~/.claude/settings.json`, `~/.claude.json` (only its MCP server
definitions are read) and `~/.claude/CLAUDE.md`. Values are scanned, never printed.
Organization-managed settings are not audited by this tool; they are owned by IT.
