"""The CISO skill's read-only tools (`skills/ciso/scripts/ciso_tool.py`).

They read files, git history, configuration and the plugin's own logs, and print
findings: rule, severity, location, fixed remediation. They never print file content,
command text, prompts, environment values or secrets. The only file they write is a
report under the plugin's data directory, when `--data-dir` is given.
"""
