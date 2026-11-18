#!/usr/bin/env python3
"""Build the per-platform managed settings artifacts from ``pack_source.json``.

Usage: ``python3 build_pack.py [<source.json> [<out_dir>]]`` (defaults: the
``pack_source.json`` next to this file, written into this directory).

Writes, in the formats and for the locations the vendor documents
(https://code.claude.com/docs/en/managed-settings.md, "Where each mechanism stores the
policy"):

- ``linux/managed-settings.json``   -> /etc/claude-code/managed-settings.json
- ``macos/managed-settings.json``   -> /Library/Application Support/ClaudeCode/managed-settings.json
- ``macos/com.anthropic.claudecode.mobileconfig``  configuration profile, domain
  com.anthropic.claudecode, same top-level keys
- ``windows/managed-settings.json`` -> C:\\Program Files\\ClaudeCode\\managed-settings.json
- ``windows/ClaudeCode-policy.reg`` -> HKLM\\SOFTWARE\\Policies\\ClaudeCode, REG_SZ ``Settings``

The output is deterministic, so a test can prove the committed files match the source.
Run ``check_pack.py`` afterwards. Standard library only.
"""

from __future__ import annotations

import importlib.util
import json
import plistlib
import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent

ARTIFACTS = (
    "linux/managed-settings.json",
    "macos/managed-settings.json",
    "macos/com.anthropic.claudecode.mobileconfig",
    "windows/managed-settings.json",
    "windows/ClaudeCode-policy.reg",
)
PROFILE_NAMESPACE = uuid.UUID("6f1d8a52-3c4e-4b7a-9d1e-2a5c7e9b0f13")


def _checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_aigov_check_pack_for_build", HERE / "check_pack.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("check_pack.py not found next to build_pack.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolves the module by name
    spec.loader.exec_module(module)
    return module


def json_bytes(policy: dict[str, Any]) -> bytes:
    return (json.dumps(policy, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def reg_bytes(policy: dict[str, Any]) -> bytes:
    """A version 5 .reg file (UTF-16 LE with BOM) holding the policy as one REG_SZ."""
    compact = json.dumps(policy, separators=(",", ":"), ensure_ascii=False)
    escaped = compact.replace("\\", "\\\\").replace('"', '\\"')
    lines = [
        "Windows Registry Editor Version 5.00",
        "",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\ClaudeCode]",
        f'"Settings"="{escaped}"',
        "",
    ]
    return "\ufeff".encode("utf-16-le") + "\r\n".join(lines).encode("utf-16-le")


def profile_bytes(policy: dict[str, Any]) -> bytes:
    """A configuration profile with one payload for the com.anthropic.claudecode domain."""
    payload: dict[str, Any] = {
        "PayloadType": "com.anthropic.claudecode",
        "PayloadIdentifier": "com.corp.aigovernance.claudecode.settings",
        "PayloadUUID": str(uuid.uuid5(PROFILE_NAMESPACE, "payload")).upper(),
        "PayloadVersion": 1,
        "PayloadDisplayName": "Claude Code managed settings",
        **policy,
    }
    profile = {
        "PayloadType": "Configuration",
        "PayloadIdentifier": "com.corp.aigovernance.claudecode",
        "PayloadUUID": str(uuid.uuid5(PROFILE_NAMESPACE, "profile")).upper(),
        "PayloadVersion": 1,
        "PayloadDisplayName": "Company AI governance: Claude Code",
        "PayloadDescription": "Claude Code policy enforced by the company AI-governance programme.",
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": True,
        "PayloadContent": [payload],
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True)


def build(source: dict[str, Any]) -> dict[str, bytes]:
    """Every artifact, keyed by its path relative to the pack directory."""
    checker = _checker()
    policies = {
        platform: checker.merge_platform(
            source["policy"], source["platform_env"][platform], source["platform_deny"][platform]
        )
        for platform in ("windows", "macos", "linux")
    }
    return {
        "linux/managed-settings.json": json_bytes(policies["linux"]),
        "macos/managed-settings.json": json_bytes(policies["macos"]),
        "macos/com.anthropic.claudecode.mobileconfig": profile_bytes(policies["macos"]),
        "windows/managed-settings.json": json_bytes(policies["windows"]),
        "windows/ClaudeCode-policy.reg": reg_bytes(policies["windows"]),
    }


def main(argv: list[str]) -> int:
    source_path = Path(argv[1]) if len(argv) > 1 else HERE / "pack_source.json"
    out_dir = Path(argv[2]) if len(argv) > 2 else HERE
    source = json.loads(source_path.read_text(encoding="utf-8"))
    for relative, data in build(source).items():
        target = out_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        sys.stdout.write(f"wrote {target}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
