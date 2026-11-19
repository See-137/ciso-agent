"""Build the CISO agent plugin's bundled engine, rules, managed templates and apps zip.

The plugin (`integrations/claude_code/ciso-plugin/`) runs the SAME governance engine,
inspector and hook intake as the service, with no server. This script copies them, it
never forks them:

- `lib/ciso/...`: every module of `ciso.governance`, `ciso.inspection`, the hook intake
  (`ciso.intake`), and `ciso.app.change_shape` / `ciso.app.change_decide`, plus exactly the
  modules they import (computed from the source with `ast`, never listed by hand). Each
  file is a byte-for-byte copy. The one exception is `ciso/app/__init__.py`, which in the
  source wires the whole service; the bundle gets the fixed stub `APP_INIT_STUB` instead.
- `rules/governance-ruleset.json`: the deployment ruleset
  (`config/governance-ruleset.provisional.json`) plus `PLUGIN_ADDITIONS`: the assistant's
  own credential files (review M6) and the folders uv runs the hook from (review H1),
  which the vendor-neutral core may not name. Patterns are only ever added.
- `lib/BUNDLE.json`: what was copied, from where, with SHA-256 of each file.
- `integrations/claude_code/managed-plugin/<platform>/managed-settings.json`: generated
  from `managed-plugin/source.json` (see that folder's README).
- `--zip PATH`: the skill alone, as the zip a Claude apps organization uploads.

Run from the repository root:

    uv run python tools/build_ciso_plugin.py            # write the bundle and templates
    uv run python tools/build_ciso_plugin.py --check    # exit 1 if anything differs
    uv run python tools/build_ciso_plugin.py --zip dist/ciso-skill.zip

`--check` also imports the bundle in a separate isolated interpreter (`-I`, only `lib/` on
the path) to prove the copy is complete. Stale files the bundle no longer needs are
reported, never deleted: remove them by hand.
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

ROOT: Final = Path(__file__).resolve().parent.parent
SRC: Final = ROOT / "src"
PLUGIN: Final = ROOT / "integrations" / "claude_code" / "ciso-plugin"
MANAGED: Final = ROOT / "integrations" / "claude_code" / "managed-plugin"
RULESET_SOURCE: Final = ROOT / "config" / "governance-ruleset.provisional.json"
RULESET_TARGET: Final = Path("rules") / "governance-ruleset.json"
MANIFEST: Final = Path("lib") / "BUNDLE.json"

#: Patterns ADDED to the deployment ruleset's lists in the plugin's ruleset.
PLUGIN_ADDITIONS: Final[dict[str, tuple[str, ...]]] = {
    # Review M6: the assistant's login and account files (authentication docs: the
    # `.credentials.json` file in the configuration folder, the `~/.claude.json` account
    # and MCP file, and the platform SDK's profile folder). The generic
    # `**/.credentials.json` is in the core's built-in list.
    "credential_paths": (
        "**/.claude.json",
        "**/.claude/.credentials.json",
        "**/.config/anthropic/**",
        "**/AppData/Roaming/Anthropic/**",
    ),
    # Review H1: the uv cache and uv-managed Python folders the hook runs from. An agent
    # write there would run before every hook check.
    "agent_config_paths": (
        "**/AppData/Local/uv/**",
        "**/AppData/Roaming/uv/**",
        "**/.cache/uv/**",
        "**/.local/share/uv/**",
        "**/Library/Caches/uv/**",
    ),
}
PLUGIN_VERSION_SUFFIX: Final = ".plugin"

#: Modules the plugin imports. Their import closure is bundled.
ENTRY_MODULES: Final = (
    "ciso.governance",
    "ciso.inspection",
    "ciso.intake",
    "ciso.intake.hook",
    "ciso.app.change_shape",
    "ciso.app.change_decide",
)
#: Package files replaced by a fixed stub, because the source wires the whole service.
APP_INIT_STUB: Final = (
    '"""Bundled subset of `ciso.app` for the CISO agent plugin: only `change_shape` and\n'
    "`change_decide` are copied (tools/build_ciso_plugin.py). The service's composition\n"
    'root is not part of the plugin."""\n'
)
STUBS: Final[dict[str, str]] = {"ciso.app": APP_INIT_STUB}
#: Third-party packages the bundle may import. Anything else fails the build.
ALLOWED_THIRD_PARTY: Final = frozenset({"pydantic", "pydantic_core"})
PLATFORMS: Final = ("windows", "macos", "linux")
#: The skill folder copied into the apps zip, and the apps variant of its SKILL.md.
SKILL_DIR: Final = PLUGIN / "skills" / "ciso"
APPS_SKILL_MD: Final = PLUGIN / "apps-skill" / "SKILL.md"
#: Fixed timestamp for zip entries, so the zip is reproducible.
ZIP_TIME: Final = (2026, 1, 1, 0, 0, 0)


class BuildError(Exception):
    pass


def _module_file(module: str) -> Path | None:
    base = SRC.joinpath(*module.split("."))
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    if base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    return None


def _imports(module: str, path: Path) -> tuple[set[str], set[str]]:
    """(ciso modules, third-party top-level names) imported by one file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    found: set[str] = set()
    external: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                anchor = ".".join(parts[: len(parts) - node.level + 1])
                base = f"{anchor}.{base}" if base else anchor
            names = [base]
            names += [f"{base}.{alias.name}" for alias in node.names]
        for name in names:
            if name.split(".")[0] == "ciso":
                if _module_file(name) is not None:
                    found.add(name)
            elif name and name.split(".")[0] not in sys.stdlib_module_names:
                external.add(name.split(".")[0])
    return found, external


def closure(entries: Iterable[str] = ENTRY_MODULES) -> list[str]:
    """Every ciso module the entries need, with their parent packages. Sorted."""
    seen: set[str] = set()
    stack = list(entries)
    while stack:
        module = stack.pop()
        if module in seen:
            continue
        seen.add(module)
        parts = module.split(".")
        stack.extend(".".join(parts[:i]) for i in range(1, len(parts)))
        if module in STUBS:
            continue
        path = _module_file(module)
        if path is None:
            raise BuildError(f"module not found in src: {module}")
        found, external = _imports(module, path)
        unknown = external - ALLOWED_THIRD_PARTY
        if unknown:
            raise BuildError(
                f"{module} imports a package the plugin cannot ship: {sorted(unknown)}"
            )
        stack.extend(found - seen)
    return sorted(seen)


def _relative(module: str) -> Path:
    path = _module_file(module)
    if path is None:
        raise BuildError(f"module not found in src: {module}")
    return Path("lib") / path.relative_to(SRC)


def bundle_files() -> dict[Path, bytes]:
    """Plugin-relative path -> exact bytes, for the engine copy and the ruleset."""
    files: dict[Path, bytes] = {}
    for module in closure():
        target = _relative(module)
        if module in STUBS:
            files[target] = STUBS[module].encode("utf-8")
        else:
            files[target] = (SRC / target.relative_to("lib")).read_bytes()
    files[RULESET_TARGET] = plugin_ruleset(RULESET_SOURCE.read_bytes())
    manifest = {
        "generated_by": "tools/build_ciso_plugin.py",
        "entry_modules": list(ENTRY_MODULES),
        "stubs": sorted(STUBS),
        "ruleset_source": RULESET_SOURCE.relative_to(ROOT).as_posix(),
        "files": {
            path.as_posix(): hashlib.sha256(data).hexdigest()
            for path, data in sorted(files.items())
        },
    }
    files[MANIFEST] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return files


def plugin_ruleset(source: bytes) -> bytes:
    """The deployment ruleset with `PLUGIN_ADDITIONS` appended (never removed)."""
    data = json.loads(source.decode("utf-8"))
    for key, extra in PLUGIN_ADDITIONS.items():
        current = list(data.get(key, []))
        data[key] = current + [p for p in extra if p not in current]
    data["version"] = str(data["version"]) + PLUGIN_VERSION_SUFFIX
    data["description"] = (
        str(data["description"])
        + " CISO agent plugin copy (tools/build_ciso_plugin.py): plus the plugin's "
        "additions to credential_paths and agent_config_paths."
    )
    text = json.dumps(data, indent=2, ensure_ascii=False) + chr(10)
    return text.encode("utf-8")


# --- managed settings templates --------------------------------------------------------


def managed_templates() -> dict[Path, bytes]:
    """`managed-plugin/<platform>/managed-settings.json` from `managed-plugin/source.json`.

    The source holds `common` (keys every platform gets) and `platforms.<name>` (the
    admin-owned paths). `env` blocks are merged, platform last; the git hardening pairs
    become `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`.
    """
    source = json.loads((MANAGED / "source.json").read_text(encoding="utf-8"))
    out: dict[Path, bytes] = {}
    for name in PLATFORMS:
        platform = source["platforms"][name]
        settings: dict[str, Any] = json.loads(json.dumps(source["common"]))
        env: dict[str, str] = dict(settings.get("env", {}))
        env.update(platform.get("env", {}))
        pairs = [*source["git_hardening"], ["core.hooksPath", platform["empty_hooks_dir"]]]
        env["GIT_CONFIG_COUNT"] = str(len(pairs))
        for index, (key, value) in enumerate(pairs):
            env[f"GIT_CONFIG_KEY_{index}"] = key
            env[f"GIT_CONFIG_VALUE_{index}"] = value
        settings["env"] = dict(sorted(env.items()))
        text = json.dumps(settings, indent=2, ensure_ascii=False) + "\n"
        out[Path(name) / "managed-settings.json"] = text.encode("utf-8")
    return out


# --- apps zip --------------------------------------------------------------------------


def apps_zip_entries() -> dict[str, bytes]:
    """Zip member -> bytes: `ciso/SKILL.md` (the apps variant) and `ciso/references/*`.

    The scripts are left out: the bundled engine needs Python 3.13+ and pydantic, and the
    documented code execution container is Python 3.11 with neither (README, "Claude apps").
    """
    entries = {"ciso/SKILL.md": APPS_SKILL_MD.read_bytes()}
    for path in sorted((SKILL_DIR / "references").glob("*.md")):
        entries[f"ciso/references/{path.name}"] = path.read_bytes()
    return entries


def write_zip(target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(apps_zip_entries().items()):
            info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)


# --- check and write --------------------------------------------------------------------


def _existing(root: Path, sub: str) -> set[Path]:
    base = root / sub
    if not base.exists():
        return set()
    return {
        p.relative_to(root) for p in base.rglob("*") if p.is_file() and "__pycache__" not in p.parts
    }


def differences(plugin: Path = PLUGIN, managed: Path = MANAGED) -> list[str]:
    """Every way the tree differs from what the build would write. Empty means current."""
    problems: list[str] = []
    wanted = bundle_files()
    for rel, data in sorted(wanted.items()):
        path = plugin / rel
        if not path.is_file():
            problems.append(f"missing: {rel.as_posix()}")
        elif path.read_bytes() != data:
            problems.append(f"differs from source: {rel.as_posix()}")
    expected = set(wanted)
    for rel in sorted(_existing(plugin, "lib/ciso") | _existing(plugin, "rules")):
        if rel not in expected:
            problems.append(f"not part of the bundle (remove it by hand): {rel.as_posix()}")
    for rel, data in sorted(managed_templates().items()):
        path = managed / rel
        if not path.is_file() or path.read_bytes() != data:
            problems.append(f"managed template stale: {rel.as_posix()}")
    return problems


def isolated_import_problem(plugin: Path = PLUGIN) -> str | None:
    """Import the bundle in a fresh `-I` interpreter with only `lib/` added to the path.
    Returns None when every entry module loads from the bundle."""
    lib = str(plugin / "lib")
    code = (
        "import sys, importlib, pathlib\n"
        f"lib = pathlib.Path({lib!r}).resolve()\n"
        "sys.path.insert(0, str(lib))\n"
        f"for name in {list(ENTRY_MODULES)!r}:\n"
        "    mod = importlib.import_module(name)\n"
        "    where = pathlib.Path(mod.__file__).resolve()\n"
        "    assert lib in where.parents, (name, str(where))\n"
        "print('bundle-import-ok')\n"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, this interpreter
        [sys.executable, "-I", "-B", "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if done.returncode != 0 or "bundle-import-ok" not in done.stdout:
        tail = (done.stderr or done.stdout).strip().splitlines()[-1:]
        return "isolated import failed: " + (tail[0] if tail else "no output")
    return None


def write_all(plugin: Path = PLUGIN, managed: Path = MANAGED) -> list[str]:
    for rel, data in bundle_files().items():
        path = plugin / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for rel, data in managed_templates().items():
        path = managed / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return [p for p in differences(plugin, managed) if p.startswith("not part of")]


def main(argv: list[str]) -> int:
    args = argv[1:]
    try:
        if args == ["--check"]:
            problems = differences()
            problem = isolated_import_problem()
            if problem:
                problems.append(problem)
            for line in problems:
                sys.stderr.write(line + "\n")
            sys.stdout.write("bundle current\n" if not problems else "bundle STALE\n")
            return 0 if not problems else 1
        if len(args) == 2 and args[0] == "--zip":
            write_zip(Path(args[1]))
            sys.stdout.write(f"wrote {args[1]}\n")
            return 0
        if args:
            sys.stderr.write("usage: build_ciso_plugin.py [--check | --zip PATH]\n")
            return 2
        for line in write_all():
            sys.stderr.write(line + "\n")
        sys.stdout.write("bundle written\n")
        return 0
    except BuildError as error:
        sys.stderr.write(f"build failed: {error}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
