"""The CISO skill's read-only tool: review, check, audit-setup, summary.

Run as the skill describes (`uv run --isolated <fixed flags> ... -- python -I -B <this
file> <subcommand> ...`). The plugin's runtime guard (`scripts/runtime_guard.py`, loaded
by its path) refuses any runtime that is not uv's own isolated environment before the
bundle is imported. Written for any Python 3 so an old interpreter reaches the message.
"""

import sys


def _main():
    if tuple(sys.version_info)[:2] < (3, 13) or not sys.flags.isolated:
        sys.stderr.write(
            "ciso_tool: needs Python 3.13+ started with -I (run it through uv as the skill says)\n"
        )
        return 1
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location(
        "_ciso_runtime_guard", root / "scripts" / "runtime_guard.py"
    )
    if spec is None or spec.loader is None:
        sys.stderr.write("ciso_tool: runtime guard missing\n")
        return 1
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    problem = guard.check_current()
    if problem:
        sys.stderr.write("ciso_tool: refused runtime (" + problem + "); run it through uv\n")
        return 1
    sys.path.insert(0, str(root / "lib"))
    if importlib.util.find_spec("pydantic") is None:
        sys.stderr.write("ciso_tool: pydantic is not installed (run it through uv)\n")
        return 1
    from ciso_plugin.tools.cli import run

    return run(sys.argv[1:], root, sys.stdout, sys.stderr)


if __name__ == "__main__":
    raise SystemExit(_main())
