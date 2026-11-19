# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pydantic==2.14.0",
#     "pydantic-core==2.50.0",
#     "typing-extensions==4.16.0",
#     "annotated-types==0.8.0",
#     "typing-inspection==0.4.5",
# ]
# ///
"""The CISO skill's read-only tool: review, check, audit-setup, summary.

Run as the skill describes (`uv run ... -- python -I -B <this file> <subcommand> ...`).
Written for any Python 3 so an old interpreter reaches the message below.
"""

import sys


def _main():
    if tuple(sys.version_info)[:2] < (3, 13) or not sys.flags.isolated:
        sys.stderr.write(
            "ciso_tool: needs Python 3.13+ started with -I (run it through uv as the skill says)\n"
        )
        return 1
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root / "lib"))
    import importlib.util

    if importlib.util.find_spec("pydantic") is None:
        sys.stderr.write("ciso_tool: pydantic is not installed (run it through uv)\n")
        return 1
    from ciso_plugin.tools.cli import run

    return run(sys.argv[1:], root, sys.stdout, sys.stderr)


if __name__ == "__main__":
    raise SystemExit(_main())
