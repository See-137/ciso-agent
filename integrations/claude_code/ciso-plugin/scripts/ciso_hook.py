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
"""Enforcing hook of the CISO agent plugin (PreToolUse for every tool, UserPromptSubmit).

Run by `hooks/hooks.json` as `uv run ... -- python -I -B <this file>`: uv provides Python
3.13+ and the pinned packages above (PEP 723 inline metadata); `-I` keeps the user's
environment (PYTHONPATH, PYTHONSTARTUP, user site, the working directory) out of the
interpreter. This file only checks the runtime and hands over to `lib/ciso_plugin`.
Written for any Python 3 so an old interpreter reaches the message below.
"""

import sys

RUNTIME_MESSAGE = (
    "CISO plugin: blocked because the security check has no usable runtime ({0}). "
    "IT must install uv (https://docs.astral.sh/uv/) and let it provide Python 3.13 or "
    "later with the plugin's pinned packages (network access to the package index on first "
    "use, or a pre-filled uv cache); see the plugin README, 'Machine requirements'.\n"
)


def _refuse(reason):
    sys.stderr.write(RUNTIME_MESSAGE.format(reason))
    return 2


def _main():
    if tuple(sys.version_info)[:2] < (3, 13):
        return _refuse("Python older than 3.13")
    if not sys.flags.isolated:
        return _refuse("interpreter not started in isolated mode -I")
    from pathlib import Path

    lib = Path(__file__).resolve().parent.parent / "lib"
    sys.path.insert(0, str(lib))
    import importlib.util

    if importlib.util.find_spec("pydantic") is None:
        return _refuse("pydantic is not installed")
    from ciso_plugin.hookio import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_main())
