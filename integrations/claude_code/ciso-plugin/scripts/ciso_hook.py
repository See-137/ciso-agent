"""Enforcing hook of the CISO agent plugin (PreToolUse for every tool, UserPromptSubmit).

Run by `hooks/hooks.json` as `uv run --isolated <fixed flags> --with-requirements
scripts/runtime-requirements.txt -- python -I -B <this file>`. Before anything from the
bundle is imported, `scripts/runtime_guard.py` (loaded by its path) refuses a runtime that
is not uv's own isolated environment (review H1). Then it hands over to `lib/ciso_plugin`.
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


def _guard(folder):
    import importlib.util

    path = folder / "runtime_guard.py"
    spec = importlib.util.spec_from_file_location("_ciso_runtime_guard", path)
    if spec is None or spec.loader is None:
        return "runtime guard missing"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check_current()


def _main():
    if tuple(sys.version_info)[:2] < (3, 13):
        return _refuse("Python older than 3.13")
    if not sys.flags.isolated:
        return _refuse("interpreter not started in isolated mode -I")
    from pathlib import Path

    here = Path(__file__).resolve().parent
    problem = _guard(here)
    if problem:
        return _refuse(problem)
    sys.path.insert(0, str(here.parent / "lib"))
    import importlib.util

    if importlib.util.find_spec("pydantic") is None:
        return _refuse("pydantic is not installed")
    from ciso_plugin.hookio import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_main())
