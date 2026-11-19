"""Refuse a hook or tool runtime that anything outside uv's own environment could steer.

Loaded by file path from `ciso_hook.py` and `ciso_tool.py` BEFORE anything from the
bundle is imported (review H1). Standard library only. The interpreter must:

1. be Python 3.13+ started with `-I` (no PYTHONPATH, user site or working directory);
2. run inside an environment uv created in its cache (`<cache>/builds-v0/...` or
   `<cache>/archive-v0/...`, the cache folder marked by `CACHEDIR.TAG`), not a project or
   user virtual environment;
3. import only from the base interpreter's standard library (never its `site-packages`)
   or from that uv cache: every other `sys.path` entry refuses;
4. have no `.pth` file in those uv folders except the two uv writes itself
   (`_virtualenv.pth` = `import _virtualenv`, `_uv_ephemeral_overlay.pth` adding uv cache
   folders only), and no `sitecustomize` / `usercustomize` loaded.

What this cannot do: a `.pth` that ends the process runs before any Python code of the
plugin, so it is kept out by uv's `--isolated` flag (the hook argv), not here; code edited
inside the uv cache itself (it is in the user's folder) is not detected (README, "Known
limits").
"""

import os
import re
import sys
from pathlib import Path

CACHE_KINDS = ("builds-v0", "archive-v0")
UV_PTH = "_uv_ephemeral_overlay.pth"
VENV_PTH = "_virtualenv.pth"
_ADDSITEDIR = re.compile(r'site\.addsitedir\("((?:[^"\\]|\\.)*)"\)')
_OVERLAY = re.compile(r'import site;(?:\s*site\.addsitedir\("(?:[^"\\]|\\.)*"\);?)+\s*')
#: Largest .pth file read.
MAX_PTH_BYTES = 64 * 1024


def _norm(path):
    try:
        return os.path.normcase(str(Path(path).resolve()))
    except (OSError, ValueError):
        return None


def _inside(child, parent):
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


def uv_cache_root(prefix):
    """The uv cache folder holding the environment at `prefix`, or None."""
    path = Path(prefix)
    for folder in [path, *path.parents]:
        if folder.name in CACHE_KINDS and (folder.parent / "CACHEDIR.TAG").is_file():
            return folder.parent
    return None


def _is_stdlib(entry, base):
    parts = {p.casefold() for p in Path(entry).parts}
    return _inside(entry, base) and not parts & {"site-packages", "dist-packages"}


def _pth_problem(path, allowed):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_PTH_BYTES + 1)
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return "unreadable .pth file"
    if len(raw) > MAX_PTH_BYTES:
        return "oversized .pth file"
    name = os.path.basename(path)
    if name == VENV_PTH and text.strip() == "import _virtualenv":
        return None
    if name == UV_PTH and _OVERLAY.fullmatch(text):
        for raw_dir in _ADDSITEDIR.findall(text):
            folder = _norm(raw_dir.replace("\\\\", "\\"))
            if folder is None or not any(_inside(folder, root) for root in allowed):
                return "uv overlay points outside the uv cache"
        return None
    return "unexpected .pth file " + name


def runtime_problem(prefix, base_prefix, entries, modules, isolated, version):
    """None when the runtime is acceptable, else a short reason (no paths in it)."""
    if tuple(version)[:2] < (3, 13):
        return "Python older than 3.13"
    if not isolated:
        return "interpreter not started in isolated mode -I"
    if "sitecustomize" in modules or "usercustomize" in modules:
        return "a sitecustomize or usercustomize module was loaded"
    cache = uv_cache_root(prefix)
    if cache is None:
        return "not running in an environment uv created (start it through uv as declared)"
    allowed = [_norm(cache / kind) for kind in CACHE_KINDS]
    allowed = [a for a in allowed if a is not None]
    base = _norm(base_prefix)
    if base is None:
        return "base interpreter folder unreadable"
    for entry in entries:
        if not entry:
            return "the working directory is on the import path"
        norm = _norm(entry)
        if norm is None:
            return "an import path cannot be resolved"
        if any(_inside(norm, root) for root in allowed):
            if os.path.isdir(norm):
                for name in sorted(os.listdir(norm)):
                    if name.endswith(".pth"):
                        problem = _pth_problem(os.path.join(norm, name), allowed)
                        if problem:
                            return problem
            continue
        if not _is_stdlib(norm, base):
            return "an import path outside uv's environment and the standard library"
    return None


def check_current():
    """`runtime_problem` for this interpreter."""
    return runtime_problem(
        sys.prefix,
        sys.base_prefix,
        list(sys.path),
        set(sys.modules),
        bool(sys.flags.isolated),
        sys.version_info,
    )
