"""Keyword scan of code handed to a script interpreter (`python -c`, `node -e`...).

The code is not a shell command, so it is not parsed; it is searched, case-insensitively,
for fragments that open a network connection, decode data, or run code. A decoder or a
download together with something that runs code means the code builds its own payload.
"""

from __future__ import annotations

from ciso.governance.classes import CommandClass as C

_NETWORK = (
    "urllib",
    "requests.",
    "http.client",
    "socket",
    "fetch(",
    "http.get",
    "https.get",
    "net::http",
    "open-uri",
    "lwp::",
    "io::socket",
    "webclient",
    "invoke-webrequest",
    "xmlhttprequest",
    "curl",
    "wget",
)
_DECODE = ("b64decode", "base64", "frombase64", "atob(", "unpack(", "decode('hex", "codecs.decode")
_RUN = (
    "exec(",
    "eval(",
    "os.system",
    "subprocess",
    "child_process",
    "popen",
    "system(",
    "spawn(",
    "compile(",
    "__import__",
    "`",
)


def scan_code(code: str) -> set[C]:
    """Classes shown by interpreter code text. Never raises."""
    low = code.casefold()
    network = any(f in low for f in _NETWORK)
    decode = any(f in low for f in _DECODE)
    runs = any(f in low for f in _RUN)
    found: set[C] = set()
    if network:
        found.add(C.NETWORK_TRANSFER)
    if runs and network:
        found.add(C.REMOTE_SCRIPT_EXECUTION)
    if runs and decode:
        found.add(C.OBFUSCATION)
    return found
