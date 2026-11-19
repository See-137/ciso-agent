"""Table-driven checks of one program and its arguments. No nesting, no recursion.

`check_program` looks at the normalized program name and the literal argument texts and
says which classes they show. Nested code (`sh -c`, `cmd /c`, script blocks) is read by
`ciso.governance.analysis`, which calls this for every simple command it finds.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from ciso.governance import programs as p
from ciso.governance.classes import CommandClass as C
from ciso.governance.env_vars import assignment_classes, variable_classes
from ciso.governance.lexer_types import DYN
from ciso.governance.safe_options import is_read_only_invocation

_SETID_SYMBOLIC = re.compile(r"[ugoa]*[+=][rwxXt]*s[rwxXt]*")
_SETID_OCTAL = re.compile(r"0?[2467][0-7]{3}")
_PS_RECURSE = "-recurse"


class ProgramFacts(NamedTuple):
    classes: frozenset[C]
    network: bool = False
    decoder: bool = False
    read_only: bool = False


def _positionals(args: list[str]) -> list[str]:
    return [a for a in args if a and not a.startswith(("-", "/"))]


def _recursive_delete(name: str, args: list[str]) -> bool:
    for raw in args:
        arg = raw.casefold()
        if arg == "--recursive":
            return True
        if arg.startswith("/") and "s" in arg.strip("/").split("/") and name != "ri":
            return True
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            body = arg[1:]
            if _PS_RECURSE.startswith(arg) or (body.isalpha() and "r" in body):
                return True
    return False


def _security_target(args: list[str]) -> bool:
    joined = " ".join(args).casefold()
    return any(f in joined for f in p.SECURITY_SERVICE_FRAGMENTS) or "msmpeng" in joined


def _tamper(name: str, args: list[str]) -> bool:
    low = [a.casefold() for a in args]
    joined = " ".join(low)
    checks = (
        name in p.TAMPER_ALWAYS,
        name in ("set-mppreference", "add-mppreference"),
        name == "netsh"
        and "firewall" in joined
        and any(v in low for v in ("off", "disable", "delete", "reset")),
        name in ("set-netfirewallprofile", "disable-netfirewallrule", "remove-netfirewallrule"),
        name == "ufw" and any(v in low for v in ("disable", "reset")),
        name in ("iptables", "ip6tables", "nft")
        and any(v in low for v in ("-f", "--flush", "-x", "flush", "accept")),
        name == "auditctl" and ("-d" in low or ("-e" in low and "0" in low)),
        name == "wevtutil" and any(v in low for v in ("cl", "clear-log", "sl", "set-log")),
        name == "auditpol" and any(v in joined for v in ("/clear", "/remove", "disable")),
        name == "history" and "-c" in low,
        name == "unset" and any(v.startswith("hist") for v in low),
        name in ("export", "declare", "typeset", "set")
        and any(v.startswith("hist") and (v.endswith("=0") or "/dev/null" in v) for v in low),
        name == "set" and "+o" in low and "history" in low,
        name == "set-psreadlineoption" and "savenothing" in low,
        name == "bcdedit" and "/set" in low,
        name == "reg" and any(f in joined for f in ("defender", "disableantispyware", "eventlog")),
        name == "mpcmdrun" and "-removedefinitions" in low,
        name in p.SERVICE_CONTROLLERS
        and (name in p.SERVICE_STOP_VERBS or any(v in p.SERVICE_STOP_VERBS for v in low))
        and _security_target(args),
        name in ("kill", "pkill", "killall", "taskkill", "stop-process") and _security_target(args),
    )
    return any(checks)


def _privilege(name: str, args: list[str]) -> bool:
    low = [a.casefold() for a in args]
    pos = _positionals(low)
    groups = {g for a in low for g in a.split(",")}
    checks = (
        name in p.PRIVILEGE,
        name == "chmod"
        and any(_SETID_SYMBOLIC.fullmatch(a) or _SETID_OCTAL.fullmatch(a) for a in low),
        name == "chown"
        and bool(pos)
        and (pos[0].startswith("root") or pos[0].split(":")[0] == "0"),
        name in ("usermod", "gpasswd", "adduser", "useradd") and bool(groups & p.PRIVILEGE_GROUPS),
        name == "net" and "/add" in low and ("localgroup" in low or "user" in low),
        name == "icacls" and any(a in ("/grant", "/setowner") for a in low),
        name in ("start-process", "saps") and "runas" in low,
        name in ("docker", "podman", "nerdctl")
        and any(
            a in ("--privileged", "--pid=host") or a.startswith(("/:", "--volume=/:")) for a in low
        ),
    )
    return any(checks)


def _package(name: str, args: list[str]) -> bool:
    low = [a.casefold() for a in args]
    pos = _positionals(low)
    if name in p.PACKAGE_ALWAYS:
        return True
    if name in p.PACKAGE_SUBCOMMANDS:
        if not pos:
            return name in p.INSTALL_WITHOUT_ARGS
        return pos[0] in p.PACKAGE_SUBCOMMANDS[name]
    options = p.PACKAGE_OPTIONS.get(name)
    return options is not None and any(a in {o.casefold() for o in options} for a in low)


def _credential(name: str, args: list[str]) -> bool:
    low = [a.casefold() for a in args]
    pos = _positionals(low)
    joined = " ".join(low)
    checks = (
        name in p.CREDENTIAL_PROGRAMS,
        name in p.CREDENTIAL_SUBCOMMANDS and bool(pos) and pos[0] in p.CREDENTIAL_SUBCOMMANDS[name],
        any(f in joined for f in p.CREDENTIAL_WORD_FRAGMENTS),
        any(f in joined for f in p.ENV_DUMP_WORD_FRAGMENTS),
        name == "reg"
        and bool(pos)
        and pos[0] in ("save", "export")
        and any(h in joined for h in ("hklm\\sam", "hklm\\security", "hklm\\system")),
        name == "printenv" and (not pos or any(p.SECRET_VARIABLE_RE.fullmatch(a) for a in pos)),
        name == "set" and not args,
        name in ("export", "declare", "typeset") and (not args or set(low) <= {"-p", "-x", "-px"}),
        any(a.lstrip("$").startswith("env:") for a in low),
        name == "jq" and _jq_reads_environment(args),
    )
    return any(checks)


_JQ_ENV_RE = re.compile(r"(?<![\w.])\$?env(?![\w])", re.IGNORECASE)
_JQ_ARG_OPTIONS = frozenset({"--arg", "--argjson", "--args", "--jsonargs"})


def _jq_reads_environment(args: list[str]) -> bool:
    """`env`, `$ENV`, or a variable's value handed in with `--arg` (review H2)."""
    if any(_JQ_ENV_RE.search(a) for a in args):
        return True
    return any(
        DYN in value
        for i, a in enumerate(args)
        if a in _JQ_ARG_OPTIONS
        for value in args[i + 1 : i + 3]
    )


def _decoder(name: str, args: list[str]) -> bool:
    low = [a.casefold() for a in args]
    if name in p.DECODER_ALWAYS:
        return True
    if name == "openssl":
        return "-d" in low and any(a in ("base64", "-base64", "-a", "enc") for a in low)
    options = p.DECODER_OPTIONS.get(name)
    return options is not None and any(a in {o.casefold() for o in options} for a in low)


def _network(name: str, args: list[str]) -> bool:
    low = [a.casefold() for a in args]
    if name in p.NETWORK:
        return True
    if name == "certutil":
        return any(a in ("-urlcache", "/urlcache", "-verifyctl") or "://" in a for a in low)
    return name == "python" and any(a in ("http.server", "simplehttpserver") for a in low)


def _destructive(name: str, args: list[str]) -> bool:
    low = [a.casefold() for a in args]
    if name in p.DESTRUCTIVE_ALWAYS or name.startswith("mkfs"):
        return True
    if name in p.DELETERS:
        return _recursive_delete(name, args)
    if name == "dd":
        return any(a.startswith("of=/dev/") for a in low)
    if name == "rsync":
        return any(a.startswith("--delete") for a in low)
    return name == "find" and "-delete" in low


def _container(name: str) -> bool:
    return name in p.CONTAINER_VM or name.startswith(p.CONTAINER_VM_PREFIXES)


def _environment(name: str, args: list[str]) -> set[C]:
    """`export`, `set`, `setx` and friends that set a variable for later commands."""
    found: set[C] = set()
    if name in (
        "export",
        "declare",
        "typeset",
        "local",
        "readonly",
        "set",
        "setx",
        "set-item",
        "set-variable",
        "sv",
    ):
        for arg in args:
            if "=" in arg and not arg.startswith("-"):
                found |= assignment_classes(arg)
        positional = _positionals(args)
        if name in ("setx", "set-item", "set-variable", "sv") and positional:
            found |= variable_classes(positional[0])
    return found


def check_program(name: str, args: list[str]) -> ProgramFacts:
    """Classes shown by `name` with literal arguments `args`."""
    found: set[C] = set()
    network = _network(name, args)
    if network:
        found.add(C.NETWORK_TRANSFER)
    rules = (
        (_destructive(name, args), C.DESTRUCTIVE_DELETE),
        (_privilege(name, args), C.PRIVILEGE_ESCALATION),
        (_package(name, args), C.PACKAGE_INSTALL),
        (_container(name), C.CONTAINER_OR_VM_CONTROL),
        (_tamper(name, args), C.SECURITY_TOOL_TAMPER),
        (_credential(name, args), C.CREDENTIAL_ACCESS),
    )
    found |= {cls for hit, cls in rules if hit}
    found |= _environment(name, args)
    low = [a.casefold() for a in args]
    if any(f in a for a in low for f in p.NETWORK_WORD_FRAGMENTS):
        found.add(C.NETWORK_TRANSFER)
        network = True
    decoder = _decoder(name, args) or any(f in a for a in low for f in p.DECODER_WORD_FRAGMENTS)
    read_only = not found and is_read_only_invocation(name, args)
    return ProgramFacts(frozenset(found), network, decoder, read_only)
