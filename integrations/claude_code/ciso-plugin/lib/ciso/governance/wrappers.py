"""Programs that run other programs: wrappers (`sudo`, `env`, `xargs`, `wsl`...) and code
runners (shells, `cmd`, PowerShell, script interpreters, `eval`, `iex`, `source`).

Both functions work on literal argument texts and return positions, never run anything.
"""

from __future__ import annotations

from typing import NamedTuple

from ciso.governance import programs as p
from ciso.governance.classes import CommandClass as C
from ciso.governance.env_vars import assignment_classes
from ciso.governance.shell_lexer import Dialect


class Wrapped(NamedTuple):
    classes: frozenset[C]
    #: The words after the wrapper that form the wrapped command (a suffix of the args).
    rest: tuple[str, ...]
    #: Command strings the wrapper runs, with the dialect to read them in.
    code: tuple[tuple[str, Dialect], ...] = ()
    #: The wrapper only looks something up (`command -v x`).
    read_only_stop: bool = False
    #: The wrapper runs a command even when `rest` is empty (it came from `code`).
    runs_command: bool = False
    #: The wrapper changes the environment of what it runs (`env`): never read-only.
    never_read_only: bool = False


class InterpreterParts(NamedTuple):
    kind: str  # "shell" (read code as commands) or "script" (scan code text)
    dialect: Dialect
    code_indexes: tuple[int, ...] = ()
    extra_code: str = ""
    script_index: int | None = None
    encoded: str | None = None
    reads_stdin: bool = False
    evaluator: bool = False
    classes: frozenset[C] = frozenset()
    #: Re-read as another program from this argument index (`python -m pip ...`).
    redispatch: tuple[str, int] | None = None


def _skip_options(args: list[str], with_value: frozenset[str]) -> int:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "--":
            return i + 1
        i += 2 if args[i] in with_value else 1
    return i


def _env(args: list[str]) -> Wrapped:
    i = 0
    code: list[tuple[str, Dialect]] = []
    while i < len(args):
        arg = args[i]
        if arg in ("-u", "-C", "--unset", "--chdir"):
            i += 2
        elif arg in ("-S", "--split-string") and i + 1 < len(args):
            code.append((args[i + 1], Dialect.POSIX))
            i += 2
        elif arg.startswith("-") or ("=" in arg and not arg.startswith("=")):
            i += 1
        else:
            break
    rest = tuple(args[i:])
    classes: set[C] = set()
    for arg in args[:i]:
        if "=" in arg and not arg.startswith("-"):
            classes |= assignment_classes(arg)
    if not rest and not code:
        classes.add(C.CREDENTIAL_ACCESS)
    return Wrapped(
        frozenset(classes), rest, tuple(code), runs_command=bool(code), never_read_only=True
    )


def _start_process(args: list[str]) -> Wrapped:
    classes: set[C] = set()
    if not any(a.startswith("-") for a in args):
        positional = [a for a in args if a and not a.startswith("/")]
        return Wrapped(frozenset(), tuple(args[len(args) - len(positional) :]))
    file = ""
    arguments = ""
    i = 0
    while i < len(args):
        arg = args[i].casefold()
        value = args[i + 1] if i + 1 < len(args) else ""
        if arg.startswith("-") and "-filepath".startswith(arg) and len(arg) > 2:
            file, i = value, i + 2
        elif (
            arg.startswith("-")
            and len(arg) > 1
            and ("-argumentlist".startswith(arg) or arg == "-args")
        ):
            arguments, i = value, i + 2
        elif arg == "-verb":
            if value.casefold() == "runas":
                classes.add(C.PRIVILEGE_ESCALATION)
            i += 2
        elif arg in ("-windowstyle", "-wi"):
            if value.casefold().startswith("hid"):
                classes.add(C.OBFUSCATION)
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            if not file:
                file = args[i]
            elif not arguments:
                arguments = args[i]
            i += 1
    code = f"{file} {arguments}".strip()
    return Wrapped(
        frozenset(classes), (), ((code, Dialect.WINDOWS),) if code else (), runs_command=True
    )


def _privileged(name: str, args: list[str]) -> Wrapped:
    priv = frozenset({C.PRIVILEGE_ESCALATION})
    if name == "su":
        for i, arg in enumerate(args):
            if arg in ("-c", "--command") and i + 1 < len(args):
                return Wrapped(priv, (), ((args[i + 1], Dialect.POSIX),), runs_command=True)
        return Wrapped(priv, ())
    if name == "runas":
        positional = [a for a in args if not a.startswith("/")]
        code = ((positional[-1], Dialect.WINDOWS),) if positional else ()
        return Wrapped(priv, (), code, runs_command=True)
    start = _skip_options(args, p.WRAPPERS.get(name, frozenset()))
    return Wrapped(priv, tuple(args[start:]))


def strip_wrapper(name: str, args: list[str]) -> Wrapped | None:
    """How `name` wraps another command, or None if it does not."""
    if name in p.SHELL_KEYWORDS:
        return Wrapped(frozenset(), tuple(args))
    if name in p.PRIVILEGE_WRAPPERS:
        return _privileged(name, args)
    if name == "env":
        return _env(args)
    if name in ("start-process", "saps", "start"):
        return _start_process(args)
    if name == "command" and any(a in ("-v", "-V") for a in args):
        return Wrapped(frozenset(), (), read_only_stop=True)
    if name == "timeout":
        start = _skip_options(args, frozenset({"-s", "-k", "--signal", "--kill-after"}))
        return Wrapped(frozenset(), tuple(args[start + 1 :]))
    if name == "wsl":
        start = _skip_options(args, frozenset({"-d", "--distribution", "-u", "--user", "--cd"}))
        rest = tuple(a for a in args[start:] if a not in ("-e", "--exec"))
        return Wrapped(frozenset({C.CONTAINER_OR_VM_CONTROL}), rest)
    if name in p.WRAPPERS:
        start = _skip_options(args, p.WRAPPERS[name])
        classes: frozenset[C] = frozenset()
        if name in ("chroot", "nsenter", "unshare"):
            classes = frozenset({C.CONTAINER_OR_VM_CONTROL})
            if name == "chroot":
                start += 1
        rest = tuple(args[start:])
        if name == "xargs" and not rest:
            return Wrapped(classes, ())
        return Wrapped(classes, rest)
    return None


# --- code runners -----------------------------------------------------------------

_PS_PARAMS = (
    "command",
    "encodedcommand",
    "file",
    "executionpolicy",
    "windowstyle",
    "noprofile",
    "noninteractive",
    "nologo",
    "noexit",
    "sta",
    "mta",
    "version",
    "inputformat",
    "outputformat",
    "configurationname",
    "workingdirectory",
    "settingsfile",
    "custompipename",
    "encodedarguments",
    "login",
    "interactive",
    "commandwithargs",
)
_PS_ALIASES = {
    "c": "command",
    "e": "encodedcommand",
    "ec": "encodedcommand",
    "en": "encodedcommand",
    "enc": "encodedcommand",
    "ep": "executionpolicy",
    "ex": "executionpolicy",
    "f": "file",
    "w": "windowstyle",
    "nop": "noprofile",
    "noni": "noninteractive",
    "cwa": "commandwithargs",
    "v": "version",
}
_PS_WITH_VALUE = frozenset(
    {
        "executionpolicy",
        "windowstyle",
        "version",
        "inputformat",
        "outputformat",
        "configurationname",
        "workingdirectory",
        "settingsfile",
        "custompipename",
        "encodedarguments",
    }
)


def _ps_param(arg: str) -> str | None:
    if not arg or arg[0] not in "-/" or len(arg) < 2:
        return None
    key = arg[1:].casefold()
    if key in _PS_ALIASES:
        return _PS_ALIASES[key]
    matches = [name for name in _PS_PARAMS if name.startswith(key)]
    if not matches:
        return None
    for preferred in ("command", "encodedcommand", "file"):
        if preferred in matches:
            return preferred
    return matches[0]


def _powershell(args: list[str]) -> InterpreterParts:
    classes: set[C] = set()
    i = 0
    while i < len(args):
        if args[i] == "-":
            return InterpreterParts("shell", Dialect.WINDOWS, reads_stdin=True)
        param = _ps_param(args[i])
        value = args[i + 1] if i + 1 < len(args) else ""
        if param in ("command", "commandwithargs"):
            if value == "-":
                return InterpreterParts("shell", Dialect.WINDOWS, reads_stdin=True)
            return InterpreterParts(
                "shell", Dialect.WINDOWS, tuple(range(i + 1, len(args))), classes=frozenset(classes)
            )
        if param == "encodedcommand":
            return InterpreterParts(
                "shell",
                Dialect.WINDOWS,
                encoded=value,
                classes=frozenset(classes | {C.OBFUSCATION}),
            )
        if param == "file":
            return InterpreterParts(
                "shell", Dialect.WINDOWS, script_index=i + 1, classes=frozenset(classes)
            )
        if param == "windowstyle" and value.casefold().startswith(("h", "1")):
            classes.add(C.OBFUSCATION)
        if param is None:
            return InterpreterParts(
                "shell", Dialect.WINDOWS, tuple(range(i, len(args))), classes=frozenset(classes)
            )
        i += 2 if param in _PS_WITH_VALUE else 1
    return InterpreterParts("shell", Dialect.WINDOWS, reads_stdin=True, classes=frozenset(classes))


def _posix_shell(args: list[str]) -> InterpreterParts:
    i = 0
    wants_code = False
    stdin = False
    while i < len(args):
        arg = args[i]
        if arg == "--":
            i += 1
            break
        if arg in ("-o", "-O", "+o", "+O", "--rcfile", "--init-file"):
            i += 2
            continue
        if arg.startswith(("-", "+")) and not arg.startswith("--") and len(arg) > 1:
            wants_code = wants_code or "c" in arg[1:]
            stdin = stdin or "s" in arg[1:]
            i += 1
            continue
        if arg.startswith("--") or arg == "-":
            stdin = stdin or arg == "-"
            i += 1
            continue
        break
    if wants_code:
        return InterpreterParts("shell", Dialect.POSIX, (i,) if i < len(args) else ())
    if i < len(args) and not stdin and args[i] not in p.STDIN_PATHS:
        return InterpreterParts("shell", Dialect.POSIX, script_index=i)
    return InterpreterParts("shell", Dialect.POSIX, reads_stdin=True)


def _cmd(args: list[str]) -> InterpreterParts:
    for i, arg in enumerate(args):
        low = arg.casefold()
        if low.startswith(("/c", "/k", "/r")):
            extra = arg[2:].strip('"')
            return InterpreterParts(
                "shell", Dialect.WINDOWS, tuple(range(i + 1, len(args))), extra_code=extra
            )
    return InterpreterParts("shell", Dialect.WINDOWS, reads_stdin=True)


_CODE_FLAGS = frozenset({"-c", "-e", "-E", "--eval", "-p", "--print", "-r"})
_VALUE_FLAGS = frozenset({"-W", "-X", "-Q", "--require", "-I"})


def _script(name: str, args: list[str]) -> InterpreterParts:
    i = 0
    while i < len(args):
        arg = args[i]
        if name == "python" and arg == "-m" and i + 1 < len(args):
            module = args[i + 1]
            if module == "pip":
                return InterpreterParts("script", Dialect.POSIX, redispatch=("pip", i + 2))
            net = module in ("http.server", "SimpleHTTPServer")
            return InterpreterParts(
                "script",
                Dialect.POSIX,
                classes=frozenset({C.NETWORK_TRANSFER}) if net else frozenset(),
            )
        if arg in _CODE_FLAGS and not (name == "php" and arg != "-r") and i + 1 < len(args):
            return InterpreterParts("script", Dialect.POSIX, (i + 1,))
        if arg in p.STDIN_PATHS:
            # `/dev/stdin` and friends: the code comes from the pipe (review H6).
            return InterpreterParts("script", Dialect.POSIX, reads_stdin=True)
        if arg in _VALUE_FLAGS or (name in ("ruby", "node") and arg == "-r"):
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        remote = (
            frozenset({C.REMOTE_SCRIPT_EXECUTION, C.NETWORK_TRANSFER})
            if "://" in arg
            else frozenset()
        )
        return InterpreterParts("script", Dialect.POSIX, script_index=i, classes=remote)
    return InterpreterParts("script", Dialect.POSIX, reads_stdin=True)


def _evaluator(name: str, args: list[str]) -> InterpreterParts:
    if name in ("source", "."):
        if not args or args[0] in ("-", "/dev/stdin"):
            return InterpreterParts("shell", Dialect.POSIX, reads_stdin=True, evaluator=True)
        return InterpreterParts("shell", Dialect.POSIX, script_index=0, evaluator=True)
    dialect = Dialect.POSIX if name == "eval" else Dialect.WINDOWS
    indexes = tuple(i for i, a in enumerate(args) if _ps_param(a) != "command" or name == "eval")
    return InterpreterParts("shell", dialect, indexes, reads_stdin=not indexes, evaluator=True)


def interpreter_parts(name: str, args: list[str]) -> InterpreterParts | None:
    """Where the code is for a program that runs code, or None if `name` does not."""
    if name in p.SHELLS:
        return _posix_shell(args)
    if name == "cmd":
        return _cmd(args)
    if name in p.POWERSHELLS:
        return _powershell(args)
    if name in p.SCRIPT_INTERPRETERS:
        return _script(name, args)
    if name in p.EVALUATORS:
        return _evaluator(name, args)
    return None
