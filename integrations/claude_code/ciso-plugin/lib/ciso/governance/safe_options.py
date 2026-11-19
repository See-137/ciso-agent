"""Which invocations of reader programs are read-only: a per-program allowlist of options.

A reader is read-only only with options on its list. Any other option (one that writes a
file, runs a helper program, or that this list simply does not know) means the command
is not read-only. Options whose value is a command line are returned by
`exec_option_values` so the analyzer can read that command too.

Option spelling: `--long` and `--long=value` are matched on the part before `=`; a POSIX
short cluster (`-la`) must consist of allowed letters; PowerShell parameters are matched
without case; Windows-native tools use `/x` options. Positional arguments are allowed up
to `max_positional` (None: any number).
"""

from __future__ import annotations

from typing import NamedTuple


class SafeSpec(NamedTuple):
    short: str = ""
    long: frozenset[str] = frozenset()
    max_positional: int | None = None
    numeric: bool = False  # `-5` style counts
    slash: frozenset[str] = frozenset()  # Windows `/x` options, lower case
    powershell: bool = False


def _l(text: str) -> frozenset[str]:
    return frozenset(text.split())


_GREP_LONG = _l(
    "--ignore-case --invert-match --word-regexp --line-regexp --count --files-with-matches "
    "--files-without-match --line-number --no-filename --with-filename --recursive "
    "--include --exclude --exclude-dir --color --colour --extended-regexp --fixed-strings "
    "--perl-regexp --regexp --max-count --quiet --silent --only-matching --context --after-context "
    "--before-context --no-messages --text --binary-files -e"
)
_PS_COMMON = _l("-path -literalpath -filter -include -exclude -erroraction -verbose")

#: Program -> what keeps it read-only. Programs not here are never read-only.
SAFE: dict[str, SafeSpec] = {
    "ls": SafeSpec(
        "laAhRtrS1dFGiknpsuUx",
        _l(
            "--all --almost-all --human-readable --color "
            "--sort --time --reverse --recursive --classify"
        ),
    ),
    "dir": SafeSpec("", frozenset(), slash=_l("/s /b /a /w /o /q /p /ad /a-d /on /od")),
    "pwd": SafeSpec("LP", max_positional=0),
    "cd": SafeSpec("", max_positional=1),
    "echo": SafeSpec("neE"),
    "printf": SafeSpec(""),
    "cat": SafeSpec("nAbeEstTuv", _l("--number --show-all --squeeze-blank")),
    "type": SafeSpec("afptP"),
    "head": SafeSpec("nqvcz", _l("--lines --bytes --quiet"), numeric=True),
    "tail": SafeSpec("nqvcfFz", _l("--lines --bytes --follow --quiet"), numeric=True),
    "wc": SafeSpec("lwcmL", _l("--lines --words --bytes --chars")),
    "grep": SafeSpec("ivwxclLnhHrREFPeoqsmABCaIZz", _GREP_LONG),
    "egrep": SafeSpec("ivwxclLnhHrRoqsmABCaIZz", _GREP_LONG),
    "fgrep": SafeSpec("ivwxclLnhHrRoqsmABCaIZz", _GREP_LONG),
    "rg": SafeSpec(
        "iSsFwxvclnNHoUeg.LAB C".replace(" ", ""),
        _l(
            "--ignore-case --smart-case --case-sensitive --fixed-strings --word-regexp "
            "--invert-match --count --files-with-matches --line-number --no-heading "
            "--hidden --glob --type --type-not --max-count --context --files --json "
            "--follow --no-ignore --only-matching --regexp"
        ),
    ),
    "tree": SafeSpec("adfLlCIPh", _l("--dirsfirst --noreport")),
    "stat": SafeSpec("cLft", _l("--format --printf --terse")),
    "file": SafeSpec("bLihz", _l("--brief --mime --mime-type")),
    "which": SafeSpec("as"),
    "where": SafeSpec("", slash=_l("/r /q /f /t")),
    "whereis": SafeSpec("bms"),
    "whoami": SafeSpec("", max_positional=0, slash=_l("/user /groups /all")),
    "uname": SafeSpec("asnrvmpio", _l("--all"), max_positional=0),
    "id": SafeSpec("ugGnr"),
    "nproc": SafeSpec("", _l("--all"), max_positional=0),
    "du": SafeSpec("shacdL", _l("--max-depth --human-readable --summarize")),
    "df": SafeSpec("hHTPikl", _l("--human-readable")),
    "basename": SafeSpec("as", _l("--suffix --multiple")),
    "dirname": SafeSpec("z"),
    "realpath": SafeSpec("emsqz", _l("--relative-to --canonicalize-existing")),
    "readlink": SafeSpec("fenmqsvz"),
    "true": SafeSpec(""),
    "false": SafeSpec(""),
    "sort": SafeSpec(
        "bdfgiMhnRrsuVkt",
        _l("--numeric-sort --reverse --unique --key --field-separator --human-numeric-sort"),
    ),
    "uniq": SafeSpec("cdDiuf", _l("--count --repeated --unique --ignore-case"), max_positional=1),
    "cut": SafeSpec("bcdfsz", _l("--delimiter --fields --characters --bytes")),
    "jq": SafeSpec(
        "rcsenSjaC",
        _l(
            "--raw-output --compact-output --slurp --sort-keys "
            "--arg --argjson --exit-status --null-input --tab"
        ),
    ),
    "diff": SafeSpec(
        "uqrNwbBiyc",
        _l("--unified --brief --recursive --new-file --ignore-all-space --side-by-side --color"),
    ),
    "cmp": SafeSpec("lsb", _l("--silent --quiet --verbose")),
    "findstr": SafeSpec("", slash=_l("/s /i /n /c /r /l /b /e /x /v /m /o /p /a")),
    "get-childitem": SafeSpec(
        powershell=True,
        long=_PS_COMMON
        | _l("-recurse -r -name -force -file -directory -depth -hidden -attributes"),
    ),
    "gci": SafeSpec(
        powershell=True,
        long=_PS_COMMON | _l("-recurse -r -name -force -file -directory -depth -hidden"),
    ),
    "get-content": SafeSpec(
        powershell=True,
        long=_PS_COMMON | _l("-totalcount -tail -head -raw -encoding -first -last -readcount"),
    ),
    "gc": SafeSpec(powershell=True, long=_PS_COMMON | _l("-totalcount -tail -head -raw")),
    "select-string": SafeSpec(
        powershell=True,
        long=_PS_COMMON
        | _l(
            "-pattern -simplematch -casesensitive -context -list -notmatch -allmatches -quiet -raw"
        ),
    ),
    "sls": SafeSpec(powershell=True, long=_PS_COMMON | _l("-pattern -simplematch -context")),
    "get-location": SafeSpec(powershell=True, max_positional=0),
    "gl": SafeSpec(powershell=True, max_positional=0),
    "set-location": SafeSpec(powershell=True, long=_l("-path -literalpath"), max_positional=1),
    "sl": SafeSpec(powershell=True, long=_l("-path"), max_positional=1),
    "test-path": SafeSpec(powershell=True, long=_PS_COMMON | _l("-pathtype")),
    "get-item": SafeSpec(powershell=True, long=_PS_COMMON | _l("-force")),
    "gi": SafeSpec(powershell=True, long=_PS_COMMON),
    "resolve-path": SafeSpec(powershell=True, long=_PS_COMMON | _l("-relative")),
    "measure-object": SafeSpec(
        powershell=True, long=_l("-line -word -character -sum -average -maximum -minimum")
    ),
    "write-output": SafeSpec(powershell=True, long=_l("-noenumerate")),
    "write-host": SafeSpec(
        powershell=True, long=_l("-nonewline -foregroundcolor -backgroundcolor -separator")
    ),
    "get-command": SafeSpec(powershell=True, long=_l("-name -all -commandtype")),
    "gcm": SafeSpec(powershell=True, long=_l("-name -all")),
}

SAFE["find"] = SafeSpec(
    "LHP",
    _l(
        "-name -iname -type -path -ipath -maxdepth -mindepth -size -mtime -mmin -newer "
        "-print -print0 -not -o -a -and -or -empty -perm -user -group -regex -iregex "
        "-follow -prune -readable -writable -executable"
    ),
)

#: git subcommand -> what keeps it read-only. `--output`, `--ext-diff`,
#: `--open-files-in-pager` and anything unknown are off the lists. `diff`, `log`, `show`,
#: `blame` and `grep` are never read-only: a diff or text-conversion driver in the
#: repository's configuration runs a program for them (review C4).
GIT_SAFE: dict[str, SafeSpec] = {
    "status": SafeSpec(
        "sbuvz", _l("--short --branch --porcelain --untracked-files --ignored --verbose --long")
    ),
    "rev-parse": SafeSpec(
        "q",
        _l(
            "--abbrev-ref --show-toplevel --git-dir --short --verify "
            "--is-inside-work-tree --symbolic-full-name --absolute-git-dir"
        ),
    ),
    "ls-files": SafeSpec(
        "modsckz", _l("--others --modified --exclude-standard --cached --deleted --stage")
    ),
    "describe": SafeSpec("", _l("--tags --always --abbrev --dirty --long --exact-match")),
    "shortlog": SafeSpec("sne", _l("--summary --numbered --email")),
    "merge-base": SafeSpec("a", _l("--is-ancestor --all")),
    "rev-list": SafeSpec("n", _l("--count --all --max-count --reverse")),
    "version": SafeSpec(""),
}

#: Options of other readers whose value is a command line the program will run.
EXEC_OPTIONS: dict[str, frozenset[str]] = {
    "rg": _l("--pre"),
    "sort": _l("--compress-program"),
    "tar": _l(
        "--to-command --checkpoint-action --use-compress-program -I --info-script "
        "--new-volume-script -F"
    ),
}
#: Options that make a reader run helpers or write files though they take no command.
UNSAFE_FLAGS: dict[str, frozenset[str]] = {
    "rg": _l("-z --search-zip --pre-glob"),
    "sort": _l("-o --output"),
    "tree": _l("-o"),
}


def _option_ok(spec: SafeSpec, arg: str) -> bool:
    if spec.powershell and arg.startswith("-"):
        return arg.casefold() in spec.long
    if arg.startswith("--"):
        return arg.partition("=")[0] in spec.long
    if arg in spec.long:
        return True
    body = arg[1:]
    if spec.numeric and body.isdigit():
        return True
    return bool(body) and all(ch in spec.short for ch in body)


def is_read_only_invocation(name: str, args: list[str]) -> bool:
    """True only when `name` is a known reader and every option is on its safe list."""
    spec = SAFE.get(name)
    return spec is not None and spec_allows(spec, args)


def spec_allows(spec: SafeSpec, args: list[str]) -> bool:
    """True when every argument in `args` is allowed by `spec`."""
    positional = 0
    after_dashes = False
    for arg in args:
        if after_dashes or not arg or arg == "-":
            positional += 1
        elif arg == "--":
            after_dashes = True
        elif arg.startswith("-") and len(arg) > 1:
            if not _option_ok(spec, arg):
                return False
        elif arg.startswith("/") and spec.slash:
            if arg.casefold().partition(":")[0] not in spec.slash:
                return False
        else:
            positional += 1
    return spec.max_positional is None or positional <= spec.max_positional


def exec_option_values(name: str, args: list[str]) -> tuple[list[str], bool]:
    """(command lines given to exec-capable options, whether any unsafe option is used)."""
    wanted = EXEC_OPTIONS.get(name, frozenset())
    unsafe = UNSAFE_FLAGS.get(name, frozenset())
    commands: list[str] = []
    flagged = False
    for i, arg in enumerate(args):
        key, eq, value = arg.partition("=")
        if key in wanted:
            flagged = True
            if not eq:
                value = args[i + 1] if i + 1 < len(args) else ""
            commands.append(value.removeprefix("exec=").removeprefix("exec:"))
        elif key in unsafe:
            flagged = True
    return [c for c in commands if c], flagged
