"""Where a bulk write lands: recursive copies and moves, sync tools and archive extraction
(queue Q15).

`bulk_destinations(name, args)` reads one program's literal arguments and answers None
when the invocation is not a bulk write, otherwise the destinations it writes into: an
index into `args`, the text of a value attached to its option (`--directory=..`,
`-Destination:.`, `-C..`, `7z -oDIR`), `HERE` (no destination named: the current
directory) or `UNKNOWN`. Whether a destination is broad (the current directory, a parent,
home, a root, unknown) is decided by the analyzer through `ciso.common.paths`.

Options are normalised before they are read: `--opt=value` is split; an unambiguous GNU
long-option prefix of at least three letters is the full option (`--recur`); a
PowerShell parameter may be any unambiguous prefix and may carry `:value`
(`-Recurse:$true`, `-Destination:.`). FAIL CLOSED: an option a program's table does not
know, or an ambiguous prefix, makes the destination `UNKNOWN`, so the command is a broad
bulk write (a copy whose recursion cannot be told counts as recursive).

Covered: `cp -r/-R/-a/--recursive/--archive`, `mv`, `move`, `Move-Item`, `rsync`,
`robocopy`, `xcopy /s` or `/e`, `Copy-Item -Recurse` (and `cp`/`copy`/`cpi` as its
PowerShell aliases), `tar -x` (also `x` in the old first-word form, `--extract`, `--get`),
`unzip` (not when listing, testing or printing), `7z x` / `7z e`, `Expand-Archive`.
Options that let archive members escape the destination (tar `-P`/`--absolute-names`,
7-Zip `-spf`/`-spf2` or any switch not known safe, unzip `-:`) make it `UNKNOWN`. A move
is a bulk write whatever its options: a directory moves with everything in it.
`robocopy` takes its destination from the second operand; an operand after a `/` option
is read as unknown.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple

#: No destination named: the program writes into the current directory.
HERE: Final = -1
#: A destination this reading cannot find.
UNKNOWN: Final = -2

#: A destination: an index into the arguments, a literal text, `HERE` or `UNKNOWN`.
type Destination = int | str
type Destinations = tuple[Destination, ...]


class _Gnu(NamedTuple):
    """GNU-style options of one program: short letters, the letters that take a value,
    long options (name -> takes a value)."""

    short: str
    short_valued: str
    long: dict[str, bool]


def _table(flags: str, valued: str = "") -> dict[str, bool]:
    return {**dict.fromkeys(flags.split(), False), **dict.fromkeys(valued.split(), True)}


_CP: Final = _Gnu(
    "abdfilLnpPrRsStTuvxHZ",
    "tS",
    _table(
        "--archive --recursive --no-target-directory --force --interactive --no-clobber "
        "--parents --verbose --update --link --symbolic-link --dereference --no-dereference "
        "--strip-trailing-slashes --one-file-system --attributes-only --remove-destination "
        "--copy-contents --preserve --no-preserve --backup --reflink --sparse --debug",
        "--target-directory --suffix",
    ),
)
_MV: Final = _Gnu(
    "bfinTtuvSZ",
    "tS",
    _table(
        "--backup --force --interactive --no-clobber --no-target-directory --update "
        "--verbose --strip-trailing-slashes --context --debug --exchange --no-copy",
        "--target-directory --suffix",
    ),
)
_RSYNC: Final = _Gnu(
    "avrlptgoDzhPHAXEcunWSxRbqdiIkKLOJmyC8",
    "efTBM",
    _table(
        "--archive --verbose --recursive --links --perms --times --group --owner --devices "
        "--specials --compress --progress --partial --human-readable --dry-run --checksum "
        "--update --hard-links --acls --xattrs --stats --itemize-changes --mkpath --inplace "
        "--whole-file --delete --delete-before --delete-during --delete-after "
        "--delete-excluded --remove-source-files --ignore-existing --existing --quiet "
        "--no-motd --numeric-ids --sparse --one-file-system --relative --no-relative "
        "--copy-links --safe-links --keep-dirlinks --omit-dir-times --prune-empty-dirs "
        "--size-only --ignore-times --append --append-verify --info --debug --protect-args "
        "--from0 --8-bit-output --no-perms --no-owner --no-group --no-times",
        "--rsh --exclude --include --exclude-from --include-from --filter --files-from "
        "--chmod --chown --timeout --contimeout --port --password-file --log-file "
        "--temp-dir --backup-dir --partial-dir --max-size --min-size --bwlimit --block-size "
        "--remote-option --compress-level --out-format --log-file-format",
    ),
)
#: tar's known options; any other (`--transform`, which can rename into a parent) is
#: unknown.
_TAR: Final = _Gnu(
    "xzfvjJcCtpPkOmrUuSWaZoh",
    "fC",
    _table(
        "--extract --get --verbose --gzip --gunzip --ungzip --bzip2 --xz --zstd --lzma "
        "--auto-compress --wildcards --no-wildcards --no-same-owner --same-owner "
        "--preserve-permissions --same-permissions --no-same-permissions --keep-old-files "
        "--keep-newer-files --overwrite --skip-old-files --list --create --to-stdout "
        "--touch --no-overwrite-dir --unlink-first --recursive-unlink --totals "
        "--absolute-names",
        "--file --directory --strip-components --exclude --exclude-from "
        "--blocking-factor --checkpoint --warning --format --owner --group --mode",
    ),
)
#: tar options that keep absolute and `..` member names (GNU tar and bsdtar strip them
#: otherwise).
_TAR_ESCAPE: Final = frozenset({"-P", "--absolute-names"})
#: 7-Zip switches that cannot move members outside the output directory: `-y` (assume
#: yes), `-p` (password), `-ao{a,s,u,t}` (overwrite mode). `-o` is the destination. Any
#: other switch (`-spf`, `-spf2` keep full paths) fails closed.
_SEVEN_ZIP_SAFE: Final = re.compile(r"-y|-p.*|-ao[asut]|-o.*", re.IGNORECASE)
#: unzip's own options: one letter each (`-qq`, `-aa` repeat a letter).
_UNZIP_SHORT: Final = frozenset("onqjaCLUVXKbBMsT")
_UNZIP_LISTING: Final = frozenset("ltvzZp")

_PS_COMMON_VALUED = "-path -literalpath -lp -pspath -erroraction -ea"
_COPY_ITEM_PARAMS: Final = _table(
    "-recurse -force -container -passthru -whatif -confirm -verbose",
    _PS_COMMON_VALUED + " -destination -filter -include -exclude -credential -tosession "
    "-fromsession",
)
_MOVE_ITEM_PARAMS: Final = _table(
    "-force -passthru -whatif -confirm -verbose",
    _PS_COMMON_VALUED + " -destination -filter -include -exclude -credential",
)
_EXPAND_PARAMS: Final = _table(
    "-force -passthru -whatif -confirm -verbose", _PS_COMMON_VALUED + " -destinationpath"
)
_PS_SOURCES: Final = frozenset({"-path", "-literalpath", "-lp", "-pspath"})
_PS_OFF: Final = frozenset({"$false", "0"})
_XCOPY: Final = frozenset(
    [
        "/s",
        "/e",
        "/i",
        "/y",
        "/-y",
        "/h",
        "/k",
        "/r",
        "/q",
        "/f",
        "/l",
        "/c",
        "/t",
        "/u",
        "/z",
        "/b",
        "/j",
        "/a",
        "/m",
        "/v",
        "/w",
        "/o",
        "/x",
        "/n",
        "/g",
        "/p",
    ]
)
_XCOPY_VALUED: Final = ("/d", "/exclude")
_COPY_ITEM: Final = frozenset({"copy-item", "cpi", "copy"})
_MOVES: Final = frozenset({"mv", "move", "move-item", "mi"})
_SEVEN_ZIP: Final = frozenset({"7z", "7za", "7zr", "7zz"})
_RECURSIVE: Final = frozenset({"-r", "-R", "-a", "--recursive", "--archive"})


class _Parsed(NamedTuple):
    #: Normalised option -> its values (an index into the arguments, or attached text).
    options: dict[str, list[Destination]]
    operands: list[int]
    #: Something was not understood: callers fail closed.
    unknown: bool


def _next(args: list[str], i: int) -> Destination:
    return i + 1 if i + 1 < len(args) else UNKNOWN


# --- GNU options -------------------------------------------------------------------------


def _long_name(key: str, table: dict[str, bool]) -> str | None:
    """`--recur` -> `--recursive` when the prefix is unambiguous and at least 3 letters."""
    if key in table:
        return key
    if len(key) - 2 < 3:
        return None
    found = [name for name in table if name.startswith(key)]
    return found[0] if len(found) == 1 else None


def _short(args: list[str], i: int, body: str, spec: _Gnu, out: _Parsed) -> tuple[int, bool]:
    """Read one short cluster. A value-taking letter takes the rest of a dashed cluster
    (`-Cdir`), else the next word; in the old first-word tar form (`xfC a.tar dir`) each
    value-taking letter takes the next word in turn. Returns (last index read, bad)."""
    last = i
    dashed = args[i] != body
    for pos, letter in enumerate(body):
        if letter not in spec.short:
            return last, True
        values = out.options.setdefault("-" + letter, [])
        if letter not in spec.short_valued:
            continue
        rest = body[pos + 1 :]
        if rest and dashed:
            values.append(rest)
            return last, False
        values.append(_next(args, last))
        last += 1
    return last, False


def _long(args: list[str], i: int, spec: _Gnu, out: _Parsed) -> tuple[int, bool]:
    key, eq, value = args[i].partition("=")
    name = _long_name(key, spec.long)
    if name is None:
        return i, True
    values = out.options.setdefault(name, [])
    if spec.long[name] and eq:
        values.append(value)
    elif spec.long[name]:
        values.append(_next(args, i))
        return i + 1, False
    return i, False


def _gnu(args: list[str], spec: _Gnu, *, first_word_cluster: bool = False) -> _Parsed:
    """Options, operands and whether anything was not understood (fail closed)."""
    out = _Parsed({}, [], False)
    unknown = False
    i = 0
    dashes = False
    while i < len(args):
        arg = args[i]
        old_style = first_word_cluster and i == 0
        if dashes or arg == "-" or (not arg.startswith("-") and not old_style):
            out.operands.append(i)
        elif arg == "--":
            dashes = True
        elif arg.startswith("--"):
            i, bad = _long(args, i, spec, out)
            unknown = unknown or bad
        else:
            i, bad = _short(args, i, arg if old_style else arg[1:], spec, out)
            unknown = unknown or bad
        i += 1
    return out._replace(unknown=unknown)


# --- PowerShell parameters ---------------------------------------------------------------


def _ps(args: list[str], table: dict[str, bool]) -> _Parsed:
    """PowerShell parameters: unambiguous prefixes, `-Name:value` binding."""
    out = _Parsed({}, [], False)
    unknown = False
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-") or len(arg) < 2:
            out.operands.append(i)
            i += 1
            continue
        key, colon, value = arg.casefold().partition(":")
        found = [name for name in table if name.startswith(key)]
        name = key if key in table else (found[0] if len(found) == 1 else None)
        if name is None:
            unknown = True
        elif table[name] and colon:
            out.options.setdefault(name, []).append(arg[len(key) + 1 :])
        elif table[name]:
            out.options.setdefault(name, []).append(_next(args, i))
            i += 1
        elif not (colon and value.strip() in _PS_OFF):
            out.options.setdefault(name, [])
        i += 1
    return out._replace(unknown=unknown)


def _ps_destination(parsed: _Parsed, dest_param: str) -> Destinations:
    if parsed.unknown:
        return (UNKNOWN,)
    if dest_param in parsed.options:
        return tuple(parsed.options[dest_param]) or (UNKNOWN,)
    source_named = bool(_PS_SOURCES & parsed.options.keys())
    rest = parsed.operands if source_named else parsed.operands[1:]
    if len(rest) > 1:
        return (UNKNOWN,)
    return (rest[0],) if rest else (HERE,)


# --- programs ----------------------------------------------------------------------------


def _target(parsed: _Parsed) -> Destinations | None:
    """`-t DIR` / `--target-directory`, else the last of two or more operands."""
    if parsed.unknown:
        return (UNKNOWN,)
    named = parsed.options.get("-t", []) + parsed.options.get("--target-directory", [])
    if named:
        return tuple(named)
    return (parsed.operands[-1],) if len(parsed.operands) >= 2 else None


def _powershell_style(args: list[str]) -> bool:
    """`cp -Recurse ...`: PowerShell's alias of Copy-Item (a capitalised long parameter)."""
    return any(len(a) > 2 and a[0] == "-" and a[1].isupper() and a[2:3].islower() for a in args)


def _copy(name: str, args: list[str]) -> Destinations | None:
    if name in _COPY_ITEM or _powershell_style(args):
        parsed = _ps(args, _COPY_ITEM_PARAMS)
        if parsed.unknown:
            return (UNKNOWN,)
        return _ps_destination(parsed, "-destination") if "-recurse" in parsed.options else None
    parsed = _gnu(args, _CP)
    if not (_RECURSIVE & parsed.options.keys()) and not parsed.unknown:
        return None
    return _target(parsed) or (UNKNOWN,)


def _move(name: str, args: list[str]) -> Destinations | None:
    if name in ("move-item", "mi") or _powershell_style(args):
        return _ps_destination(_ps(args, _MOVE_ITEM_PARAMS), "-destination")
    if name == "move":
        operands = [i for i, a in enumerate(args) if not a.startswith("/")]
        return (operands[-1],) if len(operands) >= 2 else (UNKNOWN,)
    return _target(_gnu(args, _MV))


def _robocopy(args: list[str]) -> Destinations:
    first_option = next((i for i, a in enumerate(args) if a.startswith("/")), len(args))
    operands = [i for i, a in enumerate(args) if not a.startswith("/")]
    if len(operands) < 2 or operands[1] > first_option:
        return (UNKNOWN,)
    return (operands[1],)


def _xcopy(args: list[str]) -> Destinations | None:
    options = [a.casefold().partition(":")[0] for a in args if a.startswith("/")]
    if any(o not in _XCOPY and not o.startswith(_XCOPY_VALUED) for o in options):
        return (UNKNOWN,)
    if not {"/s", "/e"} & set(options):
        return None
    operands = [i for i, a in enumerate(args) if not a.startswith("/")]
    if len(operands) > 2:
        return (UNKNOWN,)
    return (operands[1],) if len(operands) == 2 else (HERE,)


def _rsync(args: list[str]) -> Destinations | None:
    parsed = _gnu(args, _RSYNC)
    if parsed.unknown:
        return (UNKNOWN,)
    if len(parsed.operands) < 2:
        return None
    dest = parsed.operands[-1]
    text = args[dest]
    remote = ":" in text and not (len(text) >= 2 and text[1] == ":")
    return None if remote else (dest,)


def _tar(args: list[str]) -> Destinations | None:
    old_style = bool(args) and not args[0].startswith("-")
    parsed = _gnu(args, _TAR, first_word_cluster=old_style)
    if parsed.unknown:
        return (UNKNOWN,)
    if not {"-x", "--extract", "--get"} & parsed.options.keys():
        return None
    if _TAR_ESCAPE & parsed.options.keys():
        return (UNKNOWN,)  # members keep leading `/` and `..`: they may land anywhere
    named = parsed.options.get("-C", []) + parsed.options.get("--directory", [])
    return tuple(named) or (HERE,)


def _unzip(args: list[str]) -> Destinations | None:
    found: list[Destination] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-x":
            break  # the rest are names to leave out
        if arg == "-d":
            found.append(_next(args, i))
            i += 1
        elif arg.startswith("-d"):
            found.append(arg[2:])
        elif arg.startswith("-") and len(arg) > 1:
            letters = set(arg[1:])
            if letters & _UNZIP_LISTING:
                return None
            if not letters <= _UNZIP_SHORT:
                return (UNKNOWN,)
        i += 1
    return tuple(found) or (HERE,)


def _seven_zip(args: list[str]) -> Destinations | None:
    positional = [a for a in args if not a.startswith("-")]
    if not positional or positional[0].casefold() not in ("x", "e"):
        return None
    switches = [a for a in args if a.startswith("-")]
    if any(not _SEVEN_ZIP_SAFE.fullmatch(a) for a in switches):
        return (UNKNOWN,)
    for arg in switches:
        if arg.casefold().startswith("-o"):
            return (arg[2:],) if len(arg) > 2 else (UNKNOWN,)
    return (HERE,)


def bulk_destinations(name: str, args: list[str]) -> Destinations | None:
    """Destinations of a bulk write by program `name` (see module doc), or None."""
    if name in _COPY_ITEM or name == "cp":
        return _copy(name, args)
    if name in _MOVES:
        return _move(name, args)
    if name == "robocopy":
        return _robocopy(args)
    if name == "xcopy":
        return _xcopy(args)
    if name == "rsync":
        return _rsync(args)
    if name in ("tar", "bsdtar"):
        return _tar(args)
    if name == "unzip":
        return _unzip(args)
    if name in _SEVEN_ZIP:
        return _seven_zip(args)
    if name == "expand-archive":
        return _ps_destination(_ps(args, _EXPAND_PARAMS), "-destinationpath")
    return None
