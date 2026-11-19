"""Walk a parsed command and collect its classes.

Pipelines are where download-and-run hides: a stage that runs code read from its standard
input (a shell or interpreter with no script or with `/dev/stdin`, `iex`, `eval`, or one
started by `xargs`) after a stage that fetched from the network is remote script
execution; after a decoder, or after anything else, it is obfuscation (the code is built
at run time). A file fetched, renamed and then run in the same line is remote script
execution as well; so is code built at run time (a script block from text, a variable as
the command) in a line that fetches.

`read_only_command` is earned (review C1): every word is plain text
(`ciso.governance.readonly_words`), every program is a known reader with only safe
options, no wrapper, no assignment, no redirect except to a null device, and git only in
the directory the command started in.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ciso.governance import programs as p
from ciso.governance.analysis_code import CodeRunners, basename
from ciso.governance.analysis_state import Seen
from ciso.governance.argv_checks import check_program
from ciso.governance.classes import CommandClass as C
from ciso.governance.env_vars import assignment_classes, variable_classes
from ciso.governance.git_argv import check_git
from ciso.governance.lexer_types import DYN, MAX_DEPTH, Dialect, Redirect, Script, Stage, Word
from ciso.governance.readonly_words import arithmetic_hazard, word_earns_read_only
from ciso.governance.safe_options import SAFE, exec_option_values
from ciso.governance.shell_lexer import HiddenCommand, ParseError, parse_script
from ciso.governance.wrappers import Wrapped, interpreter_parts, strip_wrapper

if TYPE_CHECKING:
    from ciso.governance.commands import ClassifierConfig

_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", re.DOTALL)
_PS_ASSIGN_RE = re.compile(r"\$[A-Za-z_][\w:]*")
_NULL_TARGETS = frozenset({"/dev/null", "nul", "$null", "null"})
_CODE_RUNNERS = p.SHELLS | p.SCRIPT_INTERPRETERS | p.POWERSHELLS | p.EVALUATORS | {"cmd"}
_GIT_MESSAGE_OPTIONS = frozenset({"-m", "--message"})
#: A revision such as `HEAD~2` or `main^`: no separator, ends in `~N` or `^N`.
_REVISION_RE = re.compile(r"[^/\\:]*[~^][0-9]*")


def _find_exec(texts: list[str]) -> list[str]:
    """Command lines given to `find -exec`, `-execdir`, `-ok` and `-okdir`."""
    out: list[str] = []
    current: list[str] | None = None
    for text in texts:
        if text in ("-exec", "-execdir", "-ok", "-okdir"):
            current = []
            out.append("")
        elif current is not None and text in (";", "+"):
            out[-1] = " ".join(current)
            current = None
        elif current is not None:
            current.append(text)
    if current is not None:
        out[-1] = " ".join(current)
    return [c for c in out if c]


def _git_path_texts(texts: list[str]) -> list[str]:
    """git arguments that may be paths: everything except commit and tag messages and
    revisions such as `HEAD~2` (which would otherwise read as a short name)."""
    out: list[str] = []
    skip = False
    for text in texts:
        if skip:
            skip = False
        elif text in _GIT_MESSAGE_OPTIONS:
            skip = True
        elif not text.startswith("--message=") and not _REVISION_RE.fullmatch(text):
            out.append(text)
    return out


class Analyzer(CodeRunners):
    """One analysis of one parsed command. Holds mutable state; never shared."""

    # --- structure --------------------------------------------------------------

    def script(self, script: Script) -> Seen:
        outer = self.dialect
        self.dialect = script.dialect
        try:
            return self._pipelines(script)
        finally:
            self.dialect = outer

    def _pipelines(self, script: Script) -> Seen:
        seen = Seen()
        if "ifs" in script.flags:
            self.classes.add(C.OBFUSCATION)
        if "arith" in script.flags:
            self.read_only = False
        for pipeline in script.pipelines:
            infos = [self.stage(stage, index) for index, stage in enumerate(pipeline)]
            for j, info in enumerate(infos):
                if j and info.stdin_exec:
                    upstream = infos[:j]
                    if any(u.network for u in upstream):
                        self.classes.add(C.REMOTE_SCRIPT_EXECUTION)
                    else:
                        self.classes.add(C.OBFUSCATION)
            for info in infos:
                seen = seen | Seen(info.network, info.decoder)
        return seen

    def nested(self, text: str, dialect: Dialect) -> Seen:
        """Read a command string one level deeper (`sh -c`, `cmd /c`, `eval`...)."""
        self.depth += 1
        try:
            if self.depth > MAX_DEPTH:
                raise ParseError("command strings nest too deeply")
            parsed = parse_script(text, dialect, depth=self.depth)
            return self.script(parsed)
        except HiddenCommand:
            raise
        except ParseError:
            self.classes.add(C.UNPARSEABLE)
            return Seen()
        finally:
            self.depth -= 1

    def stage(self, stage: Stage, position: int) -> Seen:
        seen = Seen()
        for group in stage.groups:
            seen = seen | self.script(group)
        for word in stage.words:
            if word.subs:
                # A substitution runs a command to build an argument: never read-only.
                self.read_only = False
            if not word_earns_read_only(word, self.dialect):
                self.read_only = False
            for sub in word.subs:
                seen = seen | self.script(sub)
        for redirect in stage.redirects:
            seen = seen | self.redirect(redirect)
        words = list(stage.words)
        if stage.lead_group and words and not words[0].text.startswith("."):
            self.classes.add(C.UNPARSEABLE)
        info = self.argv(words, stage, position)
        if info.network:
            for redirect in stage.redirects:
                if redirect.target is not None and redirect.op.startswith(">"):
                    self.downloaded.add(basename(redirect.target.text))
        return seen | info

    def redirect(self, redirect: Redirect) -> Seen:
        target = redirect.target
        if target is None:
            return Seen()
        seen = Seen()
        for sub in target.subs:
            seen = seen | self.script(sub)
        # A descriptor duplication is only `>&N`, `<&N` or `>&-`; every other form with
        # `>` (`>&file`, `&>`, `&>>`, `>>&`, `>|`, `2>file`) writes to the target.
        duplicate = redirect.op in (">&", "<&") and (target.text.isdigit() or target.text == "-")
        writes = ">" in redirect.op and not duplicate
        if not duplicate and not (writes and target.text.casefold() in _NULL_TARGETS):
            self.read_only = False  # only a null device or a duplication stays read-only
        if not duplicate:
            self.environment_reads([target])
            self.path_word(target, writes=writes, strict=True)
        if "/dev/tcp/" in target.text or "/dev/udp/" in target.text:
            self.classes.add(C.NETWORK_TRANSFER)
            seen = seen | Seen(network=True)
        return seen

    # --- one simple command -----------------------------------------------------

    def argv(self, words: list[Word], stage: Stage, position: int) -> Seen:
        words = self.strip_assignments(words)
        if not words:
            return Seen()
        self.environment_reads(words)
        self.computed_code([w.text for w in words])
        first = words[0]
        if (first.text.startswith(".") and len(first.text) > 1 and stage.lead_group) or (
            first.text.startswith("[") and "]::" in first.text
        ):
            return self.expression(words)
        if first.dynamic:
            # The command run is chosen at run time (`$cmd`, `& $block`): unreadable, and
            # code built at run time (review H6).
            self.classes |= {C.UNPARSEABLE, C.OBFUSCATION}
            self.computed = True
            return self.expression(words)
        name = p.program_name(first.text)
        if not p.valid_program(name) or not p.valid_program_text(first.text):
            self.classes.add(C.UNPARSEABLE)
            return self.expression(words)
        self.check_disguise(first, name)
        if "/" in first.text or "\\" in first.text:
            self.executed.add(basename(first.text))
        return self.program(name, words[1:], stage, position)

    def strip_assignments(self, words: list[Word]) -> list[Word]:
        i = 0
        while i < len(words):
            raw = words[i].raw
            if _ASSIGN_RE.fullmatch(raw) and not raw.startswith("-"):
                # Any assignment prefix can change what runs: never read-only.
                self.read_only = False
                self.classes |= assignment_classes(words[i].text)
                self.path(words[i].text, writes=False)
                i += 1
            elif _PS_ASSIGN_RE.fullmatch(raw) and i + 1 < len(words) and words[i + 1].text == "=":
                self.read_only = False
                self.classes |= variable_classes(raw)
                i += 2
            else:
                break
        return words[i:]

    def check_disguise(self, word: Word, name: str) -> None:
        raw = word.raw
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
            raw = raw[1:-1]
        if word.ansi_c or p.program_name(raw) != name:
            self.classes.add(C.OBFUSCATION)

    def expression(self, words: list[Word]) -> Seen:
        """A PowerShell expression or a command whose name is not known."""
        self.read_only = False
        texts = [w.text for w in words]
        facts = check_program("", texts)
        self.classes |= facts.classes
        for text in texts:
            self.path(text, writes=True)
        return Seen(facts.network, facts.decoder)

    def program(self, name: str, args: list[Word], stage: Stage, position: int) -> Seen:
        texts = [w.text for w in args]
        wrapped = strip_wrapper(name, texts)
        if wrapped is not None:
            return self.wrapper(name, wrapped, args, stage, position)
        interp = interpreter_parts(name, texts)
        if interp is not None:
            return self.interpreter(interp, args, stage, position)
        if arithmetic_hazard(name, [w.raw for w in args]):
            self.classes.add(C.UNPARSEABLE)  # bash may run code evaluating these (Q1)
        if name in p.DIRECTORY_CHANGERS:
            self.change_directory(name, args)
        if name == "git":
            return self.git(texts)
        if name in p.SCRIPT_BLOCK_RUNNERS:
            self.script_block_runner(args)
        return self.plain_program(name, args, texts)

    def wrapper(
        self, name: str, wrapped: Wrapped, args: list[Word], stage: Stage, position: int
    ) -> Seen:
        self.classes |= wrapped.classes
        if wrapped.read_only_stop:
            return Seen()
        if wrapped.never_read_only or name not in p.SHELL_KEYWORDS:
            self.read_only = False  # a wrapper is not a reader
        for code, dialect in wrapped.code:
            self.nested(code, dialect)
        rest = args[len(args) - len(wrapped.rest) :] if wrapped.rest else []
        if not rest:
            return Seen()
        seen = self.argv(rest, stage, position)
        if name == "xargs" and p.program_name(rest[0].text) in _CODE_RUNNERS:
            # `xargs sh -c`: the code comes from the pipe (review H6).
            seen = seen | Seen(stdin_exec=True)
        return seen

    def plain_program(self, name: str, args: list[Word], texts: list[str]) -> Seen:
        facts = check_program(name, texts)
        self.classes |= facts.classes
        if name == "find":
            for command in _find_exec(texts):
                self.nested(command, Dialect.POSIX)
        commands, unsafe = exec_option_values(name, texts)
        if unsafe:
            # A reader told to run a helper program hides an execution.
            self.read_only = False
            self.classes.add(C.OBFUSCATION)
        for command in commands:
            self.nested(command, Dialect.POSIX)
        if facts.network:
            self.downloaded |= {basename(t) for t in texts if t and DYN not in t}
        if name in p.MOVERS:
            self.moved_file(texts)
        if name in p.SCRIPT_HOSTS:
            self.script_host(texts)
        if not facts.read_only:
            self.read_only = False
        if name not in p.PRINTERS:
            # Operands the program opens as files; a directory change opens nothing.
            opens = name in SAFE or name in p.FILE_WRITERS
            strict = opens and name not in p.DIRECTORY_CHANGERS
            for word in args:
                self.path_word(word, writes=not facts.read_only, strict=strict)
        return Seen(facts.network, facts.decoder)

    def moved_file(self, texts: list[str]) -> None:
        """A fetched file copied or renamed is still a fetched file (review H6)."""
        names = [t for t in texts if t and not t.startswith("-")]
        if len(names) < 2 or not {basename(t) for t in names[:-1]} & self.downloaded:
            return
        target = basename(names[-1])
        self.downloaded |= {target} if target else {basename(t) for t in names[:-1]}

    def git(self, texts: list[str]) -> Seen:
        facts = check_git(texts, self.cfg.protected_branches)
        self.classes |= facts.classes
        self.branches |= facts.branches
        self.unknown_branch = self.unknown_branch or facts.unknown_branch
        if not facts.read_only or self.moved:
            # Read-only git runs in the directory the command started in (review C4).
            self.read_only = False
        for code in facts.nested:
            self.nested(code, Dialect.POSIX)
        for text in _git_path_texts(texts):
            self.path(text, writes=not facts.read_only)
        return Seen()

    def script_host(self, texts: list[str]) -> None:
        for text in texts:
            low = text.casefold()
            if "://" in low or low.startswith("\\\\") or "javascript:" in low:
                self.classes |= {C.REMOTE_SCRIPT_EXECUTION, C.NETWORK_TRANSFER}
            self.executed.add(basename(text))

    # --- result ----------------------------------------------------------------

    def finish(self) -> tuple[set[C], set[str]]:
        if self.downloaded & self.executed - {""}:
            self.classes.add(C.REMOTE_SCRIPT_EXECUTION)
        if self.computed and C.NETWORK_TRANSFER in self.classes:
            self.classes.add(C.REMOTE_SCRIPT_EXECUTION)
        if self.read_only and not self.classes:
            self.classes.add(C.READ_ONLY_COMMAND)
        return self.classes, self.branches


def analyze(script: Script, config: ClassifierConfig) -> tuple[set[C], set[str], bool]:
    """Classes, push branches, and whether a push names no branch, of one reading."""
    analyzer = Analyzer(config)
    analyzer.script(script)
    classes, branches = analyzer.finish()
    return classes, branches, analyzer.unknown_branch
