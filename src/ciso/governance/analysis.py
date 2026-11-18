"""Walk a parsed command and collect its classes.

Pipelines are where download-and-run hides: a stage that runs code read from its standard
input (a shell or interpreter with no script, `iex`, `eval`) after a stage that fetched
from the network is remote script execution; after a decoder, or after anything else,
it is obfuscation (the code is built at run time). Code handed over in a string
(`sh -c`, `cmd /c`, `powershell -Command`, `-EncodedCommand`, `eval`, `iex`) is read
again, one level deeper. A file fetched and then run in the same line is remote script
execution as well.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import TYPE_CHECKING, NamedTuple

from ciso.governance import programs as p
from ciso.governance.argv_checks import check_program
from ciso.governance.classes import CommandClass as C
from ciso.governance.code_scan import scan_code
from ciso.governance.danger_paths import (
    GIT_CONFIG_PATHS,
    GIT_HOOK_PATHS,
    PRIVILEGE_PATHS,
    TAMPER_PATHS,
)
from ciso.governance.env_vars import assignment_classes, variable_classes
from ciso.governance.git_argv import check_git
from ciso.governance.globs import path_matches_any
from ciso.governance.safe_options import exec_option_values
from ciso.governance.shell_lexer import (
    DYN,
    MAX_DEPTH,
    Dialect,
    HiddenCommand,
    ParseError,
    Redirect,
    Script,
    Stage,
    Word,
    parse_script,
)
from ciso.governance.wrappers import InterpreterParts, interpreter_parts, strip_wrapper

if TYPE_CHECKING:
    from ciso.governance.commands import ClassifierConfig

_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", re.DOTALL)
_PS_ASSIGN_RE = re.compile(r"\$[A-Za-z_][\w:]*")
_NULL_TARGETS = frozenset({"/dev/null", "nul", "$null", "null"})
#: Longest decoded `-EncodedCommand` text read.
MAX_DECODED_CHARS = 8000


class Seen(NamedTuple):
    network: bool = False
    decoder: bool = False
    stdin_exec: bool = False

    def __or__(self, other: object) -> Seen:
        if not isinstance(other, Seen):
            return NotImplemented
        return Seen(
            self.network or other.network,
            self.decoder or other.decoder,
            self.stdin_exec or other.stdin_exec,
        )


def _basename(text: str) -> str:
    return re.split(r"[\\/]", text)[-1].casefold()


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


class Analyzer:
    """One analysis of one parsed command. Holds mutable state; never shared."""

    def __init__(self, config: ClassifierConfig, target_branch: str | None) -> None:
        self.cfg = config
        self.target_branch = target_branch
        self.classes: set[C] = set()
        self.branches: set[str] = set()
        self.downloaded: set[str] = set()
        self.executed: set[str] = set()
        self.read_only = True
        self.depth = 0

    # --- structure --------------------------------------------------------------

    def script(self, script: Script) -> Seen:
        seen = Seen()
        if "ifs" in script.flags:
            self.classes.add(C.OBFUSCATION)
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
                    self.downloaded.add(_basename(redirect.target.text))
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
        if writes and target.text.casefold() not in _NULL_TARGETS:
            self.read_only = False
        if not duplicate:
            self.path(target.text, writes=writes)
        if "/dev/tcp/" in target.text or "/dev/udp/" in target.text:
            self.classes.add(C.NETWORK_TRANSFER)
            seen = seen | Seen(network=True)
        return seen

    # --- paths ------------------------------------------------------------------

    def path(self, text: str, *, writes: bool) -> None:
        if not text or len(text) > 1024:
            return
        candidates = {text}
        if "=" in text:
            candidates.add(text.partition("=")[2])
        if ":" in text and not re.match(r"[A-Za-z]:[\\/]", text):
            candidates.add(text.partition(":")[2])
        for value in candidates:
            if path_matches_any(self.cfg.all_credential_paths, value):
                self.classes.add(C.CREDENTIAL_ACCESS)
            if not writes:
                continue
            for patterns, cls in (
                (self.cfg.all_agent_config_paths, C.AGENT_CONFIG_CHANGE),
                (GIT_HOOK_PATHS, C.GIT_HOOKS_CHANGE),
                (GIT_CONFIG_PATHS, C.GIT_CONFIG_CHANGE),
                (PRIVILEGE_PATHS, C.PRIVILEGE_ESCALATION),
                (TAMPER_PATHS, C.SECURITY_TOOL_TAMPER),
            ):
                if path_matches_any(patterns, value):
                    self.classes.add(cls)

    # --- one simple command -----------------------------------------------------

    def argv(self, words: list[Word], stage: Stage, position: int) -> Seen:
        words = self.strip_assignments(words)
        if not words:
            return Seen()
        first = words[0]
        if (first.text.startswith(".") and len(first.text) > 1 and stage.lead_group) or (
            first.text.startswith("[") and "]::" in first.text
        ):
            return self.expression(words)
        if first.dynamic:
            self.classes.add(C.UNPARSEABLE)
            return self.expression(words)
        name = p.program_name(first.text)
        if not p.valid_program(name) or not p.valid_program_text(first.text):
            self.classes.add(C.UNPARSEABLE)
            return self.expression(words)
        self.check_disguise(first, name)
        if "/" in first.text or "\\" in first.text:
            self.executed.add(_basename(first.text))
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
            self.classes |= wrapped.classes
            if wrapped.never_read_only:
                self.read_only = False
            if wrapped.read_only_stop:
                return Seen()
            for code, dialect in wrapped.code:
                self.nested(code, dialect)
            rest = args[len(args) - len(wrapped.rest) :] if wrapped.rest else []
            if not wrapped.rest and wrapped.runs_command:
                return Seen()
            return self.argv(rest, stage, position) if rest else Seen()
        interp = interpreter_parts(name, texts)
        if interp is not None:
            return self.interpreter(interp, args, stage, position)
        if name == "git":
            return self.git(texts)
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
            self.downloaded |= {_basename(t) for t in texts if t and DYN not in t}
        if name in p.SCRIPT_HOSTS:
            self.script_host(texts)
        if name in p.PRINTERS and any(
            p.SECRET_VARIABLE_RE.fullmatch(v) for w in args for v in w.variables
        ):
            self.classes.add(C.CREDENTIAL_ACCESS)
        if not facts.read_only:
            self.read_only = False
        for text in texts:
            self.path(text, writes=not facts.read_only)
        return Seen(facts.network, facts.decoder)

    def git(self, texts: list[str]) -> Seen:
        facts = check_git(texts, self.cfg.protected_branches, self.target_branch)
        self.classes |= facts.classes
        self.branches |= facts.branches
        if not facts.read_only:
            self.read_only = False
        for code in facts.nested:
            self.nested(code, Dialect.POSIX)
        for text in texts:
            self.path(text, writes=not facts.read_only)
        return Seen()

    def script_host(self, texts: list[str]) -> None:
        for text in texts:
            low = text.casefold()
            if "://" in low or low.startswith("\\\\") or "javascript:" in low:
                self.classes |= {C.REMOTE_SCRIPT_EXECUTION, C.NETWORK_TRANSFER}
            self.executed.add(_basename(text))

    # --- code runners -----------------------------------------------------------

    def interpreter(
        self, interp: InterpreterParts, args: list[Word], stage: Stage, position: int
    ) -> Seen:
        self.read_only = False
        self.classes |= interp.classes
        if interp.redispatch is not None:
            sub_name, start = interp.redispatch
            return self.program(sub_name, args[start:], stage, position)
        code_words = [args[i] for i in interp.code_indexes if i < len(args)]
        computed = interp.evaluator and bool(stage.groups)
        subs = tuple(sub for word in code_words for sub in word.subs)
        self.code_sources(subs, stage.groups if computed else ())
        if computed and any(
            f in w.text.casefold() for w in code_words for f in p.NETWORK_WORD_FRAGMENTS
        ):
            self.classes.add(C.REMOTE_SCRIPT_EXECUTION)
        if interp.encoded is not None:
            self.encoded(interp.encoded)
        code = " ".join(w.text for w in code_words)
        if interp.extra_code:
            code = f"{interp.extra_code} {code}".strip()
        if code and not computed:
            if interp.kind == "shell":
                self.nested(code, interp.dialect)
            else:
                self.classes |= scan_code(code)
                for token in re.split(r"[\s'\"(),;]+", code):
                    self.path(token, writes=True)
        if interp.script_index is not None:
            word = args[interp.script_index]
            self.executed.add(_basename(word.text))
            if word.subs:
                self.code_sources(word.subs, stage_groups=())
        for redirect in stage.redirects:
            self.fed_code(interp.kind, interp.dialect, redirect)
        for text in [w.text for w in args]:
            self.path(text, writes=False)
        stdin = interp.reads_stdin and not code and not computed
        return Seen(stdin_exec=stdin)

    def code_sources(self, subs: tuple[Script, ...], stage_groups: tuple[Script, ...]) -> None:
        """Code computed by substitutions: fetched => remote, otherwise obfuscation."""
        if not subs and not stage_groups:
            return
        probe = Analyzer(self.cfg, self.target_branch)
        seen = Seen()
        for sub in (*subs, *stage_groups):
            seen = seen | probe.script(sub)
        if seen.network:
            self.classes.add(C.REMOTE_SCRIPT_EXECUTION)
        elif seen.decoder or stage_groups:
            self.classes.add(C.OBFUSCATION)

    def encoded(self, text: str) -> None:
        self.classes.add(C.OBFUSCATION)
        try:
            raw = base64.b64decode(text, validate=True)
            decoded = raw.decode("utf-16-le")
        except (binascii.Error, ValueError):
            self.classes.add(C.UNPARSEABLE)
            return
        if len(decoded) > MAX_DECODED_CHARS or not decoded.strip():
            self.classes.add(C.UNPARSEABLE)
            return
        self.nested(decoded, Dialect.WINDOWS)

    def fed_code(self, kind: str, dialect: Dialect, redirect: Redirect) -> None:
        """Code given to an interpreter by a here-document, here-string or `<` file."""
        target = redirect.target
        if redirect.op == "<<" and redirect.body is not None:
            if kind == "shell":
                self.nested(redirect.body, dialect)
            else:
                self.classes |= scan_code(redirect.body)
        elif redirect.op == "<<<" and target is not None:
            self.code_sources(target.subs, ())
            if kind == "shell":
                self.nested(target.text, dialect)
        elif redirect.op == "<" and target is not None:
            self.executed.add(_basename(target.text))

    # --- result ----------------------------------------------------------------

    def finish(self) -> tuple[set[C], set[str]]:
        if self.downloaded & self.executed - {""}:
            self.classes.add(C.REMOTE_SCRIPT_EXECUTION)
        if self.read_only and not self.classes:
            self.classes.add(C.READ_ONLY_COMMAND)
        return self.classes, self.branches


def analyze(
    script: Script, config: ClassifierConfig, target_branch: str | None
) -> tuple[set[C], set[str]]:
    """Classes and push branches of one parsed reading of a command."""
    analyzer = Analyzer(config, target_branch)
    analyzer.script(script)
    return analyzer.finish()
