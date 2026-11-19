"""Code runners in the analyzer: shells, interpreters, evaluators and the code they get.

Code handed over in a string (`sh -c`, `cmd /c`, `powershell -Command`,
`-EncodedCommand`, `eval`, `iex`) is read again one level deeper. Code computed by a
substitution is remote script execution when the substitution fetches, obfuscation
otherwise. Code fed by a here-document, a here-string or a `<` file is read too.
"""

from __future__ import annotations

import base64
import binascii
import re

from ciso.governance import programs as p
from ciso.governance.analysis_paths import PathChecks
from ciso.governance.analysis_state import Seen
from ciso.governance.classes import CommandClass as C
from ciso.governance.code_scan import scan_code
from ciso.governance.lexer_types import Dialect, Redirect, Script, Stage, Word
from ciso.governance.wrappers import InterpreterParts

#: Longest decoded `-EncodedCommand` text read.
MAX_DECODED_CHARS = 8000


def basename(text: str) -> str:
    return re.split(r"[\\/]", text)[-1].casefold()


class CodeRunners(PathChecks):
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
            self.executed.add(basename(word.text))
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
        probe = type(self)(self.cfg)
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
            self.executed.add(basename(target.text))

    def computed_code(self, texts: list[str]) -> None:
        """A script block built from text, or code chosen at run time (review H6)."""
        if any(f in t.casefold() for t in texts for f in p.COMPUTED_CODE_FRAGMENTS):
            self.computed = True
            self.classes.add(C.OBFUSCATION)

    def script_block_runner(self, args: list[Word]) -> None:
        """`Invoke-Command`, `Start-Job`: a script block from a variable or an expression is
        computed code; a remote target is a network transfer."""
        if any(w.dynamic for w in args):
            self.computed = True
            self.classes.add(C.OBFUSCATION)
        if any(w.text.casefold() in p.REMOTE_TARGET_PARAMETERS for w in args):
            self.classes.add(C.NETWORK_TRANSFER)
