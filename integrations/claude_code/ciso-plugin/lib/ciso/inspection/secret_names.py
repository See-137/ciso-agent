"""Helpers of the secret scanner: which names hold secrets, and values split into pieces.

Review M4. A name is split into words (any separator, camelCase, any case) and is a
secret's name when its LAST word is a secret word (`password`, `pass`, `pwd`, `secret`,
`token`, ...) or is `key` after a qualifying word (`signing_key`, `apiKey`,
`AWS_SECRET_ACCESS_KEY`). Only the last word counts, so `token_type`, `password_file` and
`signing_key_id` are not secrets' names, and a bare `key` is not one either.

A value built from string pieces on ONE line (`"ab" + "cd"`, `'ab' 'cd'`, `"ab" . "cd"`)
is joined and scanned as one value. Pieces spread over several lines are not joined: a
line scanner cannot prove a secret is absent, it can only find the shapes it knows.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple

#: Last words that make a name a secret's name.
SECRET_WORDS: Final = frozenset(
    {
        "password", "passwd", "pass", "pwd", "passphrase", "passcode", "secret", "secrets",
        "token", "credential", "credentials", "apikey", "secretkey", "accesskey",
        "privatekey", "clientsecret", "authtoken",
    }
)  # fmt: skip
#: Words that make a following `key` a secret's name.
KEY_QUALIFIERS: Final = frozenset(
    {
        "api", "access", "secret", "private", "signing", "sign", "encryption", "encrypt",
        "master", "hmac", "client", "auth", "shared", "service", "deploy", "ssh", "webhook",
        "app", "account", "storage", "session", "jwt", "license", "subscription",
    }
)  # fmt: skip
#: Whole names that are ordinary environment variables despite their last word.
NOT_SECRET_NAMES: Final = frozenset({"pwd", "oldpwd"})

_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_PIECE = r"(?:\"[^\"\n]{0,512}\"|'[^'\n]{0,512}')"
#: Two or more quoted pieces joined by `+`, `.`, `..`, `&` or nothing but spaces.
_RUN = re.compile(rf"{_PIECE}(?:[ \t]*(?:\+|\.\.?|&)?[ \t]*{_PIECE})+")
_INNER = re.compile(_PIECE)
#: A YAML block scalar indicator: `|` or `>`, optional chomping and indent digits.
_BLOCK = re.compile(r"[|>][+-]?[0-9]?|[|>][0-9][+-]?")


def name_words(name: str) -> list[str]:
    return [word.lower() for word in _WORD.findall(name)]


def is_secret_name(name: str) -> bool:
    """True when `name` (as written: any case and separators) names a secret."""
    if name.lower().strip("_.-") in NOT_SECRET_NAMES:
        return False
    words = name_words(name)
    if not words:
        return False
    last = words[-1]
    if last in SECRET_WORDS:
        return True
    return last == "key" and len(words) > 1 and words[-2] in KEY_QUALIFIERS


class Joined(NamedTuple):
    start: int
    end: int
    value: str


def joined_strings(text: str) -> list[Joined]:
    """Every run of string pieces joined on the line, with its span and joined content."""
    out = []
    for match in _RUN.finditer(text):
        pieces = [piece[1:-1] for piece in _INNER.findall(match.group())]
        out.append(Joined(match.start(), match.end(), "".join(pieces)))
    return out


def is_block_indicator(raw: str) -> bool:
    return bool(_BLOCK.fullmatch(raw))


def indent_of(text: str) -> int:
    return len(text) - len(text.lstrip(" \t"))
