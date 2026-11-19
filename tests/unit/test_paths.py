"""`ciso.common.paths`: one normaliser for dangerous-path decisions, and `may_match`.

Sensitive names are built from halves so this file holds no complete sensitive path.
"""

from __future__ import annotations

import pytest

from ciso.common.paths import (
    UNKNOWN_LOCATION,
    NormalisedPath,
    join_paths,
    may_match,
    normalise_path,
)

pytestmark = pytest.mark.unit

SSH = ".s" + "sh"
KEY = "id_r" + "sa"
MCP = ".m" + "cp.json"


def norm(text: str, *, windows: bool = True) -> NormalisedPath:
    return normalise_path(text, windows=windows)


@pytest.mark.parametrize(
    ("text", "segments"),
    [
        ("A/B/../C/./d", ("a", "c", "d")),
        ("C:\\Users\\X\\" + SSH, ("c:", "users", "x", SSH)),
        ("/etc//x", ("", "etc", "x")),
        (MCP + ".", (MCP,)),
        (MCP + " . ", (MCP,)),
        (MCP + "::$DATA", (MCP,)),
        (MCP + ":stream:$data", (MCP,)),
        ("\\\\?\\C:\\x\\y", ("c:", "x", "y")),
        ("C:/Users/u/ASSIST~1/settings.json", ("c:", "users", "u", "*", "settings.json")),
        ("~/" + SSH, ("~", SSH)),
        ("$HOME/" + SSH, ("~", SSH)),
        ("${HOME}/" + SSH, ("~", SSH)),
        ("%USERPROFILE%\\" + SSH, ("~", SSH)),
        ("$env:USERPROFILE\\" + SSH, ("~", SSH)),
        ("~bob/" + SSH, ("~", SSH)),
        ("~+/x", ("**", "x")),
        (".s{sh,x}/k", (".s*", "k")),
        ("../../x", ("..", "..", "x")),
    ],
)
def test_normalise(text: str, segments: tuple[str, ...]) -> None:
    result = norm(text)
    assert result.segments == segments
    assert not result.unknown


def test_posix_mode_keeps_windows_spellings() -> None:
    assert norm("a\\b.", windows=False).segments == ("a\\b.",)
    assert norm("SSH~1", windows=False).segments == ("ssh~1",)


@pytest.mark.parametrize("text", ["$X/k", "a/${Y}", "%TEMP%/x", "a\x00b", "$(x)/y", "x" * 5000])
def test_unknown_text_is_flagged(text: str) -> None:
    assert norm(text).unknown


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("**/" + SSH + "/**", "~/" + SSH + "/" + KEY, True),
        ("**/" + SSH + "/**", "~/.ss[h]/x", True),
        ("**/" + SSH + "/**", "~/.ss?/x", True),
        ("**/" + SSH, "~/.ss[!h]", False),
        ("**/" + SSH, "~/.ss[a-g]", False),
        ("**/" + SSH, "~/.ss[g-i]", True),
        ("**/id_rsa*", "id_*", True),
        ("**/.env", ".en[v]", True),
        ("**/.env", "*.py", False),
        ("**/*.pem", "foo.*bar", False),
        ("**/.*/settings.json", "c:/u/ASSIST~1/settings.json", True),
        ("**/" + MCP, MCP + "::$DATA", True),
        ("/etc/shadow", "/etc/shadow", True),
        ("/etc/shadow", "etc/shadow", False),
        ("/etc/shadow", "/etc/sha*", True),
        ("/etc/shadow", "*/shadow", False),
        ("**/.docker/config.json", "src/config.json", False),
        ("main", "MAIN", True),
        ("**/" + SSH + "/**", "$X", True),
    ],
)
def test_may_match(pattern: str, text: str, expected: bool) -> None:
    assert may_match(pattern, norm(text)) is expected


def test_empty_path_matches_nothing() -> None:
    assert not may_match("**", norm("."))
    assert norm(".").empty


def test_join_resolves_relative_paths_against_a_known_directory() -> None:
    base = norm("~/.docker")
    joined = join_paths(base, norm("config.json"))
    assert joined.segments == ("~", ".docker", "config.json")
    assert may_match("**/.docker/config.json", joined)
    assert join_paths(base, norm("/etc/x")).segments == ("", "etc", "x")
    assert join_paths(base, norm("../x")).segments == ("~", "x")


def test_unknown_location_makes_every_relative_name_a_match() -> None:
    anywhere = join_paths(UNKNOWN_LOCATION, norm("config.json"))
    assert may_match("**/.docker/config.json", anywhere)
    assert may_match("**/" + SSH + "/**", join_paths(UNKNOWN_LOCATION, norm("feature")))
    assert not may_match("**/" + SSH + "/**", norm("feature"))


def test_long_patterns_and_paths_terminate() -> None:
    deep = "/".join(["a*"] * 100)
    assert may_match("**/" + "/".join(["*a"] * 60), norm(deep)) in (True, False)
