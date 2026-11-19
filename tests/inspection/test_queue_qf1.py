"""Fix round QF1, inspection side (queue Q13).

Every sensitive-path decision goes through `ciso.common.paths` (`normalise_path`,
`may_match`). Directory and archive targets (`cp -r`, `tar -x`, `unzip -d`, `7z -o`,
`Expand-Archive`, `robocopy`, `rsync`, a copy into a directory) are path findings when
the destination may contain a sensitive path: when it is, or is inside, a directory a
path rule names (`.claude`, `.ssh`, `.github/workflows`, `.git/hooks`...). A destination
that is the working directory, a parent, home, a root or unknown is one medium finding,
`path.bulk_write_broad` (governance answers such a command `bulk_write`, ask).
"""

from __future__ import annotations

import pytest
from tests.inspection.samples import command, ids, j, prompt, push, write

import ciso.common.paths as common_paths
from ciso.common.activity import Severity
from ciso.governance.bulk_write import bulk_destinations as governance_destinations
from ciso.inspection import Inspector, sensitive_path_rules
from ciso.inspection import paths as inspection_paths
from ciso.inspection.bulk_targets import bulk_destinations as inspection_destinations

pytestmark = pytest.mark.unit

INSPECTOR = Inspector()
BROAD = "path.bulk_write_broad"


def test_inspection_decides_paths_with_the_shared_normaliser_and_matcher() -> None:
    assert inspection_paths.normalise_path is common_paths.normalise_path  # type: ignore[attr-defined]
    assert inspection_paths.may_match is common_paths.may_match  # type: ignore[attr-defined]
    assert not hasattr(inspection_paths, "posixpath")


@pytest.mark.parametrize(
    ("path", "rule_id"),
    [
        (r"C:\Repo\Sub\..\.ENV. ", "path.env_file"),
        (r"\\.\D:\x\.mcp.json", "path.assistant_config"),
        ("/??/C:/repo/.git/hooks/pre-push", "path.git_hook"),
        ("../../.env", "path.env_file"),
        ("./a//b/./.npmrc", "path.package_registry_config"),
    ],
)
def test_normalised_forms_still_match(path: str, rule_id: str) -> None:
    assert rule_id in {r.rule_id for r in sensitive_path_rules(path)}


@pytest.mark.parametrize(
    ("text", "rule_id"),
    [
        (j("cp -r x ", ".claude"), "path.assistant_config"),
        (j("cp hooks.json ", ".claude/"), "path.assistant_config"),
        (j("tar -xf a.tar -C ~/.ss", "h"), "path.ssh_access"),
        (j("unzip a.zip -d ", ".github"), "path.ci_pipeline"),
        (j("unzip a.zip -d ", ".github/workflows"), "path.ci_pipeline"),
        (j("7z x a.7z -o", ".git/hooks"), "path.git_hook"),
        (j("Expand-Archive a.zip -DestinationPath ", ".vscode"), "path.editor_autorun"),
        (j("robocopy src ", ".husky", " /E"), "path.git_hook"),
        (j("cd ", ".claude", " && tar -xf a.tar"), "path.assistant_config"),
        (j("rsync -a src/ ~/", ".aws/"), "path.cloud_credentials"),
        (j("mv pkg ", "proj/.claude/hooks"), "path.assistant_config"),
    ],
)
def test_q13_directory_and_archive_targets_are_path_findings(text: str, rule_id: str) -> None:
    result = INSPECTOR.inspect(command(text))
    assert rule_id in ids(result)
    assert "inspection.paths" in result.checks_run


@pytest.mark.parametrize(
    "text",
    ["tar -xf a.tar", "unzip a.zip -d ..", "cp -r x ~", "Expand-Archive a.zip"],
)
def test_q13_broad_destinations_are_one_medium_finding(text: str) -> None:
    result = INSPECTOR.inspect(command(text))
    broad = [f for f in result.findings if f.check_id == BROAD]
    assert len(broad) == 1
    assert broad[0].severity is Severity.MEDIUM
    assert broad[0].category == "sensitive_path"
    assert all(f.severity is not Severity.CRITICAL for f in result.findings), ids(result)
    assert result.complete is True


def test_q13_a_plain_copy_into_the_working_directory_is_not_a_bulk_write() -> None:
    assert BROAD not in ids(INSPECTOR.inspect(command("cp a.txt .")))
    assert BROAD in ids(INSPECTOR.inspect(command("mv pkg ..")))


def test_q13_an_unknown_destination_may_be_any_sensitive_directory() -> None:
    """A variable destination may hold `.claude`: like an unknown file path, it is
    reported against every directory rule, and as a broad destination."""
    found = set(ids(INSPECTOR.inspect(command("cp -r x $DEST"))))
    assert {BROAD, "path.assistant_config", "path.git_hook", "path.ssh_access"} <= found


@pytest.mark.parametrize(
    "text",
    [
        "cp -r src build/out",
        "tar -xf a.tar -C build/tmp",
        "unzip a.zip -d out",
        "tar -tf a.tar",
        "cp a.txt docs/",
        "7z x a.7z -oout",
        "rsync -a src/ backup/",
    ],
)
def test_q13_ordinary_directory_targets_stay_clean(text: str) -> None:
    result = INSPECTOR.inspect(command(text))
    assert [f for f in result.findings if f.category == "sensitive_path"] == []


PARITY = [
    "cp -r vendor/pkg .", "cp -r -t . a b", "cp a.txt .", "mv a b", "rsync -a h:src/ .",
    "rsync -a src/ h:dst/", "robocopy a b /E", "xcopy a /s", "xcopy a b", "tar -xzf a.tgz",
    "tar xf a.tar -C out", "tar -tf a.tar", "unzip -l a.zip", "unzip a.zip -d out",
    "7z x a.7z -oout", "7z l a.7z", "Copy-Item -Recurse a -Destination b",
    "Copy-Item a b", "Expand-Archive -Path a.zip -DestinationPath b",
    "cp --recur x .", "tar -xf a.tar --directory=..", "Copy-Item -Recurse:1 x -Destination:.",
    "cp --zork x out", "tar xfC a.tar ..", "unzip -Q a.zip -d out", "robocopy src /E dst",
    "tar -xPf a.tar -C out", "7z x a.7z -spf -oout", "7z x a.7z -y -oout", "unzip -: a.zip",
]  # fmt: skip


@pytest.mark.parametrize("text", PARITY)
def test_the_two_bulk_readings_agree(text: str) -> None:
    """Inspection may not import governance, so it carries its own copy of the reading;
    the two must give the same answer."""
    name, *args = text.split()
    key = name.casefold()
    assert inspection_destinations(key, args) == governance_destinations(key, args)


# --- review H3 (a): scanner suppression is a HIGH finding --------------------------------

SUPPRESSION = "scan_suppression"


def _diff(path: str, added: str, removed: str = "") -> str:
    minus = f"-{removed}\n" if removed else ""
    old_count = 1 if removed else 0
    return (
        f"diff --git a/{path} b/{path}\nindex 1111111..2222222 100644\n--- a/{path}\n"
        f"+++ b/{path}\n@@ -1,{old_count} +1,1 @@\n{minus}+{added}\n"
    )


def _suppressions(result: object) -> list[str]:
    return [
        f.check_id
        for f in result.findings  # type: ignore[attr-defined]
        if f.category == SUPPRESSION and f.severity is Severity.HIGH
    ]


@pytest.mark.parametrize(
    "path", [".gitleaks.toml", "sub/.gitleaks.toml", ".gitleaksignore", ".semgrepignore"]
)
def test_h3_scanner_configuration_files_are_findings(path: str) -> None:
    assert _suppressions(INSPECTOR.inspect(write("x", path=path))) == ["suppression.scanner_config"]
    assert "suppression.scanner_config" in _suppressions(INSPECTOR.inspect(push(_diff(path, "x"))))


@pytest.mark.parametrize(
    "line",
    ["*.cfg -diff", "*.png binary", "*.cfg diff=plain", "*.dat filter=hide", "[attr]h -diff"],
)
def test_h3_gitattributes_lines_that_hide_content_are_findings(line: str) -> None:
    assert _suppressions(INSPECTOR.inspect(write(line, path=".gitattributes"))) == [
        "suppression.gitattributes"
    ]
    diff = push(_diff("sub/.gitattributes", line))
    assert "suppression.gitattributes" in _suppressions(INSPECTOR.inspect(diff))


@pytest.mark.parametrize(
    "line", ["*.sh text eol=lf", "# -diff in a comment", "*.md linguist-documentation"]
)
def test_h3_ordinary_gitattributes_lines_stay_clean(line: str) -> None:
    assert _suppressions(INSPECTOR.inspect(write(line, path=".gitattributes"))) == []


def test_h3_removing_a_hiding_gitattributes_line_is_not_a_finding() -> None:
    diff = push(_diff(".gitattributes", "*.sh text", removed="*.cfg -diff"))
    assert _suppressions(INSPECTOR.inspect(diff)) == []


@pytest.mark.parametrize(
    "line",
    [
        "x = run(cmd)  # nosec",
        "x = run(cmd)  # nosec B602",
        "eval(code)  // nosemgrep: rule.id",
        "token = load()  # gitleaks:allow",
        "x = 1  # noqa: S105",
        "x = 1  # noqa: E501, S603",
        "x = 1  # NOSEC",
    ],
)
def test_h3_inline_suppression_markers_are_findings(line: str) -> None:
    assert _suppressions(INSPECTOR.inspect(write(line, path="app.py"))) == [
        "suppression.inline_marker"
    ]
    assert "suppression.inline_marker" in _suppressions(
        INSPECTOR.inspect(push(_diff("app.py", line)))
    )
    assert "suppression.inline_marker" in _suppressions(
        INSPECTOR.inspect(command(j("echo '", line, "' >> app.py")))
    )


@pytest.mark.parametrize(
    "line", ["x = 1  # noqa: E501", "nosecurity_review = True", "x = 1  # noqa", "# sec note"]
)
def test_h3_ordinary_comments_stay_clean(line: str) -> None:
    assert _suppressions(INSPECTOR.inspect(write(line, path="app.py"))) == []


def test_h3_a_removed_marker_is_not_a_finding() -> None:
    diff = push(_diff("app.py", "x = run(cmd)", removed="x = run(cmd)  # nosec"))
    assert _suppressions(INSPECTOR.inspect(diff)) == []


def test_h3_a_prompt_mentioning_a_marker_is_not_a_finding() -> None:
    assert _suppressions(INSPECTOR.inspect(prompt("why does # nosec exist?"))) == []
