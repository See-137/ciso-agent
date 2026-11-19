"""Unified diff parser and diff inspection: added lines only, touched paths, refusals.

Code inside the diffs is data for the detector; none of it is executed.
"""

from __future__ import annotations

import pytest
from tests.inspection.samples import CLOUD_KEY, SERVICE_TOKEN, ids, push

from ciso.inspection import (
    MAX_CONTENT_CHARS,
    ChangeType,
    Inspector,
    MalformedDiff,
    inspect_diff,
    parse_unified_diff,
)
from ciso.inspection.diff import MAX_DIFF_FILES

pytestmark = pytest.mark.unit

MODIFY = """\
diff --git a/src/app.py b/src/app.py
index 83db48f..bf269f4 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,4 +10,5 @@ def main():
 a = 1
-b = 2
+b = 3
+c = 4
 d = 5
\\ No newline at end of file
 e = 6
"""

NEW_FILE = """\
diff --git a/docs/new.md b/docs/new.md
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/docs/new.md
@@ -0,0 +1,2 @@
+first
+second
"""

DELETE = """\
diff --git a/CLAUDE.md b/CLAUDE.md
deleted file mode 100644
index e69de29..0000000
--- a/CLAUDE.md
+++ /dev/null
@@ -1 +0,0 @@
-old rules
"""

RENAME_ONLY = """\
diff --git a/ci/build.yml b/.github/workflows/build.yml
similarity index 100%
rename from ci/build.yml
rename to .github/workflows/build.yml
"""

BINARY = """\
diff --git a/img/logo.png b/img/logo.png
index 1111111..2222222 100644
Binary files a/img/logo.png and b/img/logo.png differ
"""

QUOTED = """\
diff --git "a/dir/with space\\tx.txt" "b/dir/with space\\tx.txt"
index 1111111..2222222 100644
--- "a/dir/with space\\tx.txt"
+++ "b/dir/with space\\tx.txt"
@@ -1 +1 @@
-a
+b
"""

FORMAT_PATCH = f"""\
From 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b Mon Sep 17 00:00:00 2001
From: Dev <dev@example.invalid>
Subject: [PATCH 1/2] change

Body text
+ a commit message line that starts with plus
---
 src/app.py | 1 +
 1 file changed, 1 insertion(+)

{NEW_FILE}--
2.43.0

From 2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c Mon Sep 17 00:00:00 2001
Subject: [PATCH 2/2] second

---
{BINARY}--
2.43.0
"""


def test_modified_file_lines_and_numbers() -> None:
    (item,) = parse_unified_diff(MODIFY)
    assert (item.old_path, item.new_path, item.change) == (
        "src/app.py",
        "src/app.py",
        ChangeType.MODIFIED,
    )
    assert [(line.number, line.text) for line in item.added] == [(11, "b = 3"), (12, "c = 4")]
    assert [(line.number, line.text) for line in item.removed] == [(11, "b = 2")]
    assert "b = 3" not in repr(item)


def test_new_deleted_renamed_binary_and_quoted() -> None:
    (new,) = parse_unified_diff(NEW_FILE)
    assert new.change is ChangeType.ADDED
    assert new.touched_paths == ("docs/new.md",)
    (gone,) = parse_unified_diff(DELETE)
    assert gone.change is ChangeType.DELETED
    assert gone.touched_paths == ("CLAUDE.md",)
    (moved,) = parse_unified_diff(RENAME_ONLY)
    assert moved.change is ChangeType.RENAMED
    assert moved.touched_paths == (".github/workflows/build.yml", "ci/build.yml")
    (blob,) = parse_unified_diff(BINARY)
    assert blob.binary
    assert blob.new_path == "img/logo.png"
    assert blob.added == ()
    (quoted,) = parse_unified_diff(QUOTED)
    assert quoted.new_path == "dir/with space\tx.txt"


def test_format_patch_series_is_parsed() -> None:
    files = parse_unified_diff(FORMAT_PATCH)
    assert [f.new_path for f in files] == ["docs/new.md", "img/logo.png"]
    assert [line.text for line in files[0].added] == ["first", "second"]


def test_plain_unified_diff_without_git_header() -> None:
    text = "--- a/x.txt\t2026-01-01\n+++ b/x.txt\t2026-01-02\n@@ -1 +1,2 @@\n x\n+y\n"
    (item,) = parse_unified_diff(text)
    assert item.new_path == "x.txt"
    assert [line.text for line in item.added] == ["y"]


def test_crlf_and_no_text() -> None:
    (item,) = parse_unified_diff(NEW_FILE.replace("\n", "\r\n"))
    assert [line.text for line in item.added] == ["first", "second"]
    assert parse_unified_diff("") == ()
    assert parse_unified_diff("just some words\nnothing else\n") == ()


@pytest.mark.parametrize(
    "text",
    [
        MODIFY.replace("@@ -10,4 +10,5 @@", "@@ -10,4 +10,9 @@"),  # ends inside a hunk
        MODIFY.replace("+c = 4\n", "+c = 4\n+hidden = 1\n"),  # more lines than declared
        MODIFY + "+smuggled = 1\n",  # a line after the hunk ends
        MODIFY.replace("index 83db48f..bf269f4 100644", "weird header"),
        NEW_FILE + "--- a/x\nnot a new-file header\n",
        "diff --git a/x b/x\n--- a/x\n+++ b/x\nno hunk here\n",
        'diff --git "a/x b/x\n',
        "diff --git ab\n",
        QUOTED.replace("\\tx.txt", "\\qx.txt"),
        MODIFY.replace(" a = 1\n", "?a = 1\n"),
    ],
)
def test_malformed_diffs_raise(text: str) -> None:
    with pytest.raises(MalformedDiff):
        parse_unified_diff(text)


def test_hunk_line_with_unknown_tag_is_refused_where_it_occurs() -> None:
    # Counts still balance after the bad line, so only the per-line check can catch it.
    text = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n?junk\n a\n"
    with pytest.raises(MalformedDiff, match="does not match its header"):
        parse_unified_diff(text)


def test_unknown_file_header_is_named() -> None:
    text = MODIFY.replace("index 83db48f..bf269f4 100644", "weird header")
    with pytest.raises(MalformedDiff, match="unknown file header at diff line 2"):
        parse_unified_diff(text)


def test_too_many_files_is_malformed() -> None:
    one = "diff --git a/f{n} b/f{n}\nold mode 100644\nnew mode 100755\n"
    text = "".join(one.format(n=n) for n in range(MAX_DIFF_FILES + 1))
    with pytest.raises(MalformedDiff, match="too many files"):
        parse_unified_diff(text)
    assert len(parse_unified_diff("".join(one.format(n=n) for n in range(3)))) == 3


def test_only_added_lines_are_inspected() -> None:
    text = MODIFY.replace("-b = 2", f"-old = '{CLOUD_KEY}'").replace(
        "+c = 4", f"+key = '{SERVICE_TOKEN}'"
    )
    result = inspect_diff(text, action_id="act_1")
    assert ids(result) == ["secret.service_token"]
    assert result.findings[0].location == "src/app.py:12:8"
    assert result.complete is True
    assert set(result.checks_run) == {
        "inspection.size",
        "inspection.diff",
        "inspection.paths",
        "inspection.secrets",
        "inspection.code_risk",
        "inspection.scan_suppression",
    }


def test_risky_code_in_added_lines_only() -> None:
    text = MODIFY.replace("-b = 2", "-r = eval(x)").replace("+c = 4", "+r = eval(y)")
    result = inspect_diff(text, action_id="a")
    assert ids(result) == ["code.dynamic_eval"]


def test_touched_sensitive_paths_are_reported() -> None:
    assert ids(inspect_diff(RENAME_ONLY, action_id="a")) == ["path.ci_pipeline"]
    assert ids(inspect_diff(DELETE, action_id="a")) == ["path.assistant_config"]


def test_binary_change_makes_the_result_incomplete() -> None:
    result = inspect_diff(BINARY, action_id="a")
    assert result.complete is False
    assert ids(result) == ["inspection.binary_not_inspected"]
    assert result.findings[0].location == "img/logo.png"


def test_malformed_empty_and_oversized_diffs_are_incomplete() -> None:
    bad = inspect_diff(MODIFY + "+smuggled\n", action_id="a")
    assert (bad.complete, ids(bad)) == (False, ["inspection.diff_malformed"])
    assert "diff line" in bad.findings[0].location
    assert "inspection.secrets" not in bad.checks_run
    empty = inspect_diff("", action_id="a")
    assert (empty.complete, ids(empty)) == (False, ["inspection.diff_empty"])
    big = inspect_diff("x" * (MAX_CONTENT_CHARS + 1), action_id="a")
    assert (big.complete, ids(big)) == (False, ["inspection.too_large"])
    ok = inspect_diff(NEW_FILE, action_id="a")
    assert (ok.complete, ids(ok)) == (True, [])


def test_inspector_treats_push_content_as_a_diff() -> None:
    inspector = Inspector()
    result = inspector.inspect(push(RENAME_ONLY))
    assert ids(result) == ["path.ci_pipeline"]
    assert result.action_id == "act_d"
    assert inspector.inspect_diff(RENAME_ONLY, action_id="z") == inspect_diff(
        RENAME_ONLY, action_id="z"
    )
    missing = inspector.inspect(push(None))
    assert (missing.complete, ids(missing)) == (False, ["inspection.content_missing"])
