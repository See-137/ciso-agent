"""Inspector orchestration: kinds, bounds, missing content, truncation, determinism."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from tests.inspection.samples import (
    CLOUD_KEY,
    PEM_HEADER,
    command,
    ids,
    prompt,
    write,
)

from ciso.common.activity import (
    MAX_FINDINGS,
    MAX_INSPECTION_CHARS,
    ActionKind,
    InspectionInput,
    Severity,
)
from ciso.common.errors import ValidationFailed
from ciso.inspection import MAX_CONTENT_CHARS, MAX_LINE_CHARS, RULE_TABLE, Inspector

pytestmark = pytest.mark.unit

INSPECTOR = Inspector()


def test_clean_write_is_complete_and_lists_every_check() -> None:
    result = INSPECTOR.inspect(write("print('hello')\n", path="src/app.py"))
    assert result.complete is True
    assert result.findings == ()
    assert result.checks_run == (
        "inspection.size",
        "inspection.paths",
        "inspection.secrets",
        "inspection.code_risk",
        "inspection.scan_suppression",
    )


def test_content_over_the_limit_is_refused_when_the_input_is_built() -> None:
    big = CLOUD_KEY + "a" * MAX_CONTENT_CHARS
    with pytest.raises(ValidationError) as caught:
        write(big, path="x.txt")
    assert CLOUD_KEY not in str(caught.value)


def test_the_inspection_limit_is_the_contract_bound() -> None:
    assert MAX_CONTENT_CHARS == MAX_INSPECTION_CHARS


def test_findings_carry_the_rule_table_remediation() -> None:
    result = INSPECTOR.inspect(write(f"key {CLOUD_KEY}" + chr(10), path="x.txt"))
    found = [f for f in result.findings if f.check_id == "secret.cloud_access_key"]
    assert found
    assert found[0].remediation == RULE_TABLE["secret.cloud_access_key"].remediation
    assert found[0].remediation


def test_content_at_the_limit_is_inspected() -> None:
    text = (CLOUD_KEY + "\n").ljust(MAX_CONTENT_CHARS, "a")
    text = "\n".join(text[i : i + 1000] for i in range(0, len(text), 1001))[:MAX_CONTENT_CHARS]
    result = INSPECTOR.inspect(write(text, path="x.txt"))
    assert result.complete is True
    assert "secret.cloud_access_key" in ids(result)


def test_too_long_line_is_incomplete_but_other_lines_are_scanned() -> None:
    text = f"ok\n{'a' * (MAX_LINE_CHARS + 1)}\nkey {CLOUD_KEY}\n"
    result = INSPECTOR.inspect(write(text, path="x.txt"))
    assert result.complete is False
    assert ids(result) == ["inspection.line_too_long", "secret.cloud_access_key"]
    assert result.findings[0].location == "x.txt:2"
    exact = INSPECTOR.inspect(write("a" * MAX_LINE_CHARS, path="x.txt"))
    assert exact.complete is True


@pytest.mark.parametrize(
    "item",
    [
        write(None, path="x.txt"),
        prompt(None),
        command(None),
        InspectionInput(action_id="a", kind=ActionKind.FILE_EDIT, path="x.py"),
        InspectionInput(action_id="a", kind=ActionKind.GIT_COMMIT),
    ],
)
def test_missing_content_is_incomplete(item: InspectionInput) -> None:
    result = INSPECTOR.inspect(item)
    assert result.complete is False
    assert "inspection.content_missing" in ids(result)


def test_kinds_without_content_need_none() -> None:
    item = InspectionInput(action_id="a", kind=ActionKind.SESSION_START)
    result = INSPECTOR.inspect(item)
    assert (result.complete, result.checks_run, result.findings) == (
        True,
        ("inspection.size",),
        (),
    )


def test_prompt_is_checked_for_secrets_only() -> None:
    result = INSPECTOR.inspect(prompt(f"run eval(x) with {CLOUD_KEY}"))
    assert ids(result) == ["secret.cloud_access_key"]
    assert "inspection.code_risk" not in result.checks_run


def test_command_secret_is_located_in_the_command() -> None:
    result = INSPECTOR.inspect(command(f"export K={CLOUD_KEY}"))
    assert [(f.check_id, f.location) for f in result.findings] == [
        ("secret.cloud_access_key", "command:1:10")
    ]


def test_findings_over_the_cap_keep_the_worst_and_mark_incomplete() -> None:
    lines = [f"k{i} = {CLOUD_KEY}" for i in range(MAX_FINDINGS + 50)] + [PEM_HEADER]
    result = INSPECTOR.inspect(prompt("\n".join(lines)))
    assert len(result.findings) == MAX_FINDINGS
    assert result.complete is False
    assert result.findings[-1].check_id == "inspection.findings_truncated"
    assert result.findings[-1].location == "52 findings dropped"  # 251 found, 199 kept
    assert "secret.private_key" in ids(result)
    assert result.worst is Severity.CRITICAL


def test_findings_at_the_cap_are_kept_whole() -> None:
    lines = [f"k{i} = {CLOUD_KEY}" for i in range(MAX_FINDINGS)]
    result = INSPECTOR.inspect(prompt("\n".join(lines)))
    assert len(result.findings) == MAX_FINDINGS
    assert result.complete is True


def test_inspection_is_deterministic() -> None:
    item = write(f"DEBUG = True\nkey = {CLOUD_KEY}\n", path=".env")
    assert Inspector().inspect(item) == Inspector().inspect(item)


@pytest.mark.parametrize("bad", ["tests", ["Bad Id"], [""], [1]])
def test_required_sandbox_checks_are_validated(bad: object) -> None:
    with pytest.raises(ValidationFailed):
        Inspector(required_sandbox_checks=bad)  # type: ignore[arg-type]


def test_required_sandbox_checks_accept_ids() -> None:
    Inspector(required_sandbox_checks=("secret_scan", "tests"))
