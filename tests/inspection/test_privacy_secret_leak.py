"""No secret value or content reaches a result, its repr, its JSON or an error message."""

from __future__ import annotations

import pytest
from tests.inspection.samples import (
    SECRET_CASES,
    SERVICE_TOKEN,
    command,
    prompt,
    push,
    write,
)

from ciso.common.activity import InspectionResult
from ciso.inspection import Inspector, MalformedDiff, from_sandbox_report, parse_unified_diff

pytestmark = pytest.mark.privacy

INSPECTOR = Inspector()


def _renderings(result: InspectionResult) -> list[str]:
    texts = [result.model_dump_json(), repr(result), str(result)]
    texts += [repr(f) for f in result.findings] + [f.detail + f.location for f in result.findings]
    return texts


def _assert_absent(value: str, result: InspectionResult) -> None:
    assert result.findings, "positive evidence: something must have been found"
    for text in _renderings(result):
        assert value not in text


def _diff(line: str) -> str:
    return (
        "diff --git a/app/cfg.txt b/app/cfg.txt\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/app/cfg.txt\n@@ -0,0 +1 @@\n+" + line + "\n"
    )


@pytest.mark.parametrize(("text", "rule_id", "value"), SECRET_CASES)
def test_value_absent_in_every_context(text: str, rule_id: str, value: str) -> None:
    for item in (prompt(text), write(text, path="cfg.txt"), command(text), push(_diff(text))):
        result = INSPECTOR.inspect(item)
        assert rule_id in [f.check_id for f in result.findings]
        _assert_absent(value, result)


def test_input_repr_hides_content() -> None:
    item = write(f"key {SERVICE_TOKEN}", path="a.txt")
    assert SERVICE_TOKEN not in repr(item)
    assert SERVICE_TOKEN not in str(item)


def test_malformed_diff_message_holds_no_content() -> None:
    text = _diff("ok") + f"+{SERVICE_TOKEN}\n"
    with pytest.raises(MalformedDiff) as caught:
        parse_unified_diff(text)
    assert SERVICE_TOKEN not in str(caught.value)
    _assert_absent(SERVICE_TOKEN, INSPECTOR.inspect(push(text)))


def test_parsed_lines_do_not_show_text_in_repr() -> None:
    (item,) = parse_unified_diff(_diff(SERVICE_TOKEN))
    assert SERVICE_TOKEN not in repr(item)


def test_sandbox_message_with_secret_is_not_kept() -> None:
    report = {
        "job_id": "j1",
        "checks": [
            {
                "check_id": "secret_scan",
                "status": "failed",
                "findings": [
                    {
                        "rule": "token",
                        "category": "secret",
                        "severity": "high",
                        "path": "a.py",
                        "line": 3,
                        "message": f"value {SERVICE_TOKEN}",
                    }
                ],
            }
        ],
    }
    result = from_sandbox_report(report, action_id="a", required_checks=("secret_scan",))
    _assert_absent(SERVICE_TOKEN, result)


def test_sandbox_message_is_redacted_by_the_vault_shapes() -> None:
    # A bearer value with no digit escapes our detector's shape but not the vault redactor.
    message = "header authorization=opaqueValueWithoutDigitsHere"
    report = {
        "job_id": "j1",
        "checks": [
            {
                "check_id": "s",
                "status": "failed",
                "findings": [
                    {
                        "rule": "r",
                        "category": "secret",
                        "severity": "low",
                        "path": "",
                        "line": None,
                        "message": message,
                    }
                ],
            }
        ],
    }
    result = from_sandbox_report(report, action_id="a", required_checks=("s",))
    _assert_absent("opaqueValueWithoutDigitsHere", result)
