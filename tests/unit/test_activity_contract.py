"""The shared AI-activity contract refuses text that could forge or hide audit content."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ciso.common.activity import (
    ActionKind,
    ActivitySource,
    IdentityClaim,
    ObservedAction,
    Phase,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 18, tzinfo=UTC)


def _action(**overrides: object) -> ObservedAction:
    fields: dict[str, object] = {
        "action_id": "act_1",
        "session_id": "sess-1",
        "source": ActivitySource.HOOK,
        "phase": Phase.BEFORE,
        "kind": ActionKind.SHELL_COMMAND,
        "tool_name": "Bash",
        "received_at": NOW,
        "command": "git push origin main",
    }
    fields.update(overrides)
    return ObservedAction.model_validate(fields)


def test_a_clean_action_is_accepted_and_hides_its_command_from_repr() -> None:
    action = _action(target={"repository": "app", "branch": "main"})
    assert action.target["branch"] == "main"
    assert "git push" not in repr(action)


BAD_TEXT = [
    "a" + chr(10) + "b",
    "a" + chr(13) + "b",
    "x" + chr(0x202E) + "y",
    "x" + chr(0x2028) + "y",
    " padded",
    "tab" + chr(9),
]


@pytest.mark.parametrize("bad", BAD_TEXT)
@pytest.mark.parametrize("field", ["action_id", "session_id", "tool_name", "surface"])
def test_control_and_format_characters_are_refused(field: str, bad: str) -> None:
    with pytest.raises(ValidationError):
        _action(**{field: bad})


@pytest.mark.parametrize("target", [{"branch": "main\nforged"}, {"bad\nkey": "x"}])
def test_target_keys_and_values_are_clean(target: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        _action(target=target)


def test_identity_subject_is_clean() -> None:
    assert IdentityClaim(kind="os_account", subject=r"CORP\jdoe").subject == r"CORP\jdoe"
    with pytest.raises(ValidationError):
        IdentityClaim(kind="os_account", subject="jdoe\n")
