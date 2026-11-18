"""The shipped tools: drafts in a local outbox, verified by reading the outbox.

Blueprint 9.1 L2 (channel-specific authorization), 9.5 (do not infer success from a tool
response); FR-026; plan row T2.4; plan gap G13; OD-13.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from tests.execution.broker_world import World
from tests.execution.conftest import WorldFactory
from tests.fakes.core import FakeRedactor

from ciso.common.enums import AuthorityLevel
from ciso.common.errors import AuthorizationError
from ciso.execution import (
    OWNER_NOTICE_OPERATION,
    TICKET_DRAFT_OPERATION,
    ChannelRegistry,
    ExecutionRefused,
    ExecutionState,
    RefusalReason,
    Tool,
    ToolCall,
    ToolOutcome,
    ToolRegistry,
    ToolResult,
    build_outbox_tools,
    outbox_tools,
)
from ciso.execution.outbox_tools import OutboxDrafts, draft_file_name

pytestmark = pytest.mark.broker

SECRET = "token-9f3c1a77d2e04b55"
TICKET = {"channel": "sec_tickets", "title": "Rotate the key", "body": "It is old."}
NOTICE = {
    "channel": "sec_tickets",
    "owner": "person:p1",
    "subject": "Review needed",
    "message": "Please look.",
}


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "outbox"


@pytest.fixture
def approved_channels(channels: ChannelRegistry) -> ChannelRegistry:
    seen = channels.propose("agent_ciso", "sec_tickets", "security_queue", "ticket drafts")
    channels.approve(
        "human_admin",
        "sec_tickets",
        seen.target,
        version=seen.version,
        purpose_digest=seen.purpose_digest,
    )
    return channels


@pytest.fixture
def outbox_world(
    world_factory: WorldFactory, picky_audit: Any, approved_channels: ChannelRegistry, root: Path
) -> World:
    tools = build_outbox_tools(root, approved_channels, FakeRedactor(SECRET))
    world = world_factory(picky_audit, extra_tools=tools)
    world.context.is_channel_approved = approved_channels.is_approved  # type: ignore[method-assign]
    return world


def ticket(world: World, key: str = "idem-1", **arguments: Any) -> Any:
    spec = world.registry.get(TICKET_DRAFT_OPERATION).spec
    return world.envelope(spec, key=key, arguments={**TICKET, **arguments})


def call_for(world: World, envelope: Any) -> ToolCall:
    return world.registry.call_for(world.validator.validate(envelope), world.secrets)


def files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []


class Targets:
    """Stands in for the channel registry and hands out whatever target it is given."""

    def __init__(self, target: Any) -> None:
        self.target = target

    def approved_target(self, channel: str) -> Any:
        if isinstance(self.target, Exception):
            raise self.target
        return self.target


# --- what ships ----------------------------------------------------------------------


def test_the_factory_ships_exactly_two_l2_draft_tools(
    approved_channels: ChannelRegistry, root: Path
) -> None:
    tools = build_outbox_tools(root, approved_channels, FakeRedactor())
    assert [t.name for t in tools] == [TICKET_DRAFT_OPERATION, OWNER_NOTICE_OPERATION]
    assert (TICKET_DRAFT_OPERATION, OWNER_NOTICE_OPERATION) == (
        "ticket.create_draft",
        "owner.notify_draft",
    )
    for tool in tools:
        assert isinstance(tool, Tool)
        assert tool.spec.authority_level is AuthorityLevel.L2_COORDINATE
        assert tool.spec.writes
        assert tool.spec.channel_argument == "channel"
        assert tool.verify is not None
        assert tool.rollback is None
        assert tool.credential_refs == ()
        assert not tool.spec.protected
    assert len(ToolRegistry(tools).seal()) == 2
    assert not root.exists()  # nothing is created until a draft is written


# --- through the broker --------------------------------------------------------------


def test_a_ticket_draft_lands_in_the_approved_outbox_and_is_verified(
    outbox_world: World, root: Path
) -> None:
    record = outbox_world.broker().execute(ticket(outbox_world))
    assert record.state is ExecutionState.VERIFIED
    (draft,) = files(root)
    assert draft.parent == root / "security_queue"
    assert draft.name == draft_file_name(TICKET_DRAFT_OPERATION, "idem-1")
    assert "idem-1" not in draft.name
    assert draft.name.startswith("ticket-")
    document = json.loads(draft.read_text(encoding="utf-8"))
    assert document["arguments"] == {**TICKET, "related": []}
    assert document["operation"] == TICKET_DRAFT_OPERATION
    assert document["kind"] == "draft"
    assert record.references == record.observed == (f"draft:{draft.stem}",)


def test_an_owner_notice_draft_is_written_too(outbox_world: World, root: Path) -> None:
    spec = outbox_world.registry.get(OWNER_NOTICE_OPERATION).spec
    record = outbox_world.broker().execute(outbox_world.envelope(spec, arguments=NOTICE))
    assert record.state is ExecutionState.VERIFIED
    (draft,) = files(root)
    assert draft.name.startswith("owner-")
    assert json.loads(draft.read_text("utf-8"))["arguments"] == NOTICE


def test_a_draft_to_an_unapproved_channel_is_denied_and_writes_nothing(
    outbox_world: World, root: Path
) -> None:
    with pytest.raises(ExecutionRefused) as excinfo:
        outbox_world.broker().execute(ticket(outbox_world, channel="random_channel"))
    assert excinfo.value.reason is RefusalReason.POLICY_DENIED
    assert excinfo.value.codes == ("channel_unapproved",)
    assert files(root) == []


def test_verification_reads_the_outbox_and_not_the_tools_reply(
    world_factory: WorldFactory, picky_audit: Any, approved_channels: ChannelRegistry, root: Path
) -> None:
    """A tool that claims success without writing anything is caught."""
    real = build_outbox_tools(root, approved_channels, FakeRedactor())[0]

    def liar(call: ToolCall) -> ToolResult:
        return ToolResult(outcome=ToolOutcome.SUCCEEDED, references=("draft:made_up",))

    lying = Tool(spec=real.spec, run=liar, verify=real.verify)
    world = world_factory(picky_audit, extra_tools=(lying,))
    record = world.broker().execute(ticket(world))
    assert record.state is ExecutionState.VERIFICATION_FAILED
    assert record.tool_outcome is ToolOutcome.SUCCEEDED
    assert record.observed == ()
    assert "no draft file" in record.verification_detail
    assert files(root) == []


def test_secrets_are_redacted_before_the_draft_is_written(outbox_world: World, root: Path) -> None:
    envelope = ticket(outbox_world, body=f"use {SECRET} to log in")
    assert outbox_world.broker().execute(envelope).state is ExecutionState.VERIFIED
    text = files(root)[0].read_text(encoding="utf-8")
    assert SECRET not in text
    assert "[REDACTED]" in text


# --- the tool on its own -------------------------------------------------------------


def test_running_the_same_key_again_cannot_create_a_second_draft(
    outbox_world: World, root: Path
) -> None:
    tool = outbox_world.registry.get(TICKET_DRAFT_OPERATION)
    call = call_for(outbox_world, ticket(outbox_world))
    first, second = tool.run(call), tool.run(call)
    assert first.outcome is second.outcome is ToolOutcome.SUCCEEDED
    assert first.references == second.references
    assert len(files(root)) == 1
    other = call_for(outbox_world, ticket(outbox_world, key="idem-2"))
    assert tool.run(other).outcome is ToolOutcome.SUCCEEDED
    assert len(files(root)) == 2
    assert not [p for p in files(root) if p.name.endswith(".part")]


def test_a_different_draft_under_the_same_key_is_not_overwritten(
    outbox_world: World, root: Path
) -> None:
    tool = outbox_world.registry.get(TICKET_DRAFT_OPERATION)
    tool.run(call_for(outbox_world, ticket(outbox_world)))
    before = files(root)[0].read_bytes()
    changed = tool.run(call_for(outbox_world, ticket(outbox_world, title="Something else")))
    assert changed.outcome is ToolOutcome.FAILED
    assert "nothing written" in changed.detail
    assert [p.read_bytes() for p in files(root)] == [before]


def test_verification_checks_existence_and_content_hash(outbox_world: World, root: Path) -> None:
    tool = outbox_world.registry.get(TICKET_DRAFT_OPERATION)
    assert tool.verify is not None
    call = call_for(outbox_world, ticket(outbox_world))
    assert tool.verify(call).matches is False  # nothing written yet
    tool.run(call)
    seen = tool.verify(call)
    assert seen.matches is True
    assert seen.detail.startswith("sha256 ")
    # the same key with other arguments does not match what is on disk
    assert tool.verify(call_for(outbox_world, ticket(outbox_world, title="Other"))).matches is False
    draft = files(root)[0]
    draft.write_bytes(draft.read_bytes() + b" ")
    assert tool.verify(call).matches is False
    draft.unlink()
    assert tool.verify(call).matches is False


def test_a_channel_revoked_before_the_write_writes_nothing(
    outbox_world: World, approved_channels: ChannelRegistry, root: Path
) -> None:
    tool = outbox_world.registry.get(TICKET_DRAFT_OPERATION)
    call = call_for(outbox_world, ticket(outbox_world))
    approved_channels.revoke("human_admin", "sec_tickets", "no longer used")
    result = tool.run(call)
    assert result.outcome is ToolOutcome.FAILED
    assert files(root) == []
    assert tool.verify is not None
    assert tool.verify(call).matches is False


@pytest.mark.parametrize(
    "target",
    [
        "../escape",
        "..",
        "a/b",
        "a\\b",
        "/absolute",
        "C:\\absolute",
        "c:relative",
        "con",
        "Mixed",
        "",
        ".",
        "name.with.dots",
        "queue\n",
        None,
        AuthorizationError("channel is not approved"),
    ],
    ids=repr,
)
def test_the_outbox_name_is_only_ever_one_directory_under_the_root(
    outbox_world: World, tmp_path: Path, root: Path, target: Any
) -> None:
    tool = build_outbox_tools(root, Targets(target), FakeRedactor())[0]  # type: ignore[arg-type]
    call = call_for(outbox_world, ticket(outbox_world))
    result = tool.run(call)
    assert result.outcome is ToolOutcome.FAILED
    assert "nothing written" in result.detail
    assert tool.verify is not None
    assert tool.verify(call).matches is False
    assert files(tmp_path) == []
    assert not root.exists()


@pytest.mark.parametrize("target", ["../escape", "..", "a/b", "inner/../../escape", "."])
def test_the_resolved_path_is_checked_even_if_the_name_check_let_it_through(
    outbox_world: World,
    tmp_path: Path,
    root: Path,
    target: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Second line of defence: the directory must be a direct child of the root."""
    monkeypatch.setattr("ciso.execution.outbox_tools.is_outbox_name", lambda value: True)
    tool = build_outbox_tools(root, Targets(target), FakeRedactor())[0]  # type: ignore[arg-type]
    result = tool.run(call_for(outbox_world, ticket(outbox_world)))
    assert result.outcome is ToolOutcome.FAILED
    assert "outside the outbox root" in result.detail
    assert files(tmp_path) == []


def test_a_plain_outbox_name_is_accepted_by_the_same_path_check(
    outbox_world: World, root: Path
) -> None:
    tool = build_outbox_tools(root, Targets("plain_queue"), FakeRedactor())[0]  # type: ignore[arg-type]
    call = call_for(outbox_world, ticket(outbox_world))
    assert tool.run(call).outcome is ToolOutcome.SUCCEEDED
    assert [p.parent for p in files(root)] == [root / "plain_queue"]


def test_an_outbox_directory_that_links_outside_the_root_is_refused(
    outbox_world: World, tmp_path: Path, root: Path
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    root.mkdir()
    try:
        (root / "linked_queue").symlink_to(elsewhere, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create directory links")
    tool = build_outbox_tools(root, Targets("linked_queue"), FakeRedactor())[0]  # type: ignore[arg-type]
    result = tool.run(call_for(outbox_world, ticket(outbox_world)))
    assert result.outcome is ToolOutcome.FAILED
    assert list(elsewhere.iterdir()) == []


# =====================================================================================
# Review `docs/reviews/m2-execution-broker.md`: outbox findings, named after the finding.
# =====================================================================================


def drafts_for(root: Path, target: Any) -> OutboxDrafts:
    return OutboxDrafts(TICKET_DRAFT_OPERATION, root, Targets(target), FakeRedactor())  # type: ignore[arg-type]


# --- M8: outbox guards that had no failing test --------------------------------------


def test_m8_a_call_that_names_no_channel_writes_nothing(
    outbox_world: World, tmp_path: Path, root: Path
) -> None:
    drafts = drafts_for(root, "plain_queue")
    call = call_for(outbox_world, ticket(outbox_world))
    without = call.model_copy(update={"channel": None})
    result = drafts.write_draft(without)
    assert result.outcome is ToolOutcome.FAILED
    assert "names no channel" in result.detail
    assert drafts.read_back(without).matches is False
    assert files(tmp_path) == []
    assert drafts.write_draft(call).outcome is ToolOutcome.SUCCEEDED  # allowed path
    assert len(files(root)) == 1


def test_m8_an_outbox_that_resolves_outside_the_root_is_refused(
    outbox_world: World, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What a directory link does, without needing the right to create one: the outbox
    directory resolves to a directory of the same name somewhere else."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    real = outbox_tools._resolve
    linked = real(root) / "linked_queue"
    monkeypatch.setattr(
        outbox_tools,
        "_resolve",
        lambda path: elsewhere / "linked_queue" if real(path) == linked else real(path),
    )
    drafts = drafts_for(root, "linked_queue")
    call = call_for(outbox_world, ticket(outbox_world))
    result = drafts.write_draft(call)
    assert result.outcome is ToolOutcome.FAILED
    assert result.detail == "nothing written: the outbox would fall outside the outbox root"
    assert drafts.read_back(call).matches is False
    assert files(tmp_path) == []
    assert list(elsewhere.iterdir()) == []


def test_m8_an_outbox_that_resolves_to_another_name_is_refused(
    outbox_world: World, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Still under the root, but not the directory the channel names (a link to a
    sibling outbox, or a name the file system folds into another)."""
    real = outbox_tools._resolve
    asked = real(root) / "linked_queue"
    monkeypatch.setattr(
        outbox_tools,
        "_resolve",
        lambda path: real(root) / "other_queue" if real(path) == asked else real(path),
    )
    drafts = drafts_for(root, "linked_queue")
    call = call_for(outbox_world, ticket(outbox_world))
    result = drafts.write_draft(call)
    assert result.outcome is ToolOutcome.FAILED
    assert result.detail.endswith("outside the outbox root (name)")
    assert files(tmp_path) == []


# --- L5: outbox arguments are bounded and validated ----------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        {"related": ["not a reference"]},
        {"related": ["finding:f1", "two:colons:here"]},
        {"related": ["finding:" + "x" * 160]},
        {"related": [f"finding:f{n}" for n in range(33)]},
        {"title": "has a \x00 in it"},
        {"title": "two\nlines"},
        {"body": "an escape \x1b[2J sequence"},
        {"channel": "sec_tickets\x7f"},
    ],
    ids=["free-text", "nested-ref", "long-ref", "too-many", "nul", "newline-title", "esc", "del"],
)
def test_l5_a_ticket_with_unvalidated_text_is_refused(
    outbox_world: World, root: Path, arguments: dict[str, Any]
) -> None:
    with pytest.raises(ExecutionRefused) as excinfo:
        outbox_world.broker().execute(ticket(outbox_world, **arguments))
    assert excinfo.value.reason is RefusalReason.ENVELOPE_INVALID
    assert excinfo.value.codes == ("invalid_arguments",)
    assert files(root) == []


@pytest.mark.parametrize(
    "arguments",
    [
        {"owner": "bob@example.com"},
        {"owner": "person:p1\n"},
        {"subject": "a\tb"},
        {"message": "\x00"},
    ],
    ids=["address", "newline-owner", "tab-subject", "nul"],
)
def test_l5_an_owner_notice_with_unvalidated_text_is_refused(
    outbox_world: World, root: Path, arguments: dict[str, Any]
) -> None:
    spec = outbox_world.registry.get(OWNER_NOTICE_OPERATION).spec
    envelope = outbox_world.envelope(spec, arguments={**NOTICE, **arguments})
    with pytest.raises(ExecutionRefused) as excinfo:
        outbox_world.broker().execute(envelope)
    assert excinfo.value.codes == ("invalid_arguments",)
    assert files(root) == []


def test_l5_references_and_multi_line_text_are_accepted(outbox_world: World, root: Path) -> None:
    envelope = ticket(
        outbox_world,
        related=["finding:f1", "asset:a-1.b_2"],
        body="line one\r\n\tline two\nline three",
    )
    assert outbox_world.broker().execute(envelope).state is ExecutionState.VERIFIED
    document = json.loads(files(root)[0].read_text(encoding="utf-8"))
    assert document["arguments"]["related"] == ["finding:f1", "asset:a-1.b_2"]


# --- L8: the write is synced, never overwrites, and reports stray temporary files ----


def test_l8_the_draft_is_synced_to_disk_before_it_gets_its_final_name(
    outbox_world: World, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drafts = drafts_for(root, "plain_queue")
    call = call_for(outbox_world, ticket(outbox_world))
    final = root / "plain_queue" / draft_file_name(TICKET_DRAFT_OPERATION, "idem-1")
    seen: list[tuple[bool, list[str]]] = []
    real = os.fsync

    def fsync(descriptor: int) -> None:
        seen.append((final.exists(), [p.name for p in files(root)]))
        real(descriptor)

    monkeypatch.setattr(outbox_tools.os, "fsync", fsync)
    assert drafts.write_draft(call).outcome is ToolOutcome.SUCCEEDED
    assert len(seen) == 1
    visible, names = seen[0]
    assert visible is False
    assert len(names) == 1
    assert names[0].endswith(".part")
    assert [p.name for p in files(root)] == [final.name]  # the temporary name is gone


def test_l8_a_file_that_appears_during_the_write_is_not_overwritten(
    outbox_world: World, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drafts = drafts_for(root, "plain_queue")
    call = call_for(outbox_world, ticket(outbox_world))
    final = root / "plain_queue" / draft_file_name(TICKET_DRAFT_OPERATION, "idem-1")
    real = os.fsync

    def intruder(descriptor: int) -> None:
        real(descriptor)
        final.write_bytes(b"somebody else's draft")

    monkeypatch.setattr(outbox_tools.os, "fsync", intruder)
    result = drafts.write_draft(call)
    assert result.outcome is ToolOutcome.FAILED
    assert "another draft holds this idempotency key" in result.detail
    assert final.read_bytes() == b"somebody else's draft"
    assert [p.name for p in files(root)] == [final.name]
    assert drafts.read_back(call).matches is False


def test_l8_stray_temporary_files_are_reported_and_left_alone(
    outbox_world: World, root: Path
) -> None:
    drafts = drafts_for(root, "plain_queue")
    directory = root / "plain_queue"
    directory.mkdir(parents=True)
    stray = directory / f".ticket-{'0' * 40}.json.tmp_{'0' * 26}.part"
    foreign = directory / "notes.part"
    stray.write_bytes(b"half a draft")
    foreign.write_bytes(b"not ours")
    result = drafts.write_draft(call_for(outbox_world, ticket(outbox_world)))
    assert result.outcome is ToolOutcome.SUCCEEDED
    assert result.detail == f"stray temporary files in this outbox: 1 ({stray.name})"
    assert stray.read_bytes() == b"half a draft"
    assert foreign.read_bytes() == b"not ours"
    clean = drafts.write_draft(call_for(outbox_world, ticket(outbox_world, key="idem-2")))
    assert clean.detail.startswith("stray temporary files in this outbox: 1")
    stray.unlink()
    last = drafts.write_draft(call_for(outbox_world, ticket(outbox_world, key="idem-3")))
    assert last.detail == ""
