"""The only tools this build ships: L2 coordination drafts written to a LOCAL outbox
(blueprint 9.1 L2, 9.5; FR-026; plan gap G13; OD-13: no ticketing or messaging system is
chosen, so nothing here sends anything anywhere).

`ticket.create_draft` and `owner.notify_draft` each write one JSON file into
`<outbox_root>/<outbox name>/`. The outbox name comes from the approved-channel registry
and is used strictly as one directory name under the root: it is re-validated with
`is_outbox_name`, and the resolved directory must be a direct child of the resolved root.

The file name derives from the idempotency key, so running the same key again cannot
create a second draft. A draft is written to a temporary name in the same directory,
flushed and synced to disk, and then given its final name by a hard link, which fails
instead of overwriting if a file with that name appeared meanwhile. A crash between the
write and the link leaves a `.<name>.<id>.part` file; such files are never deleted
here: each write counts the ones it finds and reports them in its result.

The content of the FILE is the typed arguments after the `Redactor`, plus references: a
secret the redactor knows does not reach the outbox. The same holds for the request the
broker stores in `execution_run` (it is redacted too). What the redactor does not
recognise is written as it came, in both places.

Verification does not look at the tool's reply. It rebuilds the bytes the call implies
and compares their hash with the hash of the file it reads from the outbox. Those bytes
are built from the REDACTED arguments, so a call rebuilt from the redacted stored
request gives the same bytes as the original call, provided the redactor returns its own
output unchanged when applied again. That is why these operations may be listed in
`ExecutionRecovery(verifiable_from_redacted=OUTBOX_OPERATIONS)`. A redactor whose rules
changed between the write and the verification turns a correct draft into a mismatch.

Arguments are closed models: text fields refuse NUL and other control characters (the
two multi-line fields allow tab, line feed and carriage return), and `related` and
`owner` must be entity references of bounded length.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator

from ciso.common.enums import AuthorityLevel
from ciso.common.errors import AuthorizationError, ValidationFailed
from ciso.common.ids import EntityRef, new_id
from ciso.common.protocols import Redactor
from ciso.common.schemas import Model, canonical_json, sha256_hex
from ciso.execution.channels import ChannelRegistry, is_outbox_name
from ciso.execution.tools import Tool, ToolCall, ToolOutcome, ToolResult, Verification
from ciso.policy.catalog import OperationSpec

logger = logging.getLogger(__name__)

TICKET_DRAFT_OPERATION = "ticket.create_draft"
OWNER_NOTICE_OPERATION = "owner.notify_draft"
#: The operations shipped here. Their verifier works from redacted arguments (see the
#: module docstring), so recovery may be told so.
OUTBOX_OPERATIONS = frozenset({TICKET_DRAFT_OPERATION, OWNER_NOTICE_OPERATION})
DRAFT_KIND = "draft"
_SUFFIX = ".json"
_PART = ".part"
#: Most stray temporary file names quoted in one result. Structural bound.
_MAX_STRAYS_NAMED = 3

#: One line of text: no NUL, no control character at all.
_LINE_RE = re.compile(r"[^\x00-\x1f\x7f]*")
#: Several lines of text: tab, line feed and carriage return are the only controls.
_LINES_RE = re.compile(r"[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*")
#: A temporary file this module wrote: `.<prefix>-<40 hex>.json.tmp_<id>.part`.
_STRAY_RE = re.compile(r"\.[a-z]+-[0-9a-f]{40}\.json\.tmp_[0-9A-Z]{26}\.part")


def _one_line(value: str) -> str:
    if not _LINE_RE.fullmatch(value):
        raise ValueError("control characters are not allowed")
    return value


def _lines(value: str) -> str:
    if not _LINES_RE.fullmatch(value):
        raise ValueError("control characters other than tab and line breaks are not allowed")
    return value


def _entity_ref(value: str) -> str:
    try:
        EntityRef.parse(value)
    except ValidationFailed as exc:
        raise ValueError("not an entity reference") from exc
    return value


class TicketDraftArgs(Model):
    """A ticket draft. `channel` names an approved channel; `related` are entity refs."""

    channel: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=8000)
    related: tuple[Annotated[str, Field(max_length=160)], ...] = Field(default=(), max_length=32)

    @field_validator("channel", "title")
    @classmethod
    def _plain(cls, value: str) -> str:
        return _one_line(value)

    @field_validator("body")
    @classmethod
    def _text(cls, value: str) -> str:
        return _lines(value)

    @field_validator("related")
    @classmethod
    def _refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_entity_ref(item) for item in value)


class OwnerNoticeArgs(Model):
    """A notice draft for an owner. `owner` is an entity ref, never an address."""

    channel: str = Field(min_length=1, max_length=64)
    owner: str = Field(min_length=1, max_length=160)
    subject: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=8000)

    @field_validator("channel", "subject")
    @classmethod
    def _plain(cls, value: str) -> str:
        return _one_line(value)

    @field_validator("message")
    @classmethod
    def _text(cls, value: str) -> str:
        return _lines(value)

    @field_validator("owner")
    @classmethod
    def _owner(cls, value: str) -> str:
        return _entity_ref(value)


def _spec(name: str, args: type[Model], description: str) -> OperationSpec:
    return OperationSpec(
        name=name,
        authority_level=AuthorityLevel.L2_COORDINATE,
        args_model=args,
        writes=True,
        channel_argument="channel",
        agent_requestable=True,
        description=description,
    )


def draft_file_name(operation: str, idempotency_key: str) -> str:
    """One fixed name per operation and idempotency key. Only hex and a fixed prefix
    reach the file system; the key itself never does."""
    prefix = operation.split(".", 1)[0]
    return f"{prefix}-{sha256_hex(f'{operation}\n{idempotency_key}')[:40]}{_SUFFIX}"


def _resolve(path: Path) -> Path:
    """The path with every link followed. A function of its own so the check that
    uses it can be tested on a machine that cannot create directory links."""
    return path.resolve()


class OutboxDrafts:
    """Writes and reads back drafts for one operation."""

    def __init__(
        self, operation: str, outbox_root: Path, channels: ChannelRegistry, redactor: Redactor
    ) -> None:
        self._operation = operation
        self._root = Path(outbox_root)
        self._channels = channels
        self._redactor = redactor

    # --- where and what --------------------------------------------------------------

    def _directory(self, call: ToolCall) -> Path:
        """The outbox directory for the call's channel. `AuthorizationError` unless the
        channel is approved now and its outbox is one plain directory under the root."""
        if call.channel is None:
            raise AuthorizationError("the call names no channel")
        name = self._channels.approved_target(call.channel)
        if not is_outbox_name(name):
            raise AuthorizationError("the channel's target is not an outbox name")
        root = _resolve(self._root)
        directory = _resolve(root / name)
        if directory.parent != root:
            raise AuthorizationError("the outbox would fall outside the outbox root")
        if directory.name != name:
            raise AuthorizationError("the outbox would fall outside the outbox root (name)")
        return directory

    def _content(self, call: ToolCall) -> bytes:
        """The exact bytes the draft for this call must hold."""
        document = {
            "kind": DRAFT_KIND,
            "operation": call.operation,
            "request_id": call.request_id,
            "envelope_hash": call.envelope_hash,
            "actor_id": call.actor_id,
            "target_resource": call.target_resource,
            "channel": call.channel,
            "arguments": self._redactor.redact_value(call.arguments.model_dump(mode="json")),
        }
        return canonical_json(document).encode("utf-8")

    # --- the tool body ---------------------------------------------------------------

    def write_draft(self, call: ToolCall) -> ToolResult:
        name = draft_file_name(call.operation, call.idempotency_key)
        reference = f"{DRAFT_KIND}:{name.removesuffix(_SUFFIX)}"
        try:
            directory = self._directory(call)
        except AuthorizationError as exc:
            return ToolResult(outcome=ToolOutcome.FAILED, detail=f"nothing written: {exc}")
        content = self._content(call)
        directory.mkdir(parents=True, exist_ok=True)
        final = directory / name
        if final.exists():
            return self._existing(final, content, reference)
        strays = self._strays(directory)
        temporary = directory / f".{name}.{new_id('tmp')}{_PART}"
        try:
            with temporary.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                # A hard link gives the final name atomically and never replaces a file
                # that appeared since the check above.
                os.link(temporary, final)
            except FileExistsError:
                return self._existing(final, content, reference)
        finally:
            temporary.unlink(missing_ok=True)
        return ToolResult(
            outcome=ToolOutcome.SUCCEEDED, references=(reference,), detail=_stray_note(strays)
        )

    @staticmethod
    def _existing(final: Path, content: bytes, reference: str) -> ToolResult:
        """A file already holds the final name: the same draft, or somebody else's."""
        if final.read_bytes() == content:
            return ToolResult(
                outcome=ToolOutcome.SUCCEEDED, references=(reference,), detail="already there"
            )
        return ToolResult(
            outcome=ToolOutcome.FAILED,
            detail="nothing written: another draft holds this idempotency key",
        )

    @staticmethod
    def _strays(directory: Path) -> tuple[str, ...]:
        """Temporary files earlier crashed writes left in this outbox, by this module's
        own naming only. Listed, never deleted."""
        return tuple(
            sorted(
                entry.name
                for entry in directory.iterdir()
                if _STRAY_RE.fullmatch(entry.name) and entry.is_file()
            )
        )

    def read_back(self, call: ToolCall) -> Verification:
        """Independent check: the outbox file exists and holds exactly what the call's
        arguments imply. Uses nothing the tool returned."""
        name = draft_file_name(call.operation, call.idempotency_key)
        try:
            path = self._directory(call) / name
        except AuthorizationError as exc:
            return Verification(matches=False, detail=f"outbox not available: {exc}")
        if not path.is_file():
            return Verification(matches=False, detail="no draft file in the outbox")
        found = sha256_hex(path.read_bytes())
        expected = sha256_hex(self._content(call))
        if found != expected:
            return Verification(matches=False, detail="draft content differs from the request")
        return Verification(
            matches=True,
            detail=f"sha256 {found}",
            observed=(f"{DRAFT_KIND}:{name.removesuffix(_SUFFIX)}",),
        )


def _stray_note(strays: tuple[str, ...]) -> str:
    if not strays:
        return ""
    named = ", ".join(strays[:_MAX_STRAYS_NAMED])
    return f"stray temporary files in this outbox: {len(strays)} ({named})"


def build_outbox_tools(
    outbox_root: Path, channels: ChannelRegistry, redactor: Redactor
) -> tuple[Tool, ...]:
    """The shipped tools, ready for `ToolRegistry`. `outbox_root` is a local directory;
    it is created when the first draft is written."""
    specs = (
        _spec(TICKET_DRAFT_OPERATION, TicketDraftArgs, "Write a ticket draft to a local outbox."),
        _spec(OWNER_NOTICE_OPERATION, OwnerNoticeArgs, "Write an owner notice draft locally."),
    )
    tools = []
    for spec in specs:
        drafts = OutboxDrafts(spec.name, Path(outbox_root), channels, redactor)
        tools.append(Tool(spec=spec, run=drafts.write_draft, verify=drafts.read_back))
    return tuple(tools)
