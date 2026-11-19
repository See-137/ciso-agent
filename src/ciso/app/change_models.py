"""Wire and record types of the pre-push change upload (docs/skill/decision-api.md).

The structural bounds here are named constants, not safety settings: the largest bundle
equals the sandbox service's archive bound (`services/sandbox/job.py`,
`MAX_ARCHIVE_BYTES`, 32 MiB), and the request cap follows from it.
"""

from __future__ import annotations

import base64
import binascii
from enum import StrEnum
from typing import Annotated, Final

from pydantic import ConfigDict, Field, model_validator

from ciso.app.change_shape import ChangeKind
from ciso.common.activity import InspectionResult
from ciso.common.errors import CisoError
from ciso.common.schemas import Model

#: Largest git bundle accepted: the sandbox's own archive bound.
MAX_BUNDLE_BYTES: Final = 32 * 1024 * 1024
#: Largest diff accepted, in bytes. Inspection itself reads at most
#: `ciso.common.activity.MAX_INSPECTION_CHARS` characters and calls a longer diff
#: incomplete, so a diff between the two bounds is stored but cannot pass.
MAX_DIFF_BYTES: Final = 4 * 1024 * 1024
#: Most commits one push may cover.
MAX_CHANGE_COMMITS: Final = 1000
#: `POST /v1/changes` body cap: base64 of the largest bundle and diff plus the rest.
MAX_CHANGE_BODY_BYTES: Final = ((MAX_BUNDLE_BYTES + MAX_DIFF_BYTES + 2) // 3) * 4 + 128 * 1024
#: Queue job kind of a sandbox run for one change.
SANDBOX_JOB_KIND: Final = "governance.sandbox_change"
#: Change id prefix (`new_id`).
CHANGE_ID_PREFIX: Final = "chg"

_COMMIT = r"[0-9a-f]{40}|[0-9a-f]{64}"
_BUNDLE_HEADERS: Final = (b"# v2 git bundle\n", b"# v3 git bundle\n")

Commit = Annotated[str, Field(pattern=rf"^(?:{_COMMIT})$")]


class ChangeState(StrEnum):
    #: Waiting for the sandbox report.
    PENDING = "pending"
    #: The sandbox report is in.
    DONE = "done"
    #: The sandbox could not check it (the queue gave up). Never complete.
    FAILED = "failed"
    #: A commit: inspected in-process only; the sandbox runs on the push.
    NOT_NEEDED = "not_needed"


class ChangeRefusal(StrEnum):
    UNKNOWN = "change_unknown"
    EXPIRED = "change_expired"
    FOREIGN = "change_foreign"
    MISMATCH = "change_mismatch"


class ChangeRefused(CisoError):
    """A change id that may not be used for this decision. `code` says why."""

    def __init__(self, code: ChangeRefusal) -> None:
        super().__init__(code.value)
        self.code = code


def _decode(text: str | None, limit: int, name: str) -> bytes | None:
    if text is None:
        return None
    if len(text) > ((limit + 2) // 3) * 4:
        raise ValueError(f"{name} is too large")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} is not base64") from exc
    if len(raw) > limit:
        raise ValueError(f"{name} is too large")
    return raw


class ChangeUpload(Model):
    """The body of `POST /v1/changes`. Content fields stay out of `repr` and errors."""

    model_config = ConfigDict(hide_input_in_errors=True)

    session_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
    kind: ChangeKind
    remote: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")] | None = None
    branch: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")] | None = None
    #: Push: the local branch sent (`needs_change.source`); None means HEAD.
    source: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")] | None = None
    #: Push: the commit the pushed ref (`source`, or HEAD) points at.
    #: Commit: the tree of the staged index.
    head: Commit
    #: The commit the diff starts from; None for a commit in a repository with no commit.
    base: Commit | None = None
    #: Push: `git rev-list base..head`, newest first (so `commits[0] == head`).
    commits: Annotated[tuple[Commit, ...], Field(max_length=MAX_CHANGE_COMMITS)] = ()
    diff_b64: str = Field(repr=False)
    bundle_b64: str | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def _consistent(self) -> ChangeUpload:
        if self.kind is ChangeKind.PUSH:
            if self.bundle_b64 is None or self.base is None:
                raise ValueError("a push needs a bundle and a base commit")
            if not self.commits or self.commits[0] != self.head:
                raise ValueError("a push must list its commits, newest (head) first")
            if len(set(self.commits)) != len(self.commits):
                raise ValueError("commits repeat")
        elif (
            self.bundle_b64 is not None or self.commits or self.remote or self.branch or self.source
        ):
            raise ValueError("a commit carries the staged diff only")
        return self

    def diff(self) -> bytes:
        raw = _decode(self.diff_b64, MAX_DIFF_BYTES, "diff")
        assert raw is not None
        return raw

    def bundle(self) -> bytes:
        raw = _decode(self.bundle_b64, MAX_BUNDLE_BYTES, "bundle")
        if raw is None:
            return b""
        if not raw.startswith(_BUNDLE_HEADERS):
            raise ValueError("bundle is not a v2 or v3 git bundle")
        return raw


class ChangeReceipt(Model):
    change_id: str
    #: False: an identical change from this device and session was already stored.
    created: bool


class ResolvedChange(Model):
    """What `decide` needs about one change: its state and the inspection results (which
    hold findings, never content)."""

    change_id: str
    state: ChangeState
    diff: InspectionResult
    sandbox: InspectionResult | None = None


class SandboxInput(Model):
    """What the worker sends to the sandbox. `bundle` stays out of `repr`."""

    change_id: str
    bundle: bytes = Field(repr=False)
    base: str
