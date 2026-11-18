"""The gates in front of authorize and transmit, their order, the audit ordering, and the
count of transport implementations in `src` (blueprint 8.4, 9.5; plan row T2.7; gaps G1,
G26; ADR-0006).

Each gate has a refusing test here; the allowed path is `test_all_gates_open_sends_once`
and the tests in `test_approval_binding.py`.
"""

from __future__ import annotations

import ast
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select
from tests.conftest import REPO_ROOT
from tests.external_inference.conftest import (
    APPROVAL_TTL,
    APPROVER_ROLE,
    REQUESTER,
    SpyTransport,
    approval_rows,
    fail_audit_when,
)
from tests.fakes.core import FakeAudit, FakeKillSwitch, FakePrincipals

from ciso.approvals import ApprovalConflict, ApprovalService, ApprovalStatus
from ciso.approvals.tables import approval as approval_table
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import ActorType, AuditOutcome, KillCapability, Role
from ciso.common.errors import ExternalInferenceBlocked, FailClosed, ValidationFailed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent
from ciso.inference.external import (
    ACTION_AUTHORIZE,
    ACTION_TRANSMIT,
    ExternalGateRefused,
    ExternalInferenceGateway,
    ExternalReason,
    ExternalRequestProposal,
    ExternalRequestRefused,
    GateReason,
    PayloadPreview,
    TransmitOutcome,
)
from ciso.inference.external.ledger import ExternalLedger

pytestmark = pytest.mark.external_inference

Gateways = Callable[..., ExternalInferenceGateway]
Proposals = Callable[..., ExternalRequestProposal]
Expected = Callable[..., PayloadPreview]
SRC = REPO_ROOT / "src"


class RaisingKillSwitch:
    def is_blocked(self, capability: KillCapability) -> bool:
        raise OSError("kill switch state file unreadable")


def _approved(
    make_gateway: Gateways,
    approvals: ApprovalService,
    approver: Principal,
    proposal: ExternalRequestProposal,
) -> str:
    made = make_gateway().request_approval(proposal, actor_id=REQUESTER)
    approvals.approve(made.approval_id, approver)
    return made.approval_id


def _blocked(make_proposal: Proposals, expected: Expected) -> ExternalRequestProposal:
    """A recorded proposal whose only item may not leave."""
    blocked = make_proposal(label="restricted")
    assert not expected(blocked).sendable
    return blocked


# One entry per gate: (reason, gateway overrides, set-up applied to the fakes, actor id).
GATES: list[tuple[GateReason, dict[str, Any], str, str]] = [
    (GateReason.FEATURE_DISABLED, {"enabled": False}, "", REQUESTER),
    (GateReason.KILL_SWITCH_ENGAGED, {}, "kill_blocked", REQUESTER),
    (GateReason.KILL_SWITCH_ENGAGED, {}, "kill_broken", REQUESTER),
    (GateReason.KILL_SWITCH_UNAVAILABLE, {"killswitch": RaisingKillSwitch()}, "", REQUESTER),
    (GateReason.APPROVER_ROLE_UNSET, {"approver_role": None}, "", REQUESTER),
    (GateReason.APPROVER_ROLE_NOT_ALLOWED, {"approver_role": Role.SECURITY_ADMIN}, "", REQUESTER),
    (GateReason.TRANSPORT_ABSENT, {"transport": None}, "", REQUESTER),
    (GateReason.IDENTITY_UNAVAILABLE, {}, "identity_broken", REQUESTER),
    (GateReason.ACTOR_UNKNOWN, {}, "", "human_nobody"),
    (GateReason.ACTOR_NOT_HUMAN, {}, "", "agent_ciso"),
    (GateReason.ACTOR_NOT_HUMAN, {}, "", "svc_connector"),
    (GateReason.NO_ALLOWED_CLASSIFICATIONS, {"allowed_classifications": ()}, "", REQUESTER),
    (GateReason.PAYLOAD_LIMIT_UNSET, {"max_payload_bytes": None}, "", REQUESTER),
    (GateReason.RESPONSE_LIMIT_UNSET, {"max_response_bytes": None}, "", REQUESTER),
    # The gateway minimizes with its own allowed set: the public item is dropped.
    (GateReason.NOT_SENDABLE, {"allowed_classifications": ("internal",)}, "", REQUESTER),
    (GateReason.PAYLOAD_TOO_LARGE, {"max_payload_bytes": 20}, "", REQUESTER),
    # Review finding M3: a human who is not the proposer, here the read-only auditor.
    (GateReason.NOT_REQUESTER, {}, "", "human_aud"),
]
GATE_IDS = [
    "flag-off", "kill-engaged", "kill-unreadable", "kill-raises", "role-unset",
    "role-not-approver", "no-transport", "identity-down", "actor-unknown", "agent",
    "service", "nothing-allowed", "payload-limit-unset", "response-limit-unset",
    "label-not-allowed", "payload-too-large", "not-the-requester",
]  # fmt: skip


def _arrange(setup: str, killswitch: FakeKillSwitch, principals: FakePrincipals) -> None:
    if setup == "kill_blocked":
        killswitch.blocked.add(KillCapability.EXTERNAL_INFERENCE)
    elif setup == "kill_broken":
        killswitch.broken = True
    elif setup == "identity_broken":
        principals.broken = True


@pytest.mark.parametrize(("reason", "overrides", "setup", "actor"), GATES, ids=GATE_IDS)
def test_transmit_gate_refuses_with_an_approved_request_in_hand(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    killswitch: FakeKillSwitch,
    principals: FakePrincipals,
    reason: GateReason,
    overrides: dict[str, Any],
    setup: str,
    actor: str,
) -> None:
    proposal = make_proposal()
    approval_id = _approved(make_gateway, approvals, approver, proposal)
    _arrange(setup, killswitch, principals)
    with pytest.raises(ExternalGateRefused) as excinfo:
        make_gateway(**overrides).transmit(proposal, approval_id, actor_id=actor)
    assert excinfo.value.reason is reason
    assert isinstance(excinfo.value, ExternalInferenceBlocked)
    assert spy.calls == []
    denied = audit.find(ACTION_TRANSMIT)
    assert [(e.outcome, e.details["reason"]) for e in denied] == [
        (AuditOutcome.DENIED, reason.value)
    ]
    assert denied[0].actor_id == actor
    principals.broken = False
    assert approvals.get(approval_id).status is ApprovalStatus.APPROVED


@pytest.mark.parametrize(("reason", "overrides", "setup", "actor"), GATES, ids=GATE_IDS)
def test_authorize_gate_refuses_and_files_no_approval(
    make_gateway: Gateways,
    make_proposal: Proposals,
    engine: Engine,
    audit: FakeAudit,
    killswitch: FakeKillSwitch,
    principals: FakePrincipals,
    reason: GateReason,
    overrides: dict[str, Any],
    setup: str,
    actor: str,
) -> None:
    proposal = make_proposal()
    _arrange(setup, killswitch, principals)
    with pytest.raises(ExternalGateRefused) as excinfo:
        make_gateway(**overrides).request_approval(proposal, actor_id=actor)
    assert excinfo.value.reason is reason
    assert approval_rows(engine) == 0
    assert [(e.outcome, e.details["reason"]) for e in audit.find(ACTION_AUTHORIZE)] == [
        (AuditOutcome.DENIED, reason.value)
    ]


def test_a_blocked_preview_is_refused_by_both_steps(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    engine: Engine,
    expected: Expected,
) -> None:
    blocked = _blocked(make_proposal, expected)
    gateway = make_gateway()
    with pytest.raises(ExternalGateRefused) as excinfo:
        gateway.request_approval(blocked, actor_id=REQUESTER)
    assert excinfo.value.reason is GateReason.NOT_SENDABLE
    assert approval_rows(engine) == 0
    approval_id = _approved(make_gateway, approvals, approver, make_proposal())
    with pytest.raises(ExternalGateRefused) as excinfo:
        gateway.transmit(blocked, approval_id, actor_id=REQUESTER)
    assert excinfo.value.reason is GateReason.NOT_SENDABLE
    assert spy.calls == []


def test_all_gates_open_sends_once(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    killswitch: FakeKillSwitch,
) -> None:
    proposal = make_proposal()
    approval_id = _approved(make_gateway, approvals, approver, proposal)
    make_gateway().transmit(proposal, approval_id, actor_id=REQUESTER)
    assert len(spy.calls) == 1
    assert set(killswitch.reads) == {KillCapability.EXTERNAL_INFERENCE}


def test_every_default_refuses(
    engine: Engine,
    clock: FixedClock,
    audit: FakeAudit,
    principals: FakePrincipals,
    killswitch: FakeKillSwitch,
    approvals: ApprovalService,
    real_redactor: Any,
    make_proposal: Proposals,
) -> None:
    """Built with only its required collaborators, the gateway is off (blueprint 8.4)."""
    shipped = ExternalInferenceGateway(
        engine=engine, clock=clock, audit=audit, redactor=real_redactor,
        principals=principals, killswitch=killswitch, approvals=approvals,
    )  # fmt: skip
    proposal = make_proposal()
    for call in (
        lambda: shipped.request_approval(proposal, actor_id=REQUESTER),
        lambda: shipped.transmit(proposal, "apr_" + "0" * 26, actor_id=REQUESTER),
    ):
        with pytest.raises(ExternalGateRefused) as excinfo:
            call()
        assert excinfo.value.reason is GateReason.FEATURE_DISABLED
    # The proposal step is off as well: the shipped gateway records nothing.
    with pytest.raises(ExternalRequestRefused) as refused:
        shipped.propose(
            requester_actor_id=REQUESTER, purpose="p", provider_name="a", model_name="b", items=[]
        )
    assert refused.value.reason is ExternalReason.FEATURE_DISABLED


def test_gates_are_checked_in_the_documented_order(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    killswitch: FakeKillSwitch,
    principals: FakePrincipals,
    clock: FixedClock,
) -> None:
    """Everything wrong at once; fix one thing at a time and watch the next gate answer."""
    blocked = _blocked(make_proposal, expected)
    good = make_proposal()
    never_proposed = ExternalRequestProposal(
        request_id="xrq_" + "0" * 26,
        requester_actor_id=REQUESTER,
        requester_actor_type=ActorType.HUMAN,
        purpose="p",
        provider_name="a",
        model_name="b",
        items=good.items,
        created_at=clock.now(),
    )
    changed = good.model_copy(update={"purpose": "another purpose"})
    killswitch.blocked.add(KillCapability.EXTERNAL_INFERENCE)
    principals.broken = True
    config: dict[str, Any] = {
        "enabled": False,
        "approver_role": None,
        "transport": None,
        "allowed_classifications": (),
        "max_payload_bytes": None,
        "max_response_bytes": None,
    }
    state: dict[str, Any] = {"proposal": expected(good), "actor": "agent_ciso"}

    def reason() -> GateReason:
        with pytest.raises(ExternalGateRefused) as excinfo:
            make_gateway(**config).transmit(
                state["proposal"], "apr_" + "0" * 26, actor_id=state["actor"]
            )
        return excinfo.value.reason

    seen = [reason()]
    config["enabled"] = True
    seen.append(reason())
    killswitch.blocked.clear()
    seen.append(reason())
    config["approver_role"] = APPROVER_ROLE
    seen.append(reason())
    del config["transport"]
    seen.append(reason())
    del config["allowed_classifications"]
    seen.append(reason())
    config["max_payload_bytes"] = 20
    seen.append(reason())
    del config["max_response_bytes"]
    seen.append(reason())
    principals.broken = False
    seen.append(reason())
    state["actor"] = "human_aud"
    seen.append(reason())
    state["proposal"] = never_proposed
    seen.append(reason())
    state["proposal"] = changed
    seen.append(reason())
    state["proposal"] = blocked
    seen.append(reason())
    state["actor"] = REQUESTER
    seen.append(reason())
    state["proposal"] = good
    seen.append(reason())
    del config["max_payload_bytes"]
    seen.append(reason())
    assert seen == [
        GateReason.FEATURE_DISABLED,
        GateReason.KILL_SWITCH_ENGAGED,
        GateReason.APPROVER_ROLE_UNSET,
        GateReason.TRANSPORT_ABSENT,
        GateReason.NO_ALLOWED_CLASSIFICATIONS,
        GateReason.PAYLOAD_LIMIT_UNSET,
        GateReason.RESPONSE_LIMIT_UNSET,
        GateReason.IDENTITY_UNAVAILABLE,
        GateReason.ACTOR_NOT_HUMAN,
        GateReason.PROPOSAL_INVALID,
        GateReason.PROPOSAL_UNKNOWN,
        GateReason.PROPOSAL_MISMATCH,
        GateReason.NOT_REQUESTER,
        GateReason.NOT_SENDABLE,
        GateReason.PAYLOAD_TOO_LARGE,
        GateReason.AUTHORIZATION_NOT_FOUND,
    ]


def test_constructor_refuses_bad_settings(make_gateway: Gateways) -> None:
    with pytest.raises(ValidationFailed):
        make_gateway(allowed_classifications=("unknown",))
    with pytest.raises(ValidationFailed):
        make_gateway(allowed_classifications=("no_such_label",))
    with pytest.raises(ValidationFailed):
        make_gateway(scheme=None)
    with pytest.raises(ValueError, match="secret resolver"):
        make_gateway(digest_key_ref="secret://digest")
    for bad in (0, -1, True, 1.5, "100"):
        with pytest.raises(ValidationFailed):
            make_gateway(max_payload_bytes=bad)
        with pytest.raises(ValidationFailed):
            make_gateway(max_response_bytes=bad)


# --- audit ordering -----------------------------------------------------------------------


def test_attempt_audit_failure_means_the_transport_is_never_called(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal = make_proposal()
    approval_id = _approved(make_gateway, approvals, approver, proposal)
    gateway = make_gateway()
    fail_audit_when(
        monkeypatch,
        audit,
        lambda e: e.action == ACTION_TRANSMIT and e.outcome is AuditOutcome.ATTEMPT,
    )
    with pytest.raises(FailClosed):
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert spy.calls == []
    assert gateway.records_for_request(proposal.request_id) == ()
    # Documented: the approval was consumed before the attempt and stays consumed.
    assert approvals.get(approval_id).status is ApprovalStatus.CONSUMED


def test_record_write_failure_before_the_send_means_no_send(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal = make_proposal()
    approval_id = _approved(make_gateway, approvals, approver, proposal)

    def down(self: ExternalLedger, item: Any) -> None:
        raise FailClosed("ledger down (scripted)")

    monkeypatch.setattr(ExternalLedger, "insert_record", down)
    with pytest.raises(FailClosed):
        make_gateway().transmit(proposal, approval_id, actor_id=REQUESTER)
    assert spy.calls == []


def test_a_refusal_that_cannot_be_audited_still_sends_nothing(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
) -> None:
    proposal = make_proposal()
    approval_id = _approved(make_gateway, approvals, approver, proposal)
    audit.fail = True
    with pytest.raises(FailClosed):
        make_gateway(enabled=False).transmit(proposal, approval_id, actor_id=REQUESTER)
    assert spy.calls == []


def test_result_audit_failure_returns_nothing_and_the_record_tells_the_truth(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal = make_proposal()
    approval_id = _approved(make_gateway, approvals, approver, proposal)
    gateway = make_gateway()
    fail_audit_when(
        monkeypatch,
        audit,
        lambda e: e.action == ACTION_TRANSMIT and e.outcome is AuditOutcome.SUCCESS,
    )
    result = None
    with pytest.raises(FailClosed):
        result = gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert result is None
    assert len(spy.calls) == 1
    # The answer came back, but nothing says so in the audit log: the row is flagged.
    (record,) = gateway.records_for_request(proposal.request_id)
    assert record.outcome is TransmitOutcome.SENT_UNRECORDED
    assert record.error_type == "closing_audit_failed:sent"
    assert record.completed_at is not None


def test_authorize_attempt_audit_failure_files_nothing(
    make_gateway: Gateways, make_proposal: Proposals, engine: Engine, audit: FakeAudit
) -> None:
    audit.fail = True
    with pytest.raises(FailClosed):
        make_gateway().request_approval(make_proposal(), actor_id=REQUESTER)
    assert approval_rows(engine) == 0


def test_an_authorization_that_cannot_be_audited_is_withdrawn(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    fail_audit_when(
        monkeypatch,
        audit,
        lambda e: e.action == ACTION_AUTHORIZE and e.outcome is AuditOutcome.SUCCESS,
    )
    with pytest.raises(FailClosed):
        gateway.request_approval(proposal, actor_id=REQUESTER)
    # Review finding L5: no orphan is left for an approver to decide.
    assert approvals.list_pending() == ()
    with engine.begin() as conn:
        (orphan,) = conn.execute(select(approval_table.c.approval_id, approval_table.c.status))
    assert orphan.status == "void"
    assert gateway.get_authorization(orphan.approval_id) is None
    with pytest.raises(ApprovalConflict):
        approvals.approve(orphan.approval_id, approver)
    with pytest.raises(ExternalGateRefused) as excinfo:
        gateway.transmit(proposal, orphan.approval_id, actor_id=REQUESTER)
    assert excinfo.value.reason is GateReason.AUTHORIZATION_NOT_FOUND
    assert spy.calls == []


@pytest.fixture
def file_engine(tmp_path: Path) -> Iterator[tuple[Path, Engine]]:
    path = tmp_path / "ops.db"
    eng = create_db_engine(path)
    init_operational_schema(eng)
    yield path, eng
    eng.dispose()


def test_audit_is_never_called_while_the_write_lock_is_held(
    file_engine: tuple[Path, Engine],
    make_gateway: Gateways,
    make_proposal: Proposals,
    clock: FixedClock,
    principals: FakePrincipals,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    path, engine = file_engine
    lock_free: list[bool] = []

    class ProbingAudit(FakeAudit):
        def append(self, event: AuditEvent) -> Any:
            con = sqlite3.connect(path, timeout=0.2, isolation_level=None)
            try:
                con.execute("BEGIN IMMEDIATE")
                con.execute("ROLLBACK")
                lock_free.append(True)
            except sqlite3.OperationalError:
                lock_free.append(False)
            finally:
                con.close()
            return super().append(event)

    audit = ProbingAudit(clock)
    approvals = ApprovalService(
        engine=engine, audit=audit, clock=clock, principals=principals, approval_ttl=APPROVAL_TTL
    )
    gateway = make_gateway(engine=engine, audit=audit, approvals=approvals)
    proposal = make_proposal(via=gateway)
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    approvals.approve(made.approval_id, approver)
    gateway.transmit(proposal, made.approval_id, actor_id=REQUESTER)
    with pytest.raises(ExternalGateRefused):
        gateway.transmit(proposal, made.approval_id, actor_id=REQUESTER)
    assert len(spy.calls) == 1
    own = [e for e in audit.events if e.action in {ACTION_AUTHORIZE, ACTION_TRANSMIT}]
    assert len(own) == 5
    assert len(lock_free) == len(audit.events) >= 10
    assert all(lock_free)


# --- zero transport implementations in src (ADR-0006) ---------------------------------------

PROTOCOL_NAME = "ExternalTransport"
SEND_PARAMETERS = {"provider_name", "model_name", "payload"}


def _base_names(node: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.add(base.id)
        elif isinstance(base, ast.Attribute):
            names.add(base.attr)
    return names


def _has_send_shape(node: ast.ClassDef) -> bool:
    for item in node.body:
        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and item.name == "send":
            params = {a.arg for a in item.args.args + item.args.kwonlyargs}
            if params >= SEND_PARAMETERS or item.args.kwarg is not None:
                return True
    return False


def scan_transport_implementations(root: Path) -> tuple[int, list[str]]:
    """(files scanned, classes that subclass the transport protocol or have its shape).

    The protocol's own definition is the one class left out: it is named
    `ExternalTransport` and derives from `Protocol`.
    """
    scanned = 0
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        scanned += 1
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = _base_names(node)
            if node.name == PROTOCOL_NAME and "Protocol" in bases:
                continue
            if PROTOCOL_NAME in bases or _has_send_shape(node):
                found.append(f"{path.name}:{node.name}")
    return scanned, found


def test_src_holds_no_transport_implementation() -> None:
    scanned, found = scan_transport_implementations(SRC)
    assert scanned > 50
    assert (SRC / "ciso" / "inference" / "external" / "transport.py").is_file()
    assert found == []
    assert len(found) == 0


def test_the_scanner_sees_planted_implementations(tmp_path: Path) -> None:
    (tmp_path / "protocol.py").write_text(
        "from typing import Protocol\n"
        "class ExternalTransport(Protocol):\n"
        "    def send(self, *, provider_name, model_name, payload): ...\n",
        encoding="utf-8",
    )
    assert scan_transport_implementations(tmp_path) == (1, [])
    (tmp_path / "planted.py").write_text(
        "from x import transport\n"
        "class ByName(ExternalTransport):\n    pass\n"
        "class ByAttribute(transport.ExternalTransport):\n    pass\n"
        "class ByShape:\n"
        "    def send(self, *, provider_name, model_name, payload):\n        return b''\n"
        "class ByKwargs:\n"
        "    async def send(self, **kwargs):\n        return b''\n"
        "class Unrelated:\n"
        "    def send(self, message):\n        return None\n",
        encoding="utf-8",
    )
    scanned, found = scan_transport_implementations(tmp_path)
    assert scanned == 2
    assert found == [
        "planted.py:ByName",
        "planted.py:ByAttribute",
        "planted.py:ByShape",
        "planted.py:ByKwargs",
    ]


def test_the_test_spy_would_be_counted_if_it_lived_in_src() -> None:
    """The spy in this directory's conftest has the transport's shape."""
    scanned, found = scan_transport_implementations(Path(__file__).parent)
    assert scanned >= 2
    assert "conftest.py:SpyTransport" in found
