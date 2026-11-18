"""Composition root, M2 part (plan T2.9): how the external model gateway is wired
(blueprint 8.4, 19.3; gaps G14, G26; ADR-0006).

Each test pins one wiring choice that is a guard: the switch, the gated kill-switch
reader, the absent transport, the two byte limits, the approver role and the digest key.
Where a send has to get as far as a transport, the gateway is rebuilt by the composition
root's own builder with a test transport (`gateway_with`).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.app.helpers import SECRET_ENV, build, event, provisional
from tests.app.m2_world import (
    SpyTransport,
    enabled_settings,
    external_on,
    first_admin,
    gateway_with,
    human,
    made_up_proposal,
    propose,
    tamper_a_middle_record,
)

from ciso.app import Container
from ciso.common.enums import KillCapability, Role
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.inference.external import (
    ExternalGateRefused,
    ExternalInferenceGateway,
    ExternalReason,
    ExternalRequestRefused,
    ExternalTransmitFailed,
    GateReason,
    TransmitOutcome,
)

pytestmark = pytest.mark.external_inference


def gate_reason(call: object) -> GateReason:
    with pytest.raises(ExternalGateRefused) as refused:
        call()  # type: ignore[operator]
    return refused.value.reason


def people(container: Container) -> tuple[Principal, Principal]:
    """(requester, approver): the approver's token was minted by somebody else."""
    admin = first_admin(container)
    requester = human(container, admin, "Requester", Role.SECURITY_ADMIN)
    owner = human(container, admin, "Owner", Role.SYSTEM_OWNER)
    return requester, owner


def send(
    container: Container, gateway: ExternalInferenceGateway, requester: Principal, owner: Principal
) -> object:
    proposal = propose(gateway, requester)
    authorization = gateway.request_approval(proposal, actor_id=requester.actor_id)
    container.approvals.approve(authorization.approval_id, owner)
    return gateway.transmit(proposal, authorization.approval_id, actor_id=requester.actor_id)


class TestSwitch:
    def test_the_shipped_settings_refuse_at_the_first_step(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            admin = first_admin(c)
            with pytest.raises(ExternalRequestRefused) as refused:
                propose(c.external_inference, admin)
            assert refused.value.reason is ExternalReason.FEATURE_DISABLED
            proposal = made_up_proposal(c, admin.actor_id)
            for step in (
                lambda: c.external_inference.request_approval(proposal, actor_id=admin.actor_id),
                lambda: c.external_inference.transmit(proposal, "apr_x", actor_id=admin.actor_id),
            ):
                assert gate_reason(step) is GateReason.FEATURE_DISABLED

    def test_switched_on_the_build_still_has_no_transport(self, tmp_path: Path) -> None:
        with build(enabled_settings(tmp_path / "d"), SECRET_ENV) as c:
            admin = first_admin(c)
            proposal = propose(c.external_inference, admin)
            authorize = lambda: c.external_inference.request_approval(  # noqa: E731
                proposal, actor_id=admin.actor_id
            )
            transmit = lambda: c.external_inference.transmit(  # noqa: E731
                proposal, "apr_x", actor_id=admin.actor_id
            )
            assert gate_reason(authorize) is GateReason.TRANSPORT_ABSENT
            assert gate_reason(transmit) is GateReason.TRANSPORT_ABSENT
            assert c.approvals.list_pending() == ()


class TestKillSwitch:
    def test_the_gateway_reads_the_gated_reader_not_the_raw_switch(self, tmp_path: Path) -> None:
        settings = enabled_settings(tmp_path / "d")
        with build(settings, SECRET_ENV) as c:
            first_admin(c)
            for n in range(3):
                c.audit.append(event(n))
        tamper_a_middle_record(settings)  # start-up verification of the audit log fails
        with build(settings, SECRET_ENV) as c:
            capability = KillCapability.EXTERNAL_INFERENCE
            assert c.killswitch.is_blocked(capability) is False  # the operator switch is clear
            assert c.killswitch_reader.is_blocked(capability) is True
            proposal = made_up_proposal(c, "act_someone")
            call = lambda: c.external_inference.request_approval(  # noqa: E731
                proposal, actor_id="act_someone"
            )
            assert gate_reason(call) is GateReason.KILL_SWITCH_ENGAGED

    def test_an_engaged_operator_switch_blocks_too(self, tmp_path: Path) -> None:
        with build(enabled_settings(tmp_path / "d"), SECRET_ENV) as c:
            admin = first_admin(c)
            proposal = propose(c.external_inference, admin)
            c.killswitch.engage(admin, (KillCapability.EXTERNAL_INFERENCE,), "drill")
            call = lambda: c.external_inference.request_approval(  # noqa: E731
                proposal, actor_id=admin.actor_id
            )
            assert gate_reason(call) is GateReason.KILL_SWITCH_ENGAGED


class TestLimitsAndRole:
    def test_with_everything_decided_one_approved_payload_is_sent_once(
        self, tmp_path: Path
    ) -> None:
        with build(enabled_settings(tmp_path / "d"), SECRET_ENV) as c:
            requester, owner = people(c)
            spy = SpyTransport()
            result = send(c, gateway_with(c, spy), requester, owner)
            assert len(spy.calls) == 1
            # A digest key is configured, so the answer's keyed digest is kept.
            assert result.response_digest  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        ("unset", "reason"),
        [
            ("external_max_payload_bytes", GateReason.PAYLOAD_LIMIT_UNSET),
            ("external_max_response_bytes", GateReason.RESPONSE_LIMIT_UNSET),
        ],
    )
    def test_an_unset_limit_refuses(self, tmp_path: Path, unset: str, reason: GateReason) -> None:
        settings = external_on(provisional(tmp_path / "d", **{unset: None}))
        with build(settings, SECRET_ENV) as c:
            requester, _ = people(c)
            spy = SpyTransport()
            gateway = gateway_with(c, spy)
            proposal = propose(gateway, requester)
            call = lambda: gateway.request_approval(  # noqa: E731
                proposal, actor_id=requester.actor_id
            )
            assert gate_reason(call) is reason
            assert spy.calls == []

    def test_the_payload_limit_is_the_configured_one(self, tmp_path: Path) -> None:
        with build(
            enabled_settings(tmp_path / "d", external_max_payload_bytes=50), SECRET_ENV
        ) as c:
            requester, _ = people(c)
            gateway = gateway_with(c, SpyTransport())
            proposal = propose(gateway, requester)
            call = lambda: gateway.request_approval(  # noqa: E731
                proposal, actor_id=requester.actor_id
            )
            assert gate_reason(call) is GateReason.PAYLOAD_TOO_LARGE
            assert c.approvals.list_pending() == ()

    def test_the_response_limit_is_the_configured_one(self, tmp_path: Path) -> None:
        with build(
            enabled_settings(tmp_path / "d", external_max_response_bytes=10), SECRET_ENV
        ) as c:
            requester, owner = people(c)
            spy = SpyTransport(body=b"x" * 11)
            with pytest.raises(ExternalTransmitFailed) as failed:
                send(c, gateway_with(c, spy), requester, owner)
            assert failed.value.outcome is TransmitOutcome.RESPONSE_TOO_LARGE
            assert len(spy.calls) == 1

    def test_the_approver_role_is_the_configured_one(self, tmp_path: Path) -> None:
        settings = external_on(provisional(tmp_path / "d"), approver_role=Role.EXECUTIVE_RISK_OWNER)
        with build(settings, SECRET_ENV) as c:
            requester, _ = people(c)
            gateway = gateway_with(c, SpyTransport())
            authorization = gateway.request_approval(
                propose(gateway, requester), actor_id=requester.actor_id
            )
            assert authorization.required_role is Role.EXECUTIVE_RISK_OWNER
            filed = c.approvals.get(authorization.approval_id)
            assert filed.required_roles == (Role.EXECUTIVE_RISK_OWNER,)
            assert filed.requested_by == requester.actor_id

    def test_an_unset_approver_role_refuses(self, tmp_path: Path) -> None:
        settings = external_on(provisional(tmp_path / "d"), approver_role=None)
        with build(settings, SECRET_ENV) as c:
            requester, _ = people(c)
            gateway = gateway_with(c, SpyTransport())
            proposal = propose(gateway, requester)
            call = lambda: gateway.request_approval(  # noqa: E731
                proposal, actor_id=requester.actor_id
            )
            assert gate_reason(call) is GateReason.APPROVER_ROLE_UNSET

    def test_the_allowed_labels_are_the_configured_ones(self, tmp_path: Path) -> None:
        settings = external_on(provisional(tmp_path / "d"), allowed_classifications=("internal",))
        with build(settings, SECRET_ENV) as c:
            requester, _ = people(c)
            gateway = gateway_with(c, SpyTransport())
            proposal = propose(gateway, requester)  # its one item is labelled public
            shown = gateway.preview(proposal, actor_id=requester.actor_id)
            assert shown.sendable is False
            assert [item.reason for item in shown.dropped] == [
                ExternalReason.CLASSIFICATION_NOT_ALLOWED
            ]


class TestDigestKey:
    def test_a_configured_key_that_does_not_resolve_stops_the_path(self, tmp_path: Path) -> None:
        environ = {
            key: value
            for key, value in SECRET_ENV.items()
            if key != "CISO_SECRET_EXTERNAL_DIGEST_KEY"
        }
        with build(enabled_settings(tmp_path / "d"), environ) as c:
            admin = first_admin(c)
            with pytest.raises(FailClosed):
                propose(c.external_inference, admin)
            assert c.audit.query(limit=10, action_prefix="inference.external.") == []
