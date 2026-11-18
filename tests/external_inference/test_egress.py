"""Egress and audit completeness for the external model path (blueprint 8.4, 10.2;
NFR-003; Appendix D #3; plan row T2.8).

The only thing that could carry bytes out is the transport, and the only transport here
is a test spy. The socket guard from the root conftest proves that the whole external
path, run end to end, opens no connection.
"""

from __future__ import annotations

import ast
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import REPO_ROOT, EgressAttempt
from tests.external_inference.conftest import (
    MODEL,
    PROVIDER,
    PURPOSE,
    REQUESTER,
    SpyTransport,
)
from tests.fakes.core import FakeAudit

from ciso.approvals import ApprovalService, ApprovalStatus
from ciso.common.enums import AuditOutcome
from ciso.common.principal import Principal
from ciso.inference.external import (
    ContextItem,
    ExternalGateRefused,
    ExternalInferenceGateway,
)

pytestmark = pytest.mark.external_inference

INFERENCE_DIR = REPO_ROOT / "src" / "ciso" / "inference"
EXTERNAL_PACKAGE = "ciso.inference.external"

A, S, D = AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS, AuditOutcome.DENIED


def test_the_socket_guard_is_active(egress_guard: list[Any]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(EgressAttempt):
            sock.connect(("192.0.2.10", 443))
        with pytest.raises(EgressAttempt):
            sock.connect_ex(("192.0.2.10", 443))
    finally:
        sock.close()
    assert egress_guard == [("192.0.2.10", 443), ("192.0.2.10", 443)]


def test_full_external_path_opens_no_connection_and_audits_every_step(
    egress_guard: list[Any],
    make_gateway: Callable[..., ExternalInferenceGateway],
    make_item: Callable[..., ContextItem],
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
) -> None:
    """Every step through the gateway, the one object a router talks to."""
    gateway = make_gateway()
    proposal = gateway.propose(
        requester_actor_id=REQUESTER,
        purpose=PURPOSE,
        provider_name=PROVIDER,
        model_name=MODEL,
        items=[make_item("a1"), make_item("b2", classification="restricted")],
    )
    preview = gateway.preview(proposal, actor_id=REQUESTER)
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    approvals.approve(made.approval_id, approver)
    result = gateway.transmit(proposal, made.approval_id, actor_id=REQUESTER)

    # Positive evidence that the path ran to the end.
    assert spy.calls == [(PROVIDER, MODEL, preview.preview_bytes)]
    assert approvals.get(made.approval_id).status is ApprovalStatus.CONSUMED
    assert result.output.size > 0
    assert [d.ref for d in made.dropped] == ["evidence:b2"]

    assert egress_guard == []

    target = f"external_request:{proposal.request_id}"
    approval_ref = f"approval:{made.approval_id}"
    assert [(e.action, e.outcome, e.target, e.actor_id) for e in audit.events] == [
        ("inference.external.propose", A, target, REQUESTER),
        ("inference.external.propose", S, target, REQUESTER),
        ("inference.external.preview", S, target, REQUESTER),
        ("inference.external.authorize", A, target, REQUESTER),
        ("approval.request", A, approval_ref, REQUESTER),
        ("approval.request", S, approval_ref, REQUESTER),
        ("inference.external.authorize", S, target, REQUESTER),
        ("approval.approve", A, approval_ref, approver.actor_id),
        ("approval.approve", S, approval_ref, approver.actor_id),
        ("approval.consume", A, approval_ref, REQUESTER),
        ("approval.consume", S, approval_ref, REQUESTER),
        ("inference.external.transmit", A, target, REQUESTER),
        ("inference.external.transmit", S, target, REQUESTER),
    ]
    sent = audit.events[-1].details
    assert sent["payload_sha256"] == preview.payload_hash
    assert sent["approval_ref"] == approval_ref
    assert sent["approver"] == approver.actor_id
    assert sent["record_id"] == result.record_id
    assert sent["outcome"] == "sent"


def test_a_refused_transmit_is_audited_and_opens_no_connection(
    egress_guard: list[Any],
    make_gateway: Callable[..., ExternalInferenceGateway],
    make_proposal: Callable[..., Any],
    spy: SpyTransport,
    audit: FakeAudit,
) -> None:
    proposal = make_proposal()
    with pytest.raises(ExternalGateRefused, match="feature_disabled"):
        make_gateway(enabled=False).transmit(proposal, "apr_" + "0" * 26, actor_id=REQUESTER)
    assert [(e.action, e.outcome) for e in audit.find("inference.external.transmit")] == [
        ("inference.external.transmit", D)
    ]
    assert spy.calls == []
    assert egress_guard == []


# --- the local gateway cannot name the external package ------------------------------------


def external_imports(source: str, module: str) -> list[str]:
    """Imports in `source` that reach the external package, absolute or relative."""
    package = module.rsplit(".", 1)[0]
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                anchor = package.split(".")[: len(package.split(".")) - (node.level - 1)]
                base = ".".join([*anchor, base] if base else anchor)
            names = [base, *(f"{base}.{alias.name}" for alias in node.names)]
        found.extend(
            name
            for name in names
            if name == EXTERNAL_PACKAGE or name.startswith(EXTERNAL_PACKAGE + ".")
        )
    return found


def _local_modules() -> list[Path]:
    return sorted(INFERENCE_DIR.glob("*.py"))


def test_local_inference_modules_import_nothing_from_the_external_package() -> None:
    paths = _local_modules()
    names = {path.name for path in paths}
    assert {"gateway.py", "records.py", "provider.py", "registry.py", "__init__.py"} <= names
    violations: dict[str, list[str]] = {}
    for path in paths:
        # `__init__` keeps its own name so that its package resolves to `ciso.inference`.
        module = f"ciso.inference.{path.stem}"
        found = external_imports(path.read_text(encoding="utf-8"), module)
        if found:
            violations[path.name] = found
    assert violations == {}
    gateway_source = (INFERENCE_DIR / "gateway.py").read_text(encoding="utf-8")
    assert "class InferenceGateway" in gateway_source
    code_names = {
        node.id for node in ast.walk(ast.parse(gateway_source)) if isinstance(node, ast.Name)
    } | {
        node.attr for node in ast.walk(ast.parse(gateway_source)) if isinstance(node, ast.Attribute)
    }
    assert len(code_names) > 50
    assert not [name for name in code_names if "external" in name.lower()]


@pytest.mark.parametrize(
    "line",
    [
        "import ciso.inference.external",
        "import ciso.inference.external.gateway as g",
        "from ciso.inference.external import ExternalInferenceGateway",
        "from ciso.inference import external",
        "from . import external",
        "from .external import gateway",
        "from .external.gateway import ExternalInferenceGateway",
    ],
)
def test_the_import_check_sees_a_planted_import(line: str) -> None:
    assert external_imports(line + "\n", "ciso.inference.gateway")
    assert external_imports("import json\nfrom .records import X\n", "ciso.inference.gateway") == []
