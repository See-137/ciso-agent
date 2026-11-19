"""The sandbox client: the only module in `src` that talks to a network. Every test uses
`httpx.MockTransport`; nothing opens a socket."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from tests.fakes.core import FakeSecrets

from ciso.app.change_models import SandboxInput
from ciso.app.sandbox_client import MAX_REPORT_BYTES, SandboxClient, SandboxUnavailable
from ciso.common.errors import FailClosed

pytestmark = pytest.mark.unit

URL = "http://127.0.0.1:8790"
TOKEN_REF = "secret://sandbox_token"
TOKEN = "sandbox-token-for-tests-0123"
BUNDLE = b"# v2 git bundle\nbody"
BASE = "a" * 40
HEAD = "b" * 40
ITEM = SandboxInput(change_id="chg_1", bundle=BUNDLE, base=BASE, head=HEAD, commits=(HEAD,))
REPORT = {"job_id": "chg_1", "checks": [{"check_id": "tests", "status": "passed"}]}


def _client(handler: Callable[[httpx.Request], httpx.Response], **changes: Any) -> SandboxClient:
    args: dict[str, Any] = {
        "url": URL,
        "token_ref": TOKEN_REF,
        "secrets": FakeSecrets({TOKEN_REF: TOKEN}),
        "timeout_seconds": 5.0,
        "transport": httpx.MockTransport(handler),
    }
    args.update(changes)
    return SandboxClient(**args)


def test_a_job_is_posted_with_the_token_and_the_report_comes_back() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=REPORT)

    report = _client(handler).run(ITEM, ("secrets", "code", "tests"))
    assert report == REPORT
    (request,) = seen
    assert (request.method, str(request.url)) == ("POST", URL + "/v1/jobs")
    assert request.headers["authorization"] == "Bearer " + TOKEN
    body = json.loads(request.content)
    assert body == {
        "job_id": "chg_1",
        "archive_format": "git_bundle",
        "archive_b64": base64.b64encode(BUNDLE).decode(),
        "base_ref": BASE,
        "head": HEAD,
        "commits": [HEAD],
        "checks": ["secrets", "code", "tests"],
    }


@pytest.mark.parametrize("status", [401, 413, 422, 429, 500, 503, 302])
def test_any_other_status_is_unavailable(status: int) -> None:
    client = _client(lambda r: httpx.Response(status, headers={"location": "http://x"}))
    with pytest.raises(SandboxUnavailable) as caught:
        client.run(ITEM, ("tests",))
    assert caught.value.code == f"status_{status}"


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b"x" * (MAX_REPORT_BYTES + 1)])
def test_a_bad_body_is_unavailable(body: bytes) -> None:
    client = _client(lambda r: httpx.Response(200, content=body))
    with pytest.raises(SandboxUnavailable):
        client.run(ITEM, ("tests",))


def test_a_transport_error_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(SandboxUnavailable) as caught:
        _client(handler).run(ITEM, ("tests",))
    assert caught.value.code == "ConnectError"


def test_the_token_never_reaches_an_error_message() -> None:
    client = _client(lambda r: httpx.Response(500, text=TOKEN))
    with pytest.raises(SandboxUnavailable) as caught:
        client.run(ITEM, ("tests",))
    assert TOKEN not in str(caught.value)
    assert TOKEN not in repr(client)


@pytest.mark.parametrize(
    "changes",
    [
        {"url": None},
        {"token_ref": None},
        {"timeout_seconds": None},
        {"secrets": FakeSecrets({})},  # the token does not resolve
        {"secrets": FakeSecrets({TOKEN_REF: "short"})},  # too short to be a token
    ],
)
def test_unset_or_unusable_settings_refuse_before_sending(changes: dict[str, Any]) -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=REPORT)

    client = _client(handler, **changes)
    with pytest.raises(FailClosed):
        client.run(ITEM, ("tests",))
    assert sent == []


@pytest.mark.parametrize("url", ["http://sandbox.example.test", "ftp://127.0.0.1"])
def test_a_url_that_is_not_https_or_loopback_refuses(url: str) -> None:
    with pytest.raises(FailClosed):
        _client(lambda r: httpx.Response(200, json=REPORT), url=url).run(ITEM, ("tests",)
        )


def test_no_checks_refuses() -> None:
    with pytest.raises(FailClosed):
        _client(lambda r: httpx.Response(200, json=REPORT)).run(ITEM, ())


def test_the_sandbox_client_is_the_only_network_module() -> None:
    """Without its exemption, the network rule finds violations in this module and in
    no other: exactly one network module in `src`."""
    from tests.architecture import test_import_boundaries as rules

    assert frozenset({"ciso.app.sandbox_client"}) == rules.NETWORK_ALLOWLIST
    tree = rules.load(rules.SRC)  # type: ignore[attr-defined]
    _scanned, violations = rules._banned_report(
        tree, rules.NETWORK_NAMES, rules.NETWORK_ATTRIBUTES, frozenset(), frozenset()
    )
    offenders = {line.split(":")[0] for line in violations}
    assert offenders == {"ciso.app.sandbox_client"}


def test_an_oversized_but_well_formed_report_is_unavailable() -> None:
    body = json.dumps({"job_id": "x", "pad": "y" * MAX_REPORT_BYTES}).encode()
    client = _client(lambda r: httpx.Response(200, content=body))
    with pytest.raises(SandboxUnavailable) as caught:
        client.run(ITEM, ("tests",))
    assert caught.value.code == "report_too_large"
