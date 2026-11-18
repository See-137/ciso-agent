"""The HTTP surface: one authenticated job endpoint and a health endpoint."""

from __future__ import annotations

import base64
import hmac
import warnings
from collections.abc import Iterator

import pytest
from pydantic import SecretStr
from services.sandbox.app import create_app
from services.sandbox.report import validate_wire
from services.sandbox.runner import JobRunner
from services.sandbox.settings import SandboxSettings
from tests.services.sandbox.support import FakeBackend, fixture_bytes, outcome, tar_of

from ciso.common.clock import FixedClock
from services.sandbox import app as app_module

# The installed starlette deprecates its httpx-based TestClient in favour of a package that is
# not installed (same workaround as tests/api/helpers.py).
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient`")
    from fastapi.testclient import TestClient

pytestmark = pytest.mark.unit

TOKEN = "test-token-0123456789"


def body(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "job_id": "job-1",
        "archive_format": "tar",
        "archive_b64": base64.b64encode(tar_of({"README.md": b"hi"})).decode(),
        "checks": ["secrets"],
    }
    values.update(overrides)
    return values


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend(outcomes={"gitleaks": outcome(0, fixture_bytes("gitleaks_report.json"))})


@pytest.fixture
def client(
    settings: SandboxSettings, clock: FixedClock, backend: FakeBackend
) -> Iterator[TestClient]:
    app = create_app(runner=JobRunner(backend, settings, clock), token=SecretStr(TOKEN))
    with TestClient(app) as test_client:
        yield test_client


def auth(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_job_returns_the_report(client: TestClient, backend: FakeBackend) -> None:
    response = client.post("/v1/jobs", json=body(), headers=auth())
    assert response.status_code == 200
    data = response.json()
    validate_wire(data)
    assert data["job_id"] == "job-1"
    assert data["checks"][0]["status"] == "failed"
    assert len(backend.specs) == 1


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong"},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": f"bearer{TOKEN}"},
        {"Authorization": f"Bearer {TOKEN} "},
        {"Authorization": f"Bearer {TOKEN}x"},
    ],
)
def test_bad_or_missing_token_is_401_and_runs_nothing(
    client: TestClient, backend: FakeBackend, headers: dict[str, str]
) -> None:
    response = client.post("/v1/jobs", json=body(), headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert backend.specs == []


def test_token_compare_is_constant_time(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    seen: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        seen.append((a, b))
        return bool(real(a, b))

    monkeypatch.setattr(hmac, "compare_digest", spy)
    client.post("/v1/jobs", json=body(), headers=auth("wrong"))
    assert seen == [(b"wrong", TOKEN.encode())]


def test_unset_token_refuses_every_job(
    settings: SandboxSettings, clock: FixedClock, backend: FakeBackend
) -> None:
    app = create_app(runner=JobRunner(backend, settings, clock), token=None)
    with TestClient(app) as test_client:
        response = test_client.post("/v1/jobs", json=body(), headers=auth())
    assert response.status_code == 503
    assert backend.specs == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"archive_b64": "not base64!!"},
        {"archive_b64": ""},
        {"job_id": "a b"},
        {"checks": ["shell"]},
        {"archive_format": "zip"},
        {"extra": 1},
        {"base_ref": "main"},
    ],
)
def test_malformed_jobs_are_422_without_echo(
    client: TestClient, backend: FakeBackend, overrides: dict[str, object]
) -> None:
    response = client.post("/v1/jobs", json=body(**overrides), headers=auth())
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid job"}
    assert backend.specs == []


def test_non_json_body_is_422(client: TestClient) -> None:
    response = client.post("/v1/jobs", content=b"{", headers=auth())
    assert response.status_code == 422


def test_oversized_body_is_413(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    monkeypatch.setattr(app_module, "MAX_BODY_BYTES", 100)
    response = client.post("/v1/jobs", json=body(), headers=auth())
    assert response.status_code == 413


def test_oversized_streamed_body_without_length_is_413(
    monkeypatch: pytest.MonkeyPatch, client: TestClient, backend: FakeBackend
) -> None:
    monkeypatch.setattr(app_module, "MAX_BODY_BYTES", 100)
    chunks = iter([b'{"job_id": "', b"x" * 200, b'"}'])
    response = client.post("/v1/jobs", content=chunks, headers=auth())
    assert "content-length" not in {k.lower() for k in response.request.headers}
    assert response.status_code == 413
    assert backend.specs == []


def test_busy_service_refuses_a_second_job(
    settings: SandboxSettings, clock: FixedClock, backend: FakeBackend
) -> None:
    app = create_app(runner=JobRunner(backend, settings, clock), token=SecretStr(TOKEN))
    with TestClient(app) as test_client:
        lock = app.state.job_lock
        assert lock.acquire(blocking=False)
        try:
            response = test_client.post("/v1/jobs", json=body(), headers=auth())
        finally:
            lock.release()
        assert response.status_code == 429
        assert backend.specs == []
        assert test_client.post("/v1/jobs", json=body(), headers=auth()).status_code == 200


def test_healthz_usable(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"usable": True, "missing": [], "backend": []}


def test_healthz_unusable_is_503(clock: FixedClock) -> None:
    app = create_app(runner=JobRunner(None, SandboxSettings(), clock), token=SecretStr(TOKEN))
    with TestClient(app) as test_client:
        response = test_client.get("/healthz")
    assert response.status_code == 503
    data = response.json()
    assert data["usable"] is False
    assert data["backend"] == ["no_backend"]
    assert "limits" in data["missing"]


def test_only_the_two_routes_exist(client: TestClient) -> None:
    paths = {getattr(r, "path", "") for r in client.app.routes}  # type: ignore[attr-defined]
    assert paths == {"/v1/jobs", "/healthz"}
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
