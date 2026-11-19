"""HTTP surface: `POST /v1/jobs` (bearer token) and `GET /healthz`. Nothing else.

- The token comes from configuration (`serve.load_config`); unset means every job is
  refused with 503. It is compared in constant time (`hmac.compare_digest`).
- The body is read with a hard cap before parsing. Errors never echo the input.
- One job at a time: a second request while one runs gets 429. The job runs synchronously
  in a worker thread and is bounded by the job's wall-time limit.
- No interactive docs or schema routes.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
import threading
from typing import Annotated, Any, Final

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import Field, SecretStr, ValidationError
from services.sandbox.job import MAX_ARCHIVE_BYTES, ArchiveFormat, CheckId, Job
from services.sandbox.runner import JobRunner

from ciso.common.schemas import Model

logger = logging.getLogger(__name__)

#: Largest request body: the base64 of the largest archive plus room for the other fields.
MAX_BODY_BYTES: Final = (MAX_ARCHIVE_BYTES * 4) // 3 + 64 * 1024

_UNAUTHORIZED = {"detail": "unauthorized"}


class JobRequest(Model):
    """Wire form of a job: the archive is base64 text."""

    job_id: str
    archive_format: ArchiveFormat
    archive_b64: Annotated[str, Field(min_length=1, max_length=MAX_BODY_BYTES)]
    base_ref: str | None = None
    #: Bundle jobs only: the commit the bundle's HEAD must be, and every commit of the
    #: range (head first). Checked against the bundle before anything runs.
    head: str | None = None
    commits: tuple[str, ...] | None = None
    checks: tuple[CheckId, ...]

    def to_job(self) -> Job:
        try:
            archive = base64.b64decode(self.archive_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("archive_b64 is not base64") from exc
        return Job(
            job_id=self.job_id,
            archive_format=self.archive_format,
            archive=archive,
            base_ref=self.base_ref,
            head=self.head,
            commits=self.commits,
            checks=self.checks,
        )


def _authorized(header: str | None, token: SecretStr) -> bool:
    scheme, _, given = (header or "").partition(" ")
    if scheme != "Bearer" or not given:
        return False
    return hmac.compare_digest(given.encode("utf-8"), token.get_secret_value().encode("utf-8"))


async def _read_capped(request: Request) -> bytes | None:
    """The body, or None when it is larger than `MAX_BODY_BYTES`."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _parse(body: bytes) -> Job | None:
    try:
        data: Any = json.loads(body)
        return JobRequest.model_validate(data).to_job()
    except (ValueError, ValidationError):
        return None


def create_app(*, runner: JobRunner, token: SecretStr | None) -> FastAPI:
    """The sandbox HTTP app. `token=None` refuses every job (fail closed)."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.job_lock = threading.Lock()

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        health = runner.health()
        body = {
            "usable": health.usable,
            "missing": list(health.missing),
            "backend": list(health.backend_reasons),
        }
        return JSONResponse(body, status_code=200 if health.usable else 503)

    @app.post("/v1/jobs")
    async def jobs(request: Request) -> JSONResponse:
        if token is None:
            return JSONResponse({"detail": "service token not configured"}, status_code=503)
        if not _authorized(request.headers.get("authorization"), token):
            return JSONResponse(
                _UNAUTHORIZED, status_code=401, headers={"WWW-Authenticate": "Bearer"}
            )
        body = await _read_capped(request)
        if body is None:
            return JSONResponse({"detail": "body too large"}, status_code=413)
        job = _parse(body)
        if job is None:
            return JSONResponse({"detail": "invalid job"}, status_code=422)
        lock: threading.Lock = app.state.job_lock
        if not lock.acquire(blocking=False):
            return JSONResponse({"detail": "busy"}, status_code=429)
        try:
            report = await run_in_threadpool(runner.run, job)
        finally:
            lock.release()
        logger.info("job %s finished", job.job_id)
        return JSONResponse(report.to_wire(), status_code=200)

    return app
