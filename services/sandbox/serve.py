"""Configuration loading and the entry point: `python -m services.sandbox.serve <config.json>`.

The configuration file holds settings and the NAME of the environment variable that holds
the bearer token; a token value in the file is refused. The service binds 127.0.0.1 unless
the file says otherwise.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Final

from pydantic import Field, SecretStr
from services.sandbox.app import create_app
from services.sandbox.docker import DockerBackend
from services.sandbox.process import SubprocessRunner, minimal_env
from services.sandbox.runner import JobRunner
from services.sandbox.settings import SandboxSettings

from ciso.common.clock import SystemClock
from ciso.common.schemas import Model

logger = logging.getLogger(__name__)

DEFAULT_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 8790
#: Shortest token accepted; a shorter value counts as unset.
MIN_TOKEN_CHARS: Final = 16
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


class _FileConfig(Model):
    host: Annotated[str, Field(min_length=1, max_length=255)] = DEFAULT_HOST
    port: Annotated[int, Field(ge=1, le=65535, strict=True)] = DEFAULT_PORT
    token_env: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")] | None = None
    settings: SandboxSettings = Field(default_factory=SandboxSettings)


class ServiceConfig(Model):
    host: str
    port: int
    token: SecretStr | None
    settings: SandboxSettings


def load_config(path: Path) -> ServiceConfig:
    """Read the JSON file; resolve the token from the named environment variable."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = {k: v for k, v in raw.items() if not k.startswith("_")}
    parsed = _FileConfig.model_validate(raw)
    token: SecretStr | None = None
    if parsed.token_env is not None and _ENV_NAME.fullmatch(parsed.token_env):
        value = os.environ.get(parsed.token_env, "")
        if len(value) >= MIN_TOKEN_CHARS:
            token = SecretStr(value)
        else:
            logger.warning("token variable %s unset or too short: jobs refused", parsed.token_env)
    return ServiceConfig(host=parsed.host, port=parsed.port, token=token, settings=parsed.settings)


def main(argv: Sequence[str] | None = None) -> None:  # pragma: no cover - starts a server
    import uvicorn

    parser = argparse.ArgumentParser(description="CISO sandbox service (component C5)")
    parser.add_argument("config", type=Path)
    args = parser.parse_args(argv)
    config = load_config(args.config)
    backend = DockerBackend(SubprocessRunner(minimal_env()), config.settings.docker_cli)
    runner = JobRunner(backend, config.settings, SystemClock())
    uvicorn.run(create_app(runner=runner, token=config.token), host=config.host, port=config.port)


if __name__ == "__main__":  # pragma: no cover
    main()
