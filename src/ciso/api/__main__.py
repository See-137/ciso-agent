"""Run the API: `python -m ciso.api --config <settings.json>`.

Loads settings, builds the container and serves on the configured host and port (loopback
unless the settings allow otherwise, ADR-0015). Uvicorn's own logging configuration is
switched off so its records reach the container's redacting handler, and its access log
is off because it would print request lines that the platform audits instead.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from ciso.api.app import create_app
from ciso.app.container import build_container
from ciso.app.settings import load_settings

logger = logging.getLogger(__name__)

#: The server's own loggers. They must write through the redacting handler too.
SERVER_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ciso.api")
    parser.add_argument("--config", required=True, type=Path, help="settings JSON file")
    args = parser.parse_args(argv)
    settings = load_settings(args.config)
    with build_container(settings, logger_names=SERVER_LOGGERS) as container:
        readiness = container.readiness()
        if not readiness.ready:
            logger.warning("starting degraded; missing: %s", ", ".join(readiness.missing))
        uvicorn.run(
            create_app(container),
            host=settings.bind_host,
            port=settings.bind_port,
            log_config=None,
            access_log=False,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
