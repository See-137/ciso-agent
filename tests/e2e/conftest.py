"""End-to-end fixtures: the API fixtures (a real container on tmp_path and a TestClient)."""

from __future__ import annotations

from tests.api.conftest import api, make_api

__all__ = ["api", "make_api"]
