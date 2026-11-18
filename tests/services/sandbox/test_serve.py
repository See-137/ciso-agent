"""Loading the service configuration: token by environment variable, loopback by default."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from services.sandbox.serve import DEFAULT_HOST, load_config

pytestmark = pytest.mark.unit


def write(tmp_path: Path, data: dict[str, object]) -> Path:
    path = tmp_path / "sandbox.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_defaults_bind_loopback_and_leave_everything_unset(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, {}))
    assert DEFAULT_HOST == "127.0.0.1"
    assert config.host == "127.0.0.1"
    assert config.token is None
    assert config.settings.limits.wall_time_seconds is None
    assert config.settings.images.gitleaks is None


def test_token_comes_from_the_named_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SANDBOX_TOKEN_FOR_TEST", "abcdefghijklmnop")
    config = load_config(write(tmp_path, {"token_env": "SANDBOX_TOKEN_FOR_TEST"}))
    assert config.token is not None
    assert config.token.get_secret_value() == "abcdefghijklmnop"
    assert "abcdefghijklmnop" not in repr(config)


def test_missing_or_short_token_is_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SANDBOX_TOKEN_FOR_TEST", raising=False)
    assert load_config(write(tmp_path, {"token_env": "SANDBOX_TOKEN_FOR_TEST"})).token is None
    monkeypatch.setenv("SANDBOX_TOKEN_FOR_TEST", "short")
    assert load_config(write(tmp_path, {"token_env": "SANDBOX_TOKEN_FOR_TEST"})).token is None


def test_a_literal_token_in_the_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="token"):
        load_config(write(tmp_path, {"token": "abcdefghijklmnop"}))


def test_settings_are_read(tmp_path: Path) -> None:
    config = load_config(
        write(
            tmp_path,
            {
                "host": "127.0.0.1",
                "port": 9001,
                "settings": {"limits": {"pids": 64}, "docker_cli": "/usr/bin/docker"},
            },
        )
    )
    assert config.port == 9001
    assert config.settings.limits.pids == 64
    assert config.settings.docker_cli == "/usr/bin/docker"


def test_example_settings_file_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    example = Path(__file__).resolve().parents[3] / "services/sandbox/settings.example.json"
    config = load_config(example)
    assert config.host == "127.0.0.1"
    assert config.settings.limits.wall_time_seconds is None
