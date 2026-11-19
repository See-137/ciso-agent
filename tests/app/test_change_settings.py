"""Settings of the pre-push path (change store, sandbox client, worker): unset by default,
unset means refuse, every value named in readiness, provisional values present."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ciso.app.governance_settings import CHANGE_SETTING_NAMES, GovernanceSettings
from ciso.app.settings import load_settings

pytestmark = pytest.mark.unit

PROVISIONAL = Path(__file__).resolve().parents[2] / "config" / "provisional-settings.json"


def test_every_change_setting_is_unset_by_default() -> None:
    gov = GovernanceSettings()
    assert CHANGE_SETTING_NAMES  # positive evidence that the list is not empty
    for name in CHANGE_SETTING_NAMES:
        assert getattr(gov, name) is None, name


def test_every_unset_change_setting_is_named_in_readiness() -> None:
    unset = GovernanceSettings().unset()
    for name in CHANGE_SETTING_NAMES:
        assert f"governance.{name}" in unset


def test_a_set_value_is_not_listed() -> None:
    gov = GovernanceSettings(change_retention_seconds=60)
    assert "governance.change_retention_seconds" not in gov.unset()


@pytest.mark.parametrize("field", ["change_key_ref", "sandbox_token_ref"])
def test_key_settings_must_be_references(field: str) -> None:
    with pytest.raises(ValidationError, match="secret://"):
        GovernanceSettings(**{field: "plain-value-not-a-reference"})


@pytest.mark.parametrize(
    "url",
    [
        "http://sandbox.example.test:8790",  # plain http off loopback
        "ftp://127.0.0.1:8790",
        "http://user:pw@127.0.0.1:8790",
        "http://127.0.0.1:8790/?x=1",
        "not a url",
    ],
)
def test_sandbox_url_is_https_or_loopback_http(url: str) -> None:
    with pytest.raises(ValidationError):
        GovernanceSettings(sandbox_url=url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8790", "https://sandbox.example.test"])
def test_good_sandbox_urls_are_kept(url: str) -> None:
    assert GovernanceSettings(sandbox_url=url).sandbox_url == url


@pytest.mark.parametrize(
    "field", ["change_retention_seconds", "sandbox_timeout_seconds", "worker_poll_seconds"]
)
@pytest.mark.parametrize("value", [0, -1])
def test_numbers_must_be_positive(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        GovernanceSettings(**{field: value})


def test_provisional_file_sets_every_change_value() -> None:
    gov = load_settings(PROVISIONAL).governance
    for name in CHANGE_SETTING_NAMES:
        assert getattr(gov, name) is not None, name
    assert gov.required_sandbox_checks == ("secrets", "code", "tests")
    assert gov.sandbox_url is not None
    assert gov.sandbox_url.startswith("http://127.0.0.1")


def test_provisional_sandbox_timeout_fits_inside_the_queue_lease() -> None:
    settings = load_settings(PROVISIONAL)
    lease = settings.safety.queue_lease_seconds
    timeout = settings.governance.sandbox_timeout_seconds
    assert lease is not None
    assert timeout is not None
    assert timeout < lease
