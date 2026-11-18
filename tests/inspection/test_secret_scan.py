"""Secret detection: token shapes, assignments, entropy, placeholders, locations."""

from __future__ import annotations

import pytest
from tests.inspection.samples import (
    ASSIGNED,
    CLOUD_KEY,
    HIGH_ENTROPY,
    JWT,
    SECRET_CASES,
    SERVICE_TOKEN,
    ids,
    j,
    prompt,
    write,
)

from ciso.common.activity import Severity
from ciso.inspection import Inspector
from ciso.inspection.secret_scan import is_placeholder, shannon_entropy

pytestmark = pytest.mark.unit

INSPECTOR = Inspector()


@pytest.mark.parametrize(("text", "rule_id", "value"), SECRET_CASES)
def test_each_secret_shape_is_found_in_a_prompt(text: str, rule_id: str, value: str) -> None:
    result = INSPECTOR.inspect(prompt(f"hello\n{text}\nbye"))
    assert ids(result) == [rule_id]
    assert result.findings[0].location.startswith("line 2, col ")
    assert result.findings[0].category == "secret"
    assert result.complete is True


def test_private_key_is_critical_and_others_at_least_medium() -> None:
    severities = {
        rule_id: INSPECTOR.inspect(prompt(text)).findings[0].severity
        for text, rule_id, _ in SECRET_CASES
    }
    assert severities["secret.private_key"] is Severity.CRITICAL
    assert severities["secret.high_entropy"] is Severity.MEDIUM
    assert all(
        s in {Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM} for s in severities.values()
    )


def test_location_names_line_and_column() -> None:
    result = INSPECTOR.inspect(write(f"a\nb\n   key: {CLOUD_KEY}\n", path="cfg/app.yaml"))
    assert [f.location for f in result.findings] == ["cfg/app.yaml:3:9"]


@pytest.mark.parametrize(
    "text",
    [
        'password = "<your-password>"',
        "token: ${API_TOKEN}",
        "TOKEN=$API_TOKEN",
        'api_key = os.environ["API_KEY"]',
        "api_key = os.getenv('API_KEY')",
        "password=changeme",
        "secret: xxxxxxxxxxxx",
        "password: '********'",
        'client_secret = "secret://payments_client"',
        "AKIAIOSFODNN7EXAMPLE",
        "postgres://app:${DB_PASSWORD}@db:5432/app",
        "password: {{ vault_password }}",
        'token = "your-token-here"',
        "max_tokens: 4096",
        "token_type: bearer",
        "password: str",
        "password = None",
        "",
    ],
)
def test_placeholders_and_non_secrets_are_not_reported(text: str) -> None:
    result = INSPECTOR.inspect(prompt(text))
    assert ids(result) == []
    assert "inspection.secrets" in result.checks_run


def test_code_file_only_reports_quoted_literals() -> None:
    code = (
        "password = get_password()\n"
        'token = request.headers["x-token"]\n'
        "secret = settings.secret\n"
        "password = default_password\n"
        f'api_key = "{ASSIGNED}"\n'
    )
    result = INSPECTOR.inspect(write(code, path="src/app.py"))
    assert [(f.check_id, f.location) for f in result.findings] == [
        ("secret.assignment", "src/app.py:5:1")
    ]


def test_config_file_reports_bare_literals() -> None:
    result = INSPECTOR.inspect(write(f"[db]\npassword={ASSIGNED}\n", path="conf/app.ini"))
    assert ids(result) == ["secret.assignment"]


def test_short_and_numeric_bare_values_are_not_reported() -> None:
    result = INSPECTOR.inspect(write("password=abc\ntoken=123456789\n", path="a.ini"))
    assert ids(result) == []


def test_one_value_is_reported_once_by_the_most_specific_rule() -> None:
    result = INSPECTOR.inspect(prompt(f'github_token = "{SERVICE_TOKEN}"'))
    assert ids(result) == ["secret.service_token"]


def test_high_entropy_exempts_hash_keys_and_low_entropy_values() -> None:
    text = (
        f'commit_sha = "{HIGH_ENTROPY}"\n'
        'BUILD_LABEL = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaB1"\n'
        'all_lower_name = "abcdefghijklmnopqrstuvwxyz0123"\n'
        'REPEATING = "abcABC123abcABC123abcABC123"\n'  # mixed case, entropy about 3.2
    )
    assert ids(INSPECTOR.inspect(prompt(text))) == []


def test_two_shapes_over_one_value_are_one_finding() -> None:
    result = INSPECTOR.inspect(prompt(f"Authorization: Bearer {JWT}"))
    assert ids(result) == ["secret.jwt"]


def test_high_entropy_is_reported_for_any_key_name() -> None:
    result = INSPECTOR.inspect(prompt(f"SEED: {HIGH_ENTROPY}"))
    assert ids(result) == ["secret.high_entropy"]


def test_two_secrets_on_one_line_are_two_findings() -> None:
    result = INSPECTOR.inspect(prompt(f"{CLOUD_KEY} and {SERVICE_TOKEN}"))
    assert ids(result) == ["secret.cloud_access_key", "secret.service_token"]


def test_placeholder_helper_and_entropy() -> None:
    assert is_placeholder("<token>")
    assert is_placeholder("  ")
    assert is_placeholder("CHANGEME")
    assert not is_placeholder(ASSIGNED)
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy(HIGH_ENTROPY) > 4.0
    assert j("a", "b") == "ab"
