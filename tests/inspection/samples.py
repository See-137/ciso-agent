"""Fake credentials for the inspection tests, assembled at run time.

None of these is a real credential. They are split into pieces so the repository itself
never holds a token-shaped literal that a scanner (ours or anyone's) would report.
"""

from __future__ import annotations

from ciso.common.activity import ActionKind, InspectionInput


def j(*parts: str) -> str:
    return "".join(parts)


CLOUD_KEY = j("AKIA", "Q3EGRTZ7", "WN5HJ2KD")
PEM_HEADER = j("-----BEGIN ", "RSA PRIVATE", " KEY-----")
JWT = j(
    "eyJhbGciOiJIUzI1NiJ9",
    ".",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    ".",
    "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
)
SERVICE_TOKEN = j("gh", "p_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5")
CHAT_TOKEN = j("xo", "xb-", "2048", "-", "77aa88bb99cc", "-", "Qz1")
BEARER_VALUE = j("dGhpcyBpcyBh", "LnRva2VuLjEyMzQ1Njc4")
CONN_PASSWORD = j("S3cr3t", "Passw0rd", "Q9")
ASSIGNED = j("hunter", "2Correct", "Horse")
HIGH_ENTROPY = j("Zq8XvR2", "mK9pL4wT", "7nB3cY6hJ1sD")

#: (text, rule id expected, the value that must never appear in a result)
SECRET_CASES: tuple[tuple[str, str, str], ...] = (
    (PEM_HEADER, "secret.private_key", PEM_HEADER),
    (f"export KEY_ID={CLOUD_KEY}", "secret.cloud_access_key", CLOUD_KEY),
    (f"cookie: {JWT}", "secret.jwt", JWT),
    (f"Authorization: Bearer {BEARER_VALUE}", "secret.bearer_token", BEARER_VALUE),
    (f"use {SERVICE_TOKEN} to clone", "secret.service_token", SERVICE_TOKEN),
    (f"notify via {CHAT_TOKEN}", "secret.service_token", CHAT_TOKEN),
    (
        f"DATABASE_URL=postgres://app:{CONN_PASSWORD}@db.internal:5432/app",
        "secret.connection_string",
        CONN_PASSWORD,
    ),
    (f'db_password = "{ASSIGNED}"', "secret.assignment", ASSIGNED),
    (f'SIGNING_SEED = "{HIGH_ENTROPY}"', "secret.high_entropy", HIGH_ENTROPY),
)


def write(
    content: str | None, path: str = "notes.txt", action_id: str = "act_1"
) -> InspectionInput:
    return InspectionInput(
        action_id=action_id, kind=ActionKind.FILE_WRITE, path=path, content=content
    )


def prompt(content: str | None) -> InspectionInput:
    return InspectionInput(action_id="act_p", kind=ActionKind.PROMPT, content=content)


def command(text: str | None) -> InspectionInput:
    return InspectionInput(action_id="act_c", kind=ActionKind.SHELL_COMMAND, command=text)


def push(diff: str | None) -> InspectionInput:
    return InspectionInput(action_id="act_d", kind=ActionKind.GIT_PUSH, content=diff)


def ids(result: object) -> list[str]:
    return [f.check_id for f in result.findings]  # type: ignore[attr-defined]
