"""Write credentials behind the kill switch (blueprint 11.2; plan gap G20; ADR-0018).

"Revoke or suspend execution-broker credentials" is met here by suspension: every single
fetch asks the kill switch first. A tool receives this accessor wrapped in the registry's
`ScopedCredentials`, so it can ask only for the references it declared, and only while
write execution is not stopped. Suspending is not revoking: a secret a tool already holds
stays valid at its target (ADR-0018, weaknesses).
"""

from __future__ import annotations

from ciso.common.enums import KillCapability
from ciso.common.errors import FailClosed, KillSwitchEngaged
from ciso.common.protocols import KillSwitchReader, RevealableSecret, SecretResolver


class KillSwitchGatedCredentials:
    """A `CredentialAccessor` that resolves a secret only while `writes` reads clear,
    and, when built with `l3=True` (the call is for a level 3 or higher tool), only
    while `l3_runs` reads clear as well.

    Checked on EVERY `get`, not once per execution: an engage that lands after the
    broker's gates still stops the next fetch. Only an answer that is exactly `False`
    counts as clear; a reader that raises is `FailClosed`. This stops the next fetch; it
    does not interrupt a tool that already holds its secret.
    """

    def __init__(
        self, killswitch: KillSwitchReader, secrets: SecretResolver, *, l3: bool = False
    ) -> None:
        self._killswitch = killswitch
        self._secrets = secrets
        self._capabilities = (
            (KillCapability.WRITES, KillCapability.L3_RUNS) if l3 else (KillCapability.WRITES,)
        )

    def get(self, ref: str) -> RevealableSecret:
        for capability in self._capabilities:
            try:
                blocked = self._killswitch.is_blocked(capability)
            except Exception as exc:
                raise FailClosed(
                    f"kill switch could not be read ({type(exc).__name__}); no credential released"
                ) from exc
            if blocked is not False:
                raise KillSwitchEngaged(f"{capability.value} is stopped; no credential released")
        return self._secrets.get(ref)

    def __repr__(self) -> str:
        return "KillSwitchGatedCredentials()"
