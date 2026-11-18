"""Write-adapter contract (blueprint 13.1, 19.1; ADR-0010, ADR-0011).

Interface only. This build holds no adapter to any real system (OD-13), and none may be
added while the broker shares a process with the orchestrator (ADR-0010). Read connectors
never import this package.
"""

from ciso.write_adapters.contract import (
    AdapterManifest,
    AdapterOperation,
    CredentialSource,
    WriteAdapter,
    WriteOutcome,
    WriteReceipt,
    WriteRequest,
    WriteVerification,
)

__all__ = [
    "AdapterManifest",
    "AdapterOperation",
    "CredentialSource",
    "WriteAdapter",
    "WriteOutcome",
    "WriteReceipt",
    "WriteRequest",
    "WriteVerification",
]
