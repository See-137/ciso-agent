"""The explicit list of provider classes the gateway may run (blueprint 8.4).

Registering a provider means editing this tuple in a reviewed change. There is no
function that adds to it at run time, and the match is on the exact class, so a subclass
of a registered provider is not accepted.
"""

from __future__ import annotations

from ciso.inference.provider import LocalProvider
from ciso.inference.stub import StubLocalProvider

REGISTERED_PROVIDER_CLASSES: tuple[type[LocalProvider], ...] = (StubLocalProvider,)


def is_registered(provider: object) -> bool:
    return type(provider) in REGISTERED_PROVIDER_CLASSES
