"""How the composition root builds the services that need only settings and the shared
parts (plan T1.14; gap G14, ADR-0019). Every safety number comes from `Settings.safety`
and is passed as it is: an unset one reaches its service as `None`, and the service
refuses. `Lifecycle` is what a container must release when it closes.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import Engine

from ciso.app.killswitch_history import AuditKillSwitchHistory
from ciso.app.logging_lease import LogLease
from ciso.app.settings import Settings
from ciso.common.clock import Clock
from ciso.common.protocols import AuditSink, PrincipalResolver, Redactor, SecretResolver
from ciso.identity import Authenticator, IdentityService, ScryptParams
from ciso.inference import InferenceGateway, StubLocalProvider, load_manifest
from ciso.killswitch import KillSwitch
from ciso.policy import OperationCatalog, PolicyEngine, load_default_ruleset


class Lifecycle:
    """The container's only mutable part: what `close()` must release, released once."""

    def __init__(self, logs: LogLease) -> None:
        self.engines: tuple[Engine, ...] = ()
        self.logs = logs
        self.closed = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.logs.release()
        for engine in self.engines:
            engine.dispose()


def seconds(value: float | None) -> timedelta | None:
    """Settings hold seconds; some constructors take timedelta. `None` stays `None`."""
    return None if value is None else timedelta(seconds=value)


def build_killswitch(
    settings: Settings,
    *,
    engine: Engine,
    audit: AuditSink,
    clock: Clock,
    principals: PrincipalResolver,
    secrets: SecretResolver,
    history: AuditKillSwitchHistory,
) -> KillSwitch:
    return KillSwitch(
        engine=engine,
        audit=audit,
        clock=clock,
        principals=principals,
        secrets=secrets,
        key_ref=settings.killswitch_key_ref,
        history=history,
        claim_timeout=seconds(settings.safety.killswitch_claim_timeout_seconds),
    )


def build_authenticator(
    settings: Settings,
    *,
    engine: Engine,
    clock: Clock,
    audit: AuditSink,
    identity: IdentityService,
    scrypt: ScryptParams,
) -> Authenticator:
    return Authenticator(
        engine,
        clock,
        audit,
        identity,
        max_token_ttl=seconds(settings.safety.max_token_ttl_seconds),
        scrypt=scrypt,
    )


def build_inference(
    settings: Settings, *, engine: Engine, clock: Clock, audit: AuditSink, redactor: Redactor
) -> InferenceGateway:
    """The local gateway: exactly one provider, no fallback, no external route."""
    return InferenceGateway(
        StubLocalProvider(),
        redactor,
        audit,
        clock,
        engine,
        load_manifest(),
        timeout_seconds=settings.safety.inference_timeout_seconds,
        max_abandoned_calls=settings.safety.inference_max_abandoned_calls,
    )


def build_policy(
    settings: Settings,
    *,
    catalog: OperationCatalog,
    clock: Clock,
    audit: AuditSink,
    principals: PrincipalResolver,
) -> PolicyEngine:
    return PolicyEngine(
        catalog=catalog,
        ruleset=load_default_ruleset(),
        clock=clock,
        audit=audit,
        principals=principals,
        max_envelope_ttl=seconds(settings.safety.max_envelope_ttl_seconds),
    )
