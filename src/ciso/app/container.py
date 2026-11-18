"""Composition root: builds one of each service from `Settings` (plan T1.14, G14, G18, G20).

`build_container` is the only place where modules meet. It holds no module-level state:
calling it twice with two data directories gives two independent containers.

Degraded mode. A required value that is unset or cannot be resolved does not stop start-up
and is never replaced by a generated value. The container starts, `readiness()` names
what is missing, and the component that needs it refuses:

- audit: no usable anchor key, an anchor or witness inside the audit database's directory,
  a configured witness whose key is unusable, or a wiped or unopenable log. Every append
  then raises `FailClosed`, so every write path that audits first stops (blueprint 9.5,
  ADR-0013). The witness is wired only when its path, key and cadence are all set
  (`ciso.app.audit_wiring.build_witness`); otherwise the log is unwitnessed and readiness
  carries the integrity warning;
- every key reference must resolve to at least `ciso.vault.MIN_KEY_BYTES` bytes; one that
  does not is listed in `missing` (`ciso.app.readiness`);
- kill switch: no usable MAC key. Every capability reads as blocked (ADR-0018);
- start-up: the one `ciso.ops` sequence runs (kill-switch initialise, audit chain walk,
  owed audit delivery, reconcile; `ciso.app.killswitch_startup`). A log that does not
  verify `ok`, a failed step or a flag that disagrees with the audit log is listed in
  readiness, and `killswitch_reader` (a `GatedKillSwitch`, the only reader consumers get)
  keeps writes and L3 runs blocked. The API refuses state-changing requests while it does;
- an unset safety number reaches its service as `None`, and that service refuses (G14).
  Every safety number comes from `Settings.safety`, never from a `build_container`
  argument.

External inference is not wired here (blueprint 8.4, ADR-0006): the container holds no
such service.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from types import TracebackType
from typing import IO, Self

from sqlalchemy import Engine

from ciso.app import tables as app_tables
from ciso.app.audit_wiring import UnavailableAuditLog, build_witness, open_audit
from ciso.app.health_checks import AUTH_AUDIT_GAUGE, register_health
from ciso.app.killswitch_history import AuditKillSwitchHistory
from ciso.app.killswitch_startup import run_startup
from ciso.app.logging_lease import LogLease, acquire_logging
from ciso.app.policy_context import DefaultPolicyContext
from ciso.app.readiness import (
    HEALTH_UNTIMED,
    SECRET_REF_FIELDS,
    Readiness,
    startup_warnings,
    unusable_refs,
)
from ciso.app.settings import Settings
from ciso.audit import AuditLog, FileHeadWitness, HeadAnchor, init_audit_schema
from ciso.common.clock import Clock, SystemClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.identity import (
    PRODUCTION_SCRYPT,
    Authenticator,
    HostLocalAdmin,
    IdentityService,
    ScryptParams,
)
from ciso.identity import tables as identity_tables
from ciso.inference import InferenceGateway, StubLocalProvider, load_manifest
from ciso.inference import tables as inference_tables
from ciso.killswitch import KillSwitch
from ciso.killswitch import tables as killswitch_tables
from ciso.observability.health import HealthRegistry
from ciso.observability.metrics import MetricNames, MetricsRegistry
from ciso.ops import GatedKillSwitch, IntegrityState, StartupReport
from ciso.policy import OperationCatalog, PolicyEngine, load_default_ruleset
from ciso.vault import EnvSecretStore, SecretRedactor
from ciso.workflows import JobQueue
from ciso.workflows import tables as workflows_tables

logger = logging.getLogger(__name__)

#: Every module whose tables live on the operational database. Importing them registers
#: the tables, so `init_operational_schema` creates them.
TABLE_MODULES = (
    app_tables,
    identity_tables,
    inference_tables,
    killswitch_tables,
    workflows_tables,
)

#: Re-exported from `ciso.app.readiness` and `ciso.app.policy_context`, where they live.
__all__ = [
    "HEALTH_UNTIMED",
    "SECRET_REF_FIELDS",
    "TABLE_MODULES",
    "AuditService",
    "Container",
    "DefaultPolicyContext",
    "Readiness",
    "build_container",
]

AuditService = AuditLog | UnavailableAuditLog


class _Lifecycle:
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


@dataclass(frozen=True, kw_only=True)
class Container:
    """One of each service, wired. Use as a context manager or call `close()`."""

    settings: Settings
    clock: Clock
    redactor: SecretRedactor
    secret_store: EnvSecretStore
    operational_engine: Engine
    audit_engine: Engine
    anchor: HeadAnchor | None
    #: The audit head witness, or None when path, key or cadence is unset.
    witness: FileHeadWitness | None
    audit: AuditService
    #: The raw operator switch: only the kill-switch routes and the admin command use it
    #: (engage, release, status, reconcile).
    killswitch: KillSwitch
    #: The only `KillSwitchReader` handed to consumers: blocked when the switch is, or
    #: when start-up integrity does not allow the capability (`ciso.ops.integrity`).
    killswitch_reader: GatedKillSwitch
    #: Outcome of the start-up sequence and the state the gate reads.
    startup_report: StartupReport
    integrity: IntegrityState
    identity: IdentityService
    authenticator: Authenticator
    #: Bootstrap and lockout recovery. For a host-local command only; the API never uses it.
    host_local: HostLocalAdmin
    catalog: OperationCatalog
    policy: PolicyEngine
    policy_context: DefaultPolicyContext
    queue: JobQueue
    inference: InferenceGateway
    metrics: MetricsRegistry
    health: HealthRegistry
    missing: tuple[str, ...]
    warnings: tuple[str, ...]
    _lifecycle: _Lifecycle = field(repr=False)

    def readiness(self) -> Readiness:
        """`Settings.missing_for_writes()`, unresolvable references and start-up problems."""
        return Readiness(
            ready=not self.missing,
            missing=self.missing,
            warnings=self.warnings,
        )

    def close(self) -> None:
        """Release the log handler (removed, and the root level restored, once no other
        live container uses it) and dispose both engines. Idempotent."""
        self._lifecycle.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _seconds(value: float | None) -> timedelta | None:
    """Settings hold seconds; some constructors take timedelta. `None` stays `None`."""
    return None if value is None else timedelta(seconds=value)


def build_container(
    settings: Settings,
    *,
    environ: Mapping[str, str] | None = None,
    clock: Clock | None = None,
    scrypt: ScryptParams = PRODUCTION_SCRYPT,
    log_stream: IO[str] | None = None,
    log_level: int | str = logging.INFO,
    logger_names: Sequence[str] = (),
) -> Container:
    """Open both databases under `settings.data_dir` and build every service.

    `environ` is where `secret://` references are looked up (default: the process
    environment). `scrypt` sets the token hashing cost (tests lower it). Logging goes
    through the redacting root handler, shared with any other live container (whose
    stream then wins over `log_stream`); `logger_names` lists non-propagating loggers (a
    server's own) that must use it too. `close()` releases it. Raises only for a fault
    that leaves nothing usable (a database that cannot be opened, a schema version
    mismatch, a manifest failing its integrity check), after releasing everything opened
    so far.
    """
    clock = clock or SystemClock()
    redactor = SecretRedactor()
    metrics = MetricsRegistry(max_series_per_metric=settings.safety.metrics_max_series_per_metric)
    logs = acquire_logging(
        redactor, log_level, stream=log_stream, metrics=metrics, logger_names=logger_names
    )
    lifecycle = _Lifecycle(logs)
    try:
        return _assemble(settings, environ, clock, scrypt, redactor, metrics, lifecycle)
    except BaseException:
        lifecycle.close()
        raise


def _assemble(
    settings: Settings,
    environ: Mapping[str, str] | None,
    clock: Clock,
    scrypt: ScryptParams,
    redactor: SecretRedactor,
    metrics: MetricsRegistry,
    lifecycle: _Lifecycle,
) -> Container:
    store = EnvSecretStore(environ, redactor=redactor)
    unusable = unusable_refs(settings, store)
    audit_db_existed = settings.audit_db.is_file()
    operational = create_db_engine(settings.operational_db)
    lifecycle.engines = (operational,)
    audit_engine = create_db_engine(settings.audit_db)
    lifecycle.engines = (operational, audit_engine)
    init_operational_schema(operational)
    init_audit_schema(audit_engine)

    witness = build_witness(settings, store)
    audit, anchor, audit_problems = open_audit(
        audit_engine=audit_engine,
        operational=operational,
        audit_db=settings.audit_db,
        anchor_path=settings.audit_anchor,
        key_ref=settings.audit_hmac_key_ref,
        resolver=store,
        key_usable="audit_hmac_key_ref" not in unusable,
        audit_db_existed=audit_db_existed,
        redactor=redactor,
        clock=clock,
        witness=witness,
        witness_every=settings.safety.audit_witness_every,
    )
    identity = IdentityService(operational, clock, audit, settings.classification)
    killswitch = KillSwitch(
        engine=operational,
        audit=audit,
        clock=clock,
        principals=identity,
        secrets=store,
        key_ref=settings.killswitch_key_ref,
        history=AuditKillSwitchHistory(audit),
        claim_timeout=_seconds(settings.safety.killswitch_claim_timeout_seconds),
    )
    health = HealthRegistry(
        clock,
        check_timeout_seconds=settings.safety.health_check_timeout_seconds,
        redactor=redactor,
    )
    gate = run_startup(
        operational=operational, audit=audit, killswitch=killswitch, health=health, clock=clock
    )
    warnings = startup_warnings(settings)
    missing = tuple(
        dict.fromkeys(
            (*settings.missing_for_writes(), *unusable.values(), *audit_problems, *gate.problems)
        )
    )
    catalog = OperationCatalog(())
    authenticator = Authenticator(
        operational,
        clock,
        audit,
        identity,
        max_token_ttl=_seconds(settings.safety.max_token_ttl_seconds),
        scrypt=scrypt,
    )
    inference = InferenceGateway(
        StubLocalProvider(),
        redactor,
        audit,
        clock,
        operational,
        load_manifest(),
        timeout_seconds=settings.safety.inference_timeout_seconds,
        max_abandoned_calls=settings.safety.inference_max_abandoned_calls,
    )
    metrics.declare_gauge(AUTH_AUDIT_GAUGE)
    register_health(
        health,
        operational=operational,
        audit_engine=audit_engine,
        anchor=anchor,
        killswitch=killswitch,
        authenticator=authenticator,
        inference=inference,
        max_abandoned_calls=settings.safety.inference_max_abandoned_calls,
        handler=lifecycle.logs.handler,
        metrics=metrics,
        missing=missing,
        warnings=warnings,
        audit_problems=audit_problems,
    )
    if missing:
        logger.warning("start-up: degraded, missing: %s", ", ".join(missing))
    return Container(
        settings=settings,
        clock=clock,
        redactor=redactor,
        secret_store=store,
        operational_engine=operational,
        audit_engine=audit_engine,
        anchor=anchor,
        witness=witness,
        audit=audit,
        killswitch=killswitch,
        killswitch_reader=gate.reader,
        startup_report=gate.report,
        integrity=gate.integrity,
        identity=identity,
        authenticator=authenticator,
        host_local=HostLocalAdmin(operational, clock, audit, authenticator.minter),
        catalog=catalog,
        policy=PolicyEngine(
            catalog=catalog,
            ruleset=load_default_ruleset(),
            clock=clock,
            audit=audit,
            principals=identity,
            max_envelope_ttl=_seconds(settings.safety.max_envelope_ttl_seconds),
        ),
        policy_context=DefaultPolicyContext(),
        queue=_queue(settings, operational, clock, audit, identity, metrics),
        inference=inference,
        metrics=metrics,
        health=health,
        missing=missing,
        warnings=warnings,
        _lifecycle=lifecycle,
    )


def _queue(
    settings: Settings,
    engine: Engine,
    clock: Clock,
    audit: AuditService,
    identity: IdentityService,
    metrics: MetricsRegistry,
) -> JobQueue:
    safety = settings.safety

    def on_dead_letter(kind: str, reason: str) -> None:
        # The reason is free text: it stays in the queue's log line, never in a label.
        metrics.inc(MetricNames.QUEUE_DEAD_LETTERS, labels={"kind": kind})

    return JobQueue(
        engine,
        clock,
        audit,
        identity,
        lease_seconds=safety.queue_lease_seconds,
        max_attempts=safety.queue_max_attempts,
        backoff_base_seconds=safety.queue_backoff_base_seconds,
        backoff_max_seconds=safety.queue_backoff_max_seconds,
        on_dead_letter=on_dead_letter,
    )
