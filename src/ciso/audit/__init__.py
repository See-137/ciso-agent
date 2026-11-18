"""Tamper-evident audit log. Read `ciso.audit.log` for the ordering rule callers must follow:
audit the attempt before the side effect; an audit failure stops the operation (G5)."""

from ciso.audit.anchor import AnchorEntry, AnchorReading, AnchorState, HeadAnchor
from ciso.audit.chain import AuditRecord, record_hash
from ciso.audit.log import AUDIT_ACTOR_ID, RECOVERY_ACTION, AuditLog
from ciso.audit.reconcile import RecoveryCase, VerifyStatus
from ciso.audit.tables import (
    GENESIS_HASH,
    audit_meta,
    audit_metadata,
    audit_record,
    init_audit_schema,
)
from ciso.audit.verify import VerifyResult
from ciso.audit.witness import FileHeadWitness, HeadWitness, WitnessedHead

__all__ = [
    "AUDIT_ACTOR_ID",
    "GENESIS_HASH",
    "RECOVERY_ACTION",
    "AnchorEntry",
    "AnchorReading",
    "AnchorState",
    "AuditLog",
    "AuditRecord",
    "FileHeadWitness",
    "HeadAnchor",
    "HeadWitness",
    "RecoveryCase",
    "VerifyResult",
    "VerifyStatus",
    "WitnessedHead",
    "audit_meta",
    "audit_metadata",
    "audit_record",
    "init_audit_schema",
    "record_hash",
]
