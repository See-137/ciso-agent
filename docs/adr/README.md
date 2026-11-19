# Architecture decision records

These records exist because the v1.0 blueprint (BP; not included in this repository) says in Appendix C: "Do not silently resolve deferred decisions. When a choice is required, propose an ADR with options, trade-offs, security impact and evidence needed; select a reversible default only when implementation cannot proceed otherwise."

Rules for this directory:

- Every ADR here is **Proposed (reversible default; owner approval pending)**. None is final until the owner approves it (BP §3 change control).
- A default is a way to keep building. It is not a recommendation for production.
- No ADR names or assumes a company-specific vendor, cloud provider, identity provider, MDM/EDR product, ticketing tool or model.
- No ADR sets a latency, throughput, retention or sizing number as a decision (BP §15.1). ADR-0019 quotes the provisional values in `config/provisional-settings.json` and marks every one as a placeholder.
- Numbering: the BP's own register in §3 uses three-digit ids (ADR-001 to ADR-019) for planning-stage decisions. The records here are four-digit (ADR-0001 onward) and are a different series. A reference such as "BP §3 register item Hardware" always means the BP register.

## Index

| Id | Title | Status | Related BP open decision |
|---|---|---|---|
| [ADR-0001](0001-implementation-language-and-typing.md) | Implementation language and typing | Proposed (reversible default; owner approval pending) | None in §20. BP §3 register item "Technology stack" (DEFERRED) |
| [ADR-0002](0002-operational-and-audit-storage.md) | Operational and audit storage | Proposed (reversible default; owner approval pending) | None in §20 directly; OD-17 sets volume. BP §3 "Technology stack" |
| [ADR-0003](0003-evidence-storage.md) | Evidence storage | Proposed (reversible default; owner approval pending) | OD-09, OD-17 |
| [ADR-0004](0004-identity-bootstrap-model.md) | Identity (bootstrap model; OIDC/SSO adapter as an interface) | Proposed (reversible default; owner approval pending) | OD-03 |
| [ADR-0005](0005-local-inference-runtime.md) | Local inference runtime (provider interface plus a deterministic stub) | Proposed (reversible default; owner approval pending) | OD-01, OD-02 |
| [ADR-0006](0006-external-inference-gateway.md) | External inference (separate package, disabled, per-request approval) | Proposed (reversible default; owner approval pending) | OD-14 |
| [ADR-0007](0007-queue-and-workflow-layer.md) | Queue and workflow layer (database-backed durable job queue) | Proposed (reversible default; owner approval pending) | None in §20. BP §3 "Technology stack" |
| [ADR-0008](0008-secrets-interface.md) | Secrets (SecretStore interface, secret references, environment provider for development) | Proposed (reversible default; owner approval pending) | None in §20. BP §3 "Technology stack" |
| [ADR-0009](0009-policy-engine.md) | Policy engine (in-process, deterministic, versioned declarative rules) | Proposed (reversible default; owner approval pending) | OD-15 |
| [ADR-0010](0010-execution-boundary.md) | Execution boundary (broker as its own package; process split before any real write adapter) | Proposed (reversible default; owner approval pending) | OD-13, OD-15 |
| [ADR-0011](0011-connector-framework.md) | Connector framework (read-connector protocol; write adapters separate; fixture connector only) | Proposed (reversible default; owner approval pending) | OD-03 to OD-08, OD-13 |
| [ADR-0012](0012-api-and-console.md) | API and console (FastAPI on loopback; no console in this build) | Proposed (reversible default; owner approval pending) | OD-12 |
| [ADR-0013](0013-audit-integrity.md) | Audit integrity (hash-chained append-only log with a keyed, two-phase head anchor and an optional head witness) | Proposed (reversible default; owner approval pending) | OD-17 |
| [ADR-0014](0014-backup-and-recovery.md) | Backup and recovery (online backup into an encrypted archive, plus a restore test) | Proposed (reversible default; owner approval pending) | OD-16, OD-17 |
| [ADR-0015](0015-deployment-host-and-network.md) | Deployment, host and network | Proposed (reversible default; owner approval pending). Decision state: OPEN, no default beyond the loopback bind | OD-01, OD-16 |
| [ADR-0016](0016-separation-of-duties-for-approvals.md) | Separation of duties for approvals (self-approval forbidden by default) | Proposed (reversible default; owner approval pending). Explicit question for the owner | None in §20. BP §9.3 leaves it open; touches OD-10, OD-14 |
| [ADR-0017](0017-provisional-classification-labels.md) | Provisional classification labels (no built-in scheme; `unknown` outranks every label) | Proposed (reversible default; owner approval pending) | OD-09; touches OD-14 |
| [ADR-0018](0018-kill-switch-semantics.md) | Kill-switch semantics | Proposed (reversible default; owner approval pending) | None in §20. BP §11.2; touches OD-01, OD-15 |
| [ADR-0019](0019-provisional-safety-parameters.md) | Provisional safety parameters (unset means refuse; values only from a named file) | Proposed (reversible default; owner approval pending) | None in §20 as a whole. BP §15.1; individual knobs depend on OD-02, OD-03, OD-04, OD-13, OD-15 |
| [ADR-0020](0020-observability.md) | Observability (structured logging, in-process metrics, health aggregate; no exporter chosen) | Proposed (reversible default; owner approval pending) | None in §20. BP §3 "Technology stack"; touches OD-01, OD-17 |
| [ADR-0021](0021-approval-routing-and-risk-classes.md) | Approval routing and risk class labels (who may approve and who may request; labels carry no scale) | Proposed (reversible default; owner approval pending) | None in §20 as a whole. BP §9.3 names no approver for most approvals; touches OD-11 (labels only), OD-14, OD-15 |

See [open-decisions.md](open-decisions.md) for all of OD-01 to OD-18 and what the build does while each is open.

## Coverage of the ADRs the BP asks for

| BP request | Covered by |
|---|---|
| §19.4 #1: deployment | ADR-0015 |
| §19.4 #1: identity | ADR-0004 |
| §19.4 #1: local inference runtime | ADR-0005 |
| §19.4 #1: storage | ADR-0002, ADR-0003 |
| §19.4 #1: connector framework | ADR-0011 |
| §19.4 #1: execution boundary | ADR-0010 |
| Appendix C #14: language/framework | ADR-0001, ADR-0012 |
| Appendix C #14: database/evidence storage | ADR-0002, ADR-0003 |
| Appendix C #14: identity provider integration | ADR-0004 |
| Appendix C #14: local model runtime | ADR-0005 |
| Appendix C #14: queue/workflow | ADR-0007 |
| Appendix C #14: secret manager | ADR-0008 |
| Appendix C #14: backup approach | ADR-0014 |
| Appendix C #14: host/network setup | ADR-0015 |

ADR-0006 (external inference), ADR-0009 (policy engine), ADR-0013 (audit integrity) and ADR-0016 to ADR-0021 are not on either BP list. They are recorded because each contains a choice the build had to make. ADR-0016 to ADR-0020 document decisions listed in `docs/plan/decisions.md` (plan gaps G33, G7, G20, G14, G18). ADR-0021 records the approval routing and risk class labels that `docs/plan/followups.md` (F9, F10) and plan gap G25 required.

## Open decisions with no ADR yet

OD-10 (legal/compliance), OD-11 (risk methodology) and OD-18 (compliance mapping) have no ADR of their own because the build makes no choice for them: there is no compliance mapping and no risk-score formula. ADR-0021 records the provisional risk class labels, which carry no scale and decide nothing about OD-11. BP §19.1 requires a documented ADR and evidence before a risk-score formula or compliance target is selected.

## Template

```
# ADR-NNNN: <title>
Status: Proposed (reversible default; owner approval pending)
Date: YYYY-MM-DD
Blueprint refs: <sections / FR / NFR / OD ids>

## Context
## Options considered   (table: option | gains | costs | security impact)
## Default chosen for the local build
## Why this default is reversible   (what would have to change to switch, and where the seam is in the code)
## Evidence needed to make this final
## Consequences
```

## How an ADR leaves "Proposed"

1. The evidence listed in its "Evidence needed" section is collected, mostly through Phase 0 (`docs/phase0/`).
2. The ADR is updated with that evidence and the option it supports.
3. The owner approves or rejects it. Only then does the status line change.
4. If the approved option differs from the default, the switch described under "Why this default is reversible" becomes a planned task.
