# ADR-0011: Connector framework (read-connector protocol; write adapters separate; fixture connector only)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Blueprint refs: §5.1 #6, §6.1, §7.2, §10.2, §13.1, §13.2, §13.4, §16.2 DF-12, §19.1, §19.3 (connector integration tests), §19.4 #1 and #7, FR-004, FR-006, FR-029, FR-031, NFR-011, OD-03 to OD-08, OD-13, Appendix C #18; plan gaps G9, G10, G15, G16, G23

## Context
Connectors read data from cloud, IAM, SaaS, repositories, AI providers, existing endpoint tools and infrastructure APIs with least privilege, separate read and write credentials, and health and freshness monitoring (§5.1 #6). §13.1 defines the connector semantics and states that `execute_action` is "not available in read connectors. Write-capable adapters are separate, policy-gated and allowlisted." §19.1 adds that a read connector "must not contain dormant, undocumented write capability". §13.4 says no connector may silently expand its account, project or domain scope. The source systems are unknown (DF-12; OD-03 to OD-08, OD-13). The first real connector is to be built "after Phase 0 chooses the first source" (§19.4 #7).

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| In-process read-connector protocol per BP §13.1; write adapters as a separate contract with no implementation; a fixture connector that reads local files | Contract, health, checkpointing and ingestion can be built and tested with no vendor assumption | The contract is unproven against any real API; connectors share a process with the rest of the platform | No real credentials exist. Read-only is enforced by structure (no write method, separate package for writes); the real guarantee later is the read-only scope of the credential at the source |
| Out-of-process connectors behind a local, language-neutral contract | Connector isolation (BP §11); a faulty or compromised connector cannot read other modules' memory | IPC, supervision and a serialised contract to build before any real connector exists | Stronger containment of the component that parses untrusted source data |
| Adopt an existing integration framework | Possibly many sources ready-made | Fit to the BP's provenance, health and scope semantics is unknown; choosing it assumes which sources matter | Third-party code holding source credentials; supply-chain review needed |
| One generic HTTP connector driven by configuration | Little code per source | Blurs scope; close to the "unrestricted HTTP" interface the BP prohibits for agent use (§9.5) | Rejected |
| Build a real connector now for a guessed source | Early proof of the contract | Assumes a vendor the BP says not to assume | Rejected |

## Default chosen for the local build
The connector package is planned (tasks T3.6 to T3.8) and was not yet in `src` when this was written.
- A read-connector protocol with the BP §13.1 operations: `discover_sources`, `health_check`, `list_assets`, `get_asset`, `list_changes`, `list_findings`, `get_configuration`, `map_identity`, `checkpoint`. `subscribe_events` is in the contract as an interface only; there is no webhook route, because no source exists (G15).
- Health carries auth validity, quota, permission gaps, last success and degraded state. A connector failure is recorded as a coverage gap, never as a clean result (BP §7.2).
- Events use the envelope in BP §13.2. An envelope is rejected when `signature_valid` or `replay_checked` is false, when a timestamp is not UTC, or when it is outside the accepted clock skew (ADR-0019). Dedupe is on `(source_system, event_id)` (ADR-0007).
- Each connector registers its approved scope, and every record carries a `scope_ref`. A record outside the registered scope is rejected, audited and shown as a health flag (G9).
- A connector manifest declares purpose, field scope and a retention reference (G23).
- Pipeline order: store the payload as evidence, build the envelope with its `payload_ref`, enqueue, then ingest into the registry with the `evidence_ref` (G10).
- Write adapters are a separate contract in `ciso.write_adapters` with zero implementations; `ciso.connectors` never imports it. A test fails if a read connector exposes an execute or write method.
- The only connector is a fixture connector that reads local JSON files. A scriptable fault-injection fake in the test tree simulates auth expiry, quota, server errors, stale cursors, duplicates and permission gaps (G16).

Weaknesses of this default:
- The fault fake simulates failure modes. It does not show how a real API paginates, throttles or reports partial permissions, so the contract is still unproven.
- Push delivery is undecided. Webhook intake needs an authenticated inbound endpoint with signature verification (BP §10.2), which depends on ADR-0015.
- `signature_valid` and `replay_checked` are fields of the envelope, filled in by whichever component builds it. The pipeline rejects a false value; it cannot tell whether a true value was really checked.
- The method-name test is a tripwire. It does not prove a connector is read-only.
- In-process connectors do not give the "connector isolation" BP §11 lists as a safeguard.

## Why this default is reversible
Seam: the read-connector protocol in `ciso.connectors`. Connectors receive credentials only as secret references (ADR-0008) and emit normalized records and event envelopes; ingestion does not know which connector produced them. To move a connector out of process, write an adapter that implements the protocol by calling the external process. To change the protocol after the first real source, version it; the fixture connector and the fault fake are the only implementations to update.

## Evidence needed to make this final
- The filled Phase 0 source-system matrix: API availability, read/write capabilities, required scopes, sync method, rate limits, data sensitivity, known gaps.
- The choice of the first low-risk read-only source (BP §19.4 #7).
- Whether any high-value source offers only push delivery or only file export.
- Answers to OD-03 to OD-08 and OD-13.

## Consequences
- No connector to any real system exists in this build.
- The first real connector is expected to change the protocol; that is the point of building it against a low-risk source.
- Connector isolation should be decided together with the process split in ADR-0010.
