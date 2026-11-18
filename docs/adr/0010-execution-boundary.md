# ADR-0010: Execution boundary (broker as its own package; process split before any real write adapter)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Blueprint refs: §5.1 #12, §5.2, §9.4, §9.5, §11 (over-privileged tools row), §11.2, §18 Phase 5, §19.1, §19.3 (execution broker tests), §19.4 #1 and #6, FR-025, FR-026, NFR-016, NFR-017, OD-13, OD-15, Appendix D; plan gaps G3, G5, G12, G13, G29

## Context
The execution broker invokes allowlisted tools and playbooks and enforces preconditions, rate limits, idempotency, expiry and verification; no arbitrary shell or unrestricted admin API is exposed to the model (§5.1 #12). §5.2 recommends separately isolated processes or services for the user/API layer, the orchestrator, model serving, connectors/discovery and the execution broker, and adds: "Separate the execution broker and model-serving boundary from the orchestration process even if the initial deployment uses a small number of containers or processes." This is marked as an implementation recommendation, not a stack decision. The kill switch must be able to "revoke or suspend execution-broker credentials" (§11.2).

The default below runs one process during development. That is weaker than the §5.2 recommendation and is recorded here so it is not a silent choice. The Appendix D item "office-hosted deployment runs with private service boundaries" is not met by a local build and is stated as not achievable locally (`docs/plan/decisions.md`, G29).

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Broker as its own package with import-boundary tests; one process in development; split into a separate OS process and identity before any real write adapter exists | Simple to run and test now; the interface is shaped for a later split | The boundary is a convention plus a test until the split happens | In one process, memory is shared. Only tests and review stop orchestrator code from reaching a tool object directly. Tolerable only because no tool in this build can change a real system |
| Separate OS process and identity now | The §5.2 boundary is real from the start; the broker alone holds write credentials | Process supervision, local IPC and its authentication to build before any write target is known | A compromised orchestrator cannot call tools except through the broker's checks |
| Separate host or container now | Strongest isolation | Assumes host and packaging decisions that are open (ADR-0015) | Adds network exposure between hosts that must be authenticated (BP §10.2) |
| No boundary: tools called from the orchestrator | Least code | Contradicts BP §9 and §9.5 | Rejected |

## Default chosen for the local build
The packages below are planned (tasks T2.1 to T2.5) and were not yet in `src` when this was written. `ciso.policy` exists and never imports inference, orchestration, the API or execution.
- `ciso.execution` holds the broker, the tool registry and the channel registry. The broker refuses on: kill switch engaged or unreadable, invalid envelope, policy unavailable or not allowing, missing or mismatched approval, expired envelope, stale precondition, rate limit, or a failed audit write for the attempt. A test asserts the order of these gates. A duplicate idempotency key returns the earlier result without running again.
- Approvals are not in `ciso.execution`. They live in a standalone `ciso.approvals` module that the broker and the external inference path both use (G3). An approval binds the hash of what is approved, the approver role, scope and expiry, and is single-use. Its validity is computed when it is checked: an approver who has lost the role since approving no longer counts (G12).
- Ordering rule (G5): the attempt is audited before the side effect. An execution has an explicit state: `pending`, `executed_unverified`, `verified`, `verification_failed`, `unknown_outcome`, `rolled_back`. At start-up, an execution that was in flight becomes `unknown_outcome` and must be verified before any retry.
- Results are verified independently of the tool's reply.
- An L2 notification or ticket goes only to a channel that a `security_admin` approved (G13). Tools shipped write drafts to local outboxes.
- Write credentials are obtained through an accessor that checks the kill switch (ADR-0018).
- Write adapters are a separate contract in `ciso.write_adapters` with no implementation; `ciso.connectors` never imports it.
- The orchestrator holds no credentials and no tool handles.

Hard rule attached to this default: no write adapter to a real system may be added while the broker shares a process with the orchestrator.

Weaknesses of this default:
- Import tests see static imports. Dynamic import or reflection inside the same process is not caught.
- There are no real broker credentials, so suspending them (§11.2) is exercised with fakes only.
- A crash in the orchestrator stops the broker too.
- `unknown_outcome` needs a person or a verification routine to resolve it. Until then the action is neither done nor not done.
- Which roles may approve an L4 action is set in the default policy ruleset, not by the BP. It is a company decision that has not been made (ADR-0016, Phase 0 approval routing table).

## Why this default is reversible
Seam: the broker's execute call. Its input is the serialisable action envelope (BP §9.4) and its output is a serialisable result. To split: run the broker under its own OS identity with its own secret references (ADR-0008) and database credentials (ADR-0002), put an authenticated local transport in front of the same call, and replace the in-process call in the orchestrator with a client. Callers and the envelope do not change.

## Evidence needed to make this final
- The approved host, its operating system and its process-isolation facilities (OD-01, ADR-0015).
- The first write target and its credential model: ticketing and workflow tool (OD-13) or the first L3 playbook (OD-15).
- How the chosen secret store separates identities (ADR-0008).
- A threat model of the orchestrator-to-broker path, including a compromised orchestrator.

## Consequences
- The Phase 5 gate ("every write is authorized outside the LLM") can be met at the code level for the local outbox tools only.
- The process split is a prerequisite task for Phase 5 work on real channels, and should be scheduled before OD-13 is implemented.
- The same split pattern applies to model serving (§5.2) when a real runtime is chosen (ADR-0005).
