# ADR-0006: External inference (separate package, disabled, per-request approval)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (status of the build; approver role rule)
Blueprint refs: §2.3, §3 (register item "External LLM", AGREED), §5.1 #5, §8.4, §11 (unauthorized external inference row), §16.2 DF-04, §19.3 (external inference tests), FR-017, FR-018, NFR-003, NFR-017, OD-14, Appendix C #17; plan gaps G1, G2, G3, G26

## Context
External model use is "an explicit, per-request human choice; it is not a fallback, automatic escalation, load-balancing target or preconfigured alternate route" (§1). The initial state is disabled (§8.4). §8.4 defines seven steps: propose, preview, minimize, authorize, transmit, record, reintegrate. Step 4 requires that a designated human approves "this specific request, provider/model, purpose and payload". The hard requirement is that no external provider request is sent without that approval. The approving role, supported providers, allowed data classes, per-request UX and retention terms are unknown (OD-14, to be resolved before enabling the external adapter).

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Separate package that the orchestrator cannot import; disabled by default; single-use approval bound to the specific request; no transport implementation shipped | The control design exists and is tested before anyone needs it; the normal gateway has no code path to it | Code that cannot be used yet; the transmit step is tested only against a fake | No bytes can leave: there is nothing to send them with. An approval cannot be reused or moved to another payload, provider, model or purpose |
| Do not build the external path at all | Simplest; nothing to misuse | The approval and audit design stays untested and may be added later in a hurry | Safest today; risk moves to the day it is added |
| One gateway with a provider setting that includes external providers | Less code | External use becomes one configuration value away from normal routing | Contradicts BP §8.4 ("not part of normal routing"); rejected |
| Standing approval per provider or per data class | Less friction for approvers | Contradicts BP §8.4 step 4 ("Approval is not blanket permission") | Rejected |
| Ship a transport for one named provider | End-to-end test possible | Assumes the answer to OD-14 | Adds a working egress path before the approving role exists; rejected |

## Default chosen for the local build
Nothing on this path is built. `ciso.inference.external`, `ciso.approvals` and the external-inference API router do not exist in `src`. What exists is the settings block, the absence of any route to an external provider in the local gateway, and architecture checks. The rest of this section is the planned gate (plan tasks T2.1, T2.6 to T2.9; plan gaps G1, G2, G3, G26), written so that it can be checked when it is built.

- The external path lives in its own package, `ciso.inference.external`. Only the external-inference API router and the composition root may import it; an architecture test enforces this (G1). The local `InferenceGateway` holds exactly one provider and has no reference to it.
- Steps follow BP §8.4: propose, preview, minimize, authorize, transmit, record, reintegrate. The preview is the exact bytes that are later hashed.
- An approval comes from the standalone `ciso.approvals` module (G3). It is bound to the payload hash together with provider, model, purpose and request id, it is single-use and it is consumed on transmit (G2).
- Settings (`ExternalInferenceSettings`): `enabled` is false, `approver_role` is unset and `allowed_classifications` is empty. The path is usable only when all three have been set explicitly. The settings accept `security_admin`, `system_owner` or `executive_risk_owner` as the approver role and refuse `auditor` and every non-human role. Allowed classifications must be labels of the configured scheme (ADR-0017). Nothing defaults the approver to `security_admin` (G26).
- `transmit` refuses when the feature is off, the kill switch blocks external inference, the approval does not match, the approval is expired or already used, the approving role is unset, or no transport is present.
- The transport is an interface. The number of implementations in `src` is zero.
- Returned text is wrapped as untrusted model output; any proposed action goes through the normal policy engine.

What exists today, and what each piece shows:
- `ExternalInferenceSettings` (`src/ciso/app/settings.py`): `enabled` false, `approver_role` unset, `allowed_classifications` empty. `usable` is true only when all three are set. `config/provisional-settings.json` leaves them off.
- The composition root wires no external service. The container has no attribute, method or field that names one, and a test checks that.
- The local `InferenceGateway` holds exactly one registered provider on an in-process or loopback endpoint, has no fallback code path, and raises `InferenceUnavailable` on a timeout, an error or an empty answer. It never triggers an external call.
- `KillCapability.EXTERNAL_INFERENCE` exists, so the kill switch can already block the path when it is built. Verification of the audit log that is not `ok` also blocks that capability (`ciso.ops.integrity`, not yet wired into the composition root).
- An architecture test checks that no module imports a network client library, and another that only the human path may import `ciso.inference.external`. With the package absent, the second has nothing to check yet.

Weaknesses of this default:
- This build cannot enforce a network egress allowlist (BP §10.2, NFR-003). That depends on the host and network (ADR-0015). In code, egress is limited by a test that allows network client libraries only in an allowlist of modules; a library missing from the test's list, or a subprocess, would not be caught by that test alone.
- The settings accept `security_admin` as approver, although `security_admin` is not an approver anywhere else in the build (ADR-0021: the approver roles are `system_owner` and `executive_risk_owner`). The two rules disagree until the owner answers OD-14. The read-only `auditor` is refused.
- Minimization and secret redaction are pattern-based and can miss content.
- The binding guarantees the approved bytes are the sent bytes. It does not guarantee that the approver read them.
- If a human, not the agent, proposes the request, the self-approval rule of the shared approvals module would apply (ADR-0016), so a one-person company could not approve it. Whether that is intended for this path is a question in ADR-0016.

## Why this default is reversible
Seam: the transport interface and the settings in `ExternalInferenceSettings`. To enable: implement one transport in an allowlisted module, set the approving role and allowed classifications, then turn the flag on. To disable again: turn the flag off or engage the kill switch. To remove: delete the package; nothing in the local gateway or the orchestrator references it.

## Evidence needed to make this final
- OD-14 answered: approving role, supported providers, allowed data classes, the per-request approval UX, retention terms.
- Provider contract and data-retention terms reviewed by the legal or privacy owner (OD-10).
- A network egress control on the approved host that allows only the gateway to reach approved destinations (ADR-0015).
- The external-inference test class from BP §19.3 passing against a real transport in a test environment: disabled default, no fallback on timeout, complexity or low confidence, exact payload preview, approval binding, egress restrictions, audit completeness.

## Consequences
- External inference cannot happen in this build, by construction.
- The approval ledger fields required by BP §8.4 step 6 exist before the first real request.
- Enabling the path is a deliberate change with its own review, not a setting someone flips alone.
