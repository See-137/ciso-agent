# ADR-0005: Local inference runtime (provider interface plus a deterministic stub)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (deadline, provider and model checks)
Blueprint refs: §3 (register items "Own LLM inference", AGREED DIRECTION, and "Hardware", DEFERRED), §5.1 #4, §8.3, §10.4, §15.1, §19.4 #5, FR-016, FR-017, NFR-002, NFR-011, NFR-017, OD-01, OD-02, Appendix C #14 and #16

## Context
Local inference is the default path for the CISO's own reasoning (§8.3, FR-016). The BP does not select a model family, quantization, serving runtime, embeddings or reranker, or hardware (OD-02, OD-01) and says: "Do not order a GPU server or assume a specific local model" (§10.4). It also requires an inference abstraction "so the local model/runtime can change without changing policy, connectors, registry or business logic" (§10.4), and a stub runtime so the rest of the platform can be built without a GPU (§19.4 #5). Event processing, policy authorization and connector synchronization must keep working when inference is unavailable, and inference failure must never route externally (§10.4, NFR-017).

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Provider interface plus a deterministic stub; no model, runtime or hardware chosen | Whole platform testable with no GPU; tests are repeatable; nothing is assumed about OD-01 or OD-02 | Says nothing about real model quality, speed or context needs; the interface shape is unproven until a real runtime is attached | No model artifacts to protect yet; the "no fallback" and "output is untrusted" rules can be tested exactly |
| Select a runtime and a model now | Early feedback on real behaviour | Decides OD-02 without the workload definition and benchmark the BP requires; may drive a premature hardware purchase (BP §17.3) | Brings model supply-chain controls (§8.3) into scope before there is a process for them |
| Bind a model library in-process | Fewest moving parts | Model code shares memory with the orchestrator; BP §5.2 asks for model serving to be a separate boundary | Weakest isolation of the model runtime |
| Local model server process on a private interface | Matches the BP's serving boundary (§5.1 #4, §5.2) | A second process to run and secure; still requires choosing a runtime | Good isolation if the endpoint is private and reached only through the gateway |

A model hosted outside company-controlled office infrastructure is not a "local" option (NFR-002); it belongs to ADR-0006.

## Default chosen for the local build
`InferenceGateway.complete(request) -> InferenceResult` routes to the configured local provider only. The only provider shipped is `StubLocalProvider`, which is deterministic. A failure raises `InferenceUnavailable`; the gateway has no alternate route. Output is wrapped as `UntrustedModelOutput` and must pass schema validation before it can become a proposal. Each call is logged with model, task category, context references and timing; prompt bodies are not logged.

Checks the gateway makes (`ciso.inference`): the provider must be an instance of a registered class derived from `LocalProvider` on an in-process or loopback endpoint, so an object that only looks like a provider is refused. The model's artifact hash must match the pinned manifest entry when the gateway is built, and the model identity is read once. The gateway measures time itself and runs the provider on a worker thread with a deadline (`inference_timeout_seconds`, ADR-0019); a late answer is never returned. A thread cannot be killed, so a call that missed its deadline runs on, and the gateway refuses new work while too many such calls (`inference_max_abandoned_calls`) are outstanding. The audit log is called before and after the provider, never while the operational write lock is held, and no exception carries a prompt or an output body.

Weaknesses of this default:
- The stub proves the plumbing (validation, logging, failure handling, no fallback). It proves nothing about how a real model behaves under prompt injection, so adversarial tests against it are plumbing tests.
- The interface has not been exercised for streaming, token accounting, constrained or structured decoding, embeddings, reranking, concurrency limits or request queueing. Some of these may force an interface change.
- No sizing input is produced by this build.

## Why this default is reversible
Seam: the provider protocol behind `InferenceGateway` in `ciso.inference`. Only the composition root imports a provider, and `ciso.inference` may not import `ciso.execution` or `ciso.connectors`. To switch: add a provider that talks to the chosen runtime, register its network client in the import allowlist if it uses one, and select it in configuration. Policy, registry, connectors and execution do not change.

## Evidence needed to make this final
- The sizing inputs listed in BP §10.4: expected event volume, concurrent conversations, investigation concurrency, maximum input context, code-analysis workload, retention and search needs, latency targets, available GPU/CPU/RAM/storage, and whether embeddings or reranking are needed.
- A benchmark of candidate models on representative redacted tasks (BP §15.1). Candidates are named in that benchmark, not here.
- The approved host (OD-01).
- An approved source, versioning and integrity check for model artifacts (BP §8.3).

## Consequences
- Development of registry, policy, connectors and execution is not blocked by hardware.
- AI reasoning jobs queue or degrade to deterministic checks when inference is unavailable.
- No statement about the platform's reasoning quality can be made from this build.
