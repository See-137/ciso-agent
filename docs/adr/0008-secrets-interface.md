# ADR-0008: Secrets (SecretStore interface, secret references, environment provider for development)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (package name, keys in use, key length)
Blueprint refs: §5.1 #15, §9.5, §11 (credential theft row), §11.1, §13.4, §18 Phase 1 exit gate, §19.4 #4, NFR-007, NFR-016, Appendix C #14

## Context
The BP requires secrets and key management for connector credentials, signing keys, local model secrets and service identities, with "no secrets in prompts, memory, source code, logs or ordinary database fields" (§5.1 #15). §11 asks for an "external secrets manager or protected secret store", short-lived scoped credentials, rotation and secret scanning of model inputs and outputs. §11.1 says the registry and LLM memory store secret references and metadata only. A protected secrets interface must exist before any write-capable tool (§19.4 #4). No secret-manager product is chosen and none is assumed.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| `SecretStore` interface; references of the form `secret://name`; development provider reads process environment variables | No product needed; no secret is written to disk by the repository; every consumer is already coded against references | No rotation, no short-lived credentials, no per-component separation, no provider-side access log | Environment variables are readable by the process and may be inherited by child processes or appear in diagnostic dumps. Adequate for development only |
| Encrypted file store unlocked by a passphrase | Works offline; secrets survive restart without re-entry of each value | The passphrase must come from somewhere at start; rotation is manual | Moves the problem to protecting one passphrase |
| Operating-system credential store | Uses protection the host already provides | Ties the platform to one host OS, which is OD-01; awkward for service accounts | Reasonable for a single host; depends on host hardening |
| A dedicated secret manager service (product not chosen) | Rotation, short-lived credentials, access policy and audit per identity | A service to run and secure, or a dependency on a provider; assumes OD-01 and the company's existing tooling | Best match for BP §11; also a high-value target itself |
| Hardware-backed key storage | Keys cannot be copied off the device | Hardware and integration work; hardware is undecided (OD-01) | Strongest for the few keys that matter most (evidence key, audit anchoring key) |

## Default chosen for the local build
`SecretStore.get(ref) -> SecretValue`, where `ref` is `secret://<name>` (lower-case letters, digits and underscores). The package is `ciso.vault`, not `ciso.secrets`, so it does not shadow the standard library module and avoids a directory name the owner's tooling protects. `SecretValue` hides its content in `repr` and `str`, cannot be serialised or pickled, compares only against another `SecretValue` in constant time, and can carry an expiry after which `reveal()` fails closed. The development provider (`EnvSecretStore`) reads `CISO_SECRET_<NAME>` from the process environment, or from a mapping given to it. Configuration, registry rows and policy files hold references only. A `Redactor` (`SecretRedactor`) scrubs known secret values and common token shapes from audit details, log records and inference input. Every value the environment provider resolves is registered with the redactor at that moment, so it is scrubbed from later log lines and audit details. The platform uses five references, all set in settings by reference only: `audit_hmac_key_ref` (audit anchor), `audit_witness_key_ref` (audit witness, a different secret), `killswitch_key_ref` (kill-switch row MACs), `backup_key_ref` (archive encryption) and `evidence_key_ref` (reserved; no evidence module yet). Settings refuse a value that is not a `secret://` reference. A reference that does not resolve at start-up is listed in readiness, and the component that needs it refuses.

Key length: today the code refuses an empty key and nothing more, so a key of one character is accepted. A minimum of 32 bytes for every cryptographic key (audit anchor, audit witness, kill switch, backup and evidence) is being added and is in progress. Until it lands, a weak key is a risk the code does not catch.

Weaknesses of this default:
- While all modules run in one process (ADR-0010), every module can resolve every reference. NFR-016's separation of production secrets and broker permissions is not met.
- The `Redactor` removes values it knows and shapes it recognises. A secret in an unfamiliar format that arrives inside source content can pass through. A registered value shorter than the redactor's minimum (`MIN_REGISTERED_LENGTH`) is not matched as a substring (it would shred ordinary text), so a short secret is not scrubbed from free text; the store logs a warning naming the reference when this happens.
- Every key is read from the process environment, which child processes inherit and diagnostic dumps may include. The two host-local commands (admin and break-glass) read the same environment, so whoever can run them with it holds the keys.
- Reads are audited by our wrapper, not by an independent system.
- The evidence encryption key (ADR-0003) comes from this provider. The backup archive key (ADR-0014) is one of the five references, with the same provider and the same weaknesses. Recovery of every key is undocumented: lose the audit key and the audit log can no longer be verified or appended to; lose the kill-switch key and every capability reads as blocked and no release can succeed; lose the backup key and no archive can be opened.

## Why this default is reversible
Seam: `SecretStore` in `ciso.vault`. Consumers pass a reference and receive a `SecretValue`; they never know the provider. To switch: implement a provider for the chosen store, keep the same reference names, and give each process its own identity toward the store once processes are split. No stored data changes, because no stored data contains a secret.

## Evidence needed to make this final
- Whether the company already operates a secret store, and who administers it (Phase 0 checklist).
- The approved host and its operating system (OD-01).
- The credential type each source requires (OAuth client, workload identity, service account, signed webhook, mTLS; BP §13.4), from the source-system matrix.
- Which sources can issue short-lived or scoped credentials.
- Key ownership, recovery and rotation rules (BP §11.1).

## Consequences
- The Phase 1 gate item "no secrets in code/prompts/logs" can be tested now.
- A production secret store must be chosen before any real connector credential is issued.
- The environment provider must be refused outside development; how that is enforced is part of closing this ADR.
