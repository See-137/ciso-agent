# ADR-0001: Implementation language and typing
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Blueprint refs: §1.2, §3 (register item "Technology stack", DEFERRED), §13.1, §19.1, §19.2, NFR-010, NFR-011, Appendix C #14

## Context
The BP does not select a programming language (§1.2) and says the technology stack is DEFERRED (§3). §13.1 repeats that "exact protocol and programming language are deferred". The foundation build cannot start without a language, so a default is needed. The BP requirements that bear on the choice are: typed request/response schemas and versioned events (§19.1), structured output schemas with deterministic validation of model output (§8.3), no free-form command execution (§9.4), and replaceable inference runtime and connectors (NFR-011). The BP also assumes a small organization with no large dedicated security team (§3 register item "Organization size"), so the code must be maintainable by few people.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Python 3.13, Pydantic v2 schemas, mypy strict | Schema validation at every boundary with little code; broad library coverage for whichever sources and local inference runtime are chosen later; fast to write and test the domain breadth | Types are checked by a tool, not enforced at run time; the default interpreter runs one thread of Python code at a time, which limits CPU parallelism inside one process; deployment needs a pinned lockfile and an interpreter on the host | Large third-party dependency tree to track; dynamic features (eval, pickle, monkeypatching, dynamic import) exist and must be banned by lint and review; module boundaries are enforced by a test, not by the language |
| Go | Compiler-enforced types; single static binary; simple deployment; good concurrency | Schema validation is more manual; fewer direct bindings to local inference libraries; slower iteration on a wide domain model | Smaller runtime and dependency surface; fewer dynamic-code risks |
| TypeScript on Node | Same language as a possible browser console; good schema libraries | Types are erased at run time, as in Python; very large dependency tree | Supply-chain exposure is the main concern |
| Rust | Strongest compile-time guarantees; memory safety | Slowest to deliver the breadth of the domain; fewest people able to maintain it in a small company | Best isolation properties; highest delivery risk, which delays the controls themselves |
| Python core now, execution broker rewritten later in a compiled language | Puts the highest-risk component behind a compiler and a process boundary | Two toolchains to maintain | Fits the process split in ADR-0010; can be adopted later without changing this default |

## Default chosen for the local build
Python 3.13. Every boundary schema is a Pydantic v2 model that is frozen and rejects unknown fields (`extra="forbid"`). mypy runs in strict mode over `src/`. No dynamic code execution. Each module exposes a small service class that receives its dependencies as constructor arguments (no globals, no module-level state).

Weaknesses of this default, stated plainly:
- mypy strict is a build-time check. Nothing stops untyped data at run time except the explicit Pydantic validation at each boundary.
- The import rules that keep `policy` and `execution` away from `inference` and `orchestrator` are a test over the source tree. A dynamic import would not be caught by that test.
- This is the least reversible default in the set. The cost of switching grows with every module written.

## Why this default is reversible
The contracts between components are data, not Python objects: the action envelope (BP §9.4), event envelope (§13.2), finding record (§13.3), policy rule files, the SQL schema (ADR-0002) and the HTTP API (ADR-0012). A component can be rewritten in another language behind its contract. The most likely candidates are the execution broker (seam: ADR-0010) and individual connectors (seam: ADR-0011). A full switch means rewriting module internals while keeping these contracts and the test intent.

## Evidence needed to make this final
- Who will maintain the platform and which languages they can review (Phase 0, organization and roles).
- Which local inference runtime is selected under OD-02 and what client bindings it offers.
- Host platform and packaging constraints (OD-01).
- Measured workload (BP §15.1) showing whether any CPU-bound hot spot exists that one Python process cannot serve.

## Consequences
- Development can proceed now with one toolchain.
- Lint rules and tests carry part of the safety that a compiler would give; they must stay in the required gate.
- Dependencies need a pinned lockfile and a review step for additions (BP §11, supply-chain row).
- If the owner prefers another language, the decision should be made before more modules are written.
