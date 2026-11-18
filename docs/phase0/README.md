# Phase 0: company and environment discovery

## What Phase 0 is

Phase 0 is the first phase of the BP roadmap (BP §18). Its objective is to "replace unknown assumptions with a verified environment baseline". The BP is a design handoff, not an audit: no live account, repository, endpoint console, IAM configuration, diagram, policy, contract or data-flow inventory was inspected (BP §2.4). Every statement about the company's environment is an assumption until Phase 0 verifies it.

Phase 0 is done by people. Software cannot interview a system owner, read a contract or decide who approves what. This directory holds the instruments for that work (BP §19.4 #2, Appendix C #11). It holds no answers.

The BP lists five activities for Phase 0:

1. Interview system owners and inventory departments, identities, cloud accounts/projects, repositories, CI/CD, production services, AI applications/agents/providers, data stores, business SaaS and existing security tools.
2. Collect architecture and data-flow diagrams, environment boundaries, customer data categories, identity groups, API integration docs, policies, contracts and audit requirements.
3. Build a source/system matrix: source owner, API availability, read/write capabilities, required scopes, sync method, rate limits, data sensitivity and known gaps.
4. Define the approved office host and network segment, physical access, UPS, backup target and recovery expectations.
5. Identify legal jurisdictions, customer commitments, privacy obligations and likely security framework needs.

## Exit gate

Phase 0 is finished when all of the following exist, and not before:

| Gate item (BP §18, Phase 0 exit gate) | Produced with |
|---|---|
| A validated inventory of systems and sources | `discovery-checklist.md` and `source-system-matrix.md` |
| An initial data classification | `discovery-checklist.md`, section 10 |
| A source-authority map: which source is authoritative for which fields | `source-system-matrix.md`, authority columns and the authority map table |
| Approved discovery scopes | `discovery-checklist.md` scope questions (CLD-10, CLD-11, PRD-11); each scope approved by a person holding the role recorded for discovery scopes in the approval routing table of `role-and-approver-template.md` |
| Owner and role templates | `role-and-approver-template.md` |
| A list of compliance obligations that are still unresolved | `discovery-checklist.md`, section 11 |
| No production write action is enabled | A state to confirm, not a document. Phase 0 collects read access and information only |

The BP adds that the coding agent "must not bypass a gate simply to demonstrate autonomy" (§18). A gate item that is partly answered is open.

## The three files

| File | What it is | Who fills it | When |
|---|---|---|---|
| `discovery-checklist.md` | Questions grouped by area. Each question can be answered with evidence and names the open decision (OD id) it closes or feeds | The person running Phase 0, with each system owner | First. It finds the systems and the people |
| `source-system-matrix.md` | One row per source system, with the columns BP §18 asks for plus authority domain, environment, freshness expectation and connector priority | The owner of each source, reviewed by the Security Administrator | As each system is identified in the checklist |
| `role-and-approver-template.md` | The five role templates from BP §9.3, what each may approve, and blank slots for people | Company leadership | Early. Scope approvals and system ownership depend on it |

## How to record an answer

- Record the answer, the evidence that supports it, who gave it and the date.
- Label each answer with one of the BP's information states (verified, declared, inferred, disputed, unknown; BP §7.5). An answer given in an interview with no supporting evidence is `declared`. It becomes `verified` when current evidence from an appropriate authoritative source supports it.
- "Unknown" is a valid answer and must be written down as unknown. A blank is not an answer. An unknown is a coverage gap; do not assume absence (BP §7.5).
- If two people or two documents disagree, record both and mark the item `disputed`. Do not pick one.
- Do not write secrets, tokens, passwords or key material into these files. Record where the credential is managed and who controls it.
- Do not grant or request write access during Phase 0. Record what write capability a source offers; do not turn it on.
- Do not name a vendor in these templates. The filled copies will name them; the templates stay neutral.

The filled copies will contain sensitive information about the company (system names, owners, gaps). Decide where they are stored and who may read them before filling them in.

## What happens with the answers

- Each answer closes or narrows an open decision in `docs/adr/open-decisions.md`.
- The related ADR in `docs/adr/` is updated with the evidence and goes to the owner for approval.
- The source-system matrix decides the order of the first connectors (BP §18 Phase 2: "order is evidence-driven") and the first low-risk read-only source (BP §19.4 #7).
- The approved scopes become entries in the platform's approved-scope registry. No active discovery runs before those entries exist (BP §19.1).

## What Phase 0 does not decide

These are resolved later, per BP §20. Phase 0 collects inputs for them only: the local model and runtime (OD-02, after a benchmark), risk methodology (OD-11), the employee interface (OD-12), external LLM approvals (OD-14), L3 playbooks (OD-15), recovery objectives (OD-16) and compliance mapping (OD-18).
