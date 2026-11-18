# Open decisions

Last checked against the code on 2026-11-18. Source: BP §20 (OD-01 to OD-18) and BP §3 (decision register). The BP says of these: "The coding agent should not silently choose answers." This file tracks each one, the ADR that touches it, and what the local build does while it stays open.

Vendor and product names in the "what is unknown" column are the BP's own examples of what to ask about. None is assumed.

## Table 1: open decisions from BP §20

| Id | Decision area | What is unknown | When to resolve (per BP) | Related ADR | What this build does meanwhile |
|---|---|---|---|---|---|
| OD-01 | Physical host | Office server, workstation or small rack host; hardware specs; UPS sizing; cooling; physical access | Phase 0 / after workload estimate | ADR-0015, ADR-0005, ADR-0014, ADR-0018, ADR-0020 | Runs on a developer machine, bound to loopback. Assumes no hardware. |
| OD-02 | Local models/runtime | Model family, quantization, serving runtime, embeddings/reranker and GPU/CPU capacity | Benchmark after workload definition | ADR-0005, ADR-0019 | Provider interface with a deterministic stub. No model or runtime is referenced. The gateway enforces a deadline and refuses a provider that is not a registered local class. |
| OD-03 | Identity system | Which identity setup is in use (BP examples: Entra ID, Google, Okta, AD, multiple providers or another setup); SSO/MFA and group mapping | Phase 0 | ADR-0004, ADR-0011, ADR-0019 | Bootstrap identity model with local actors and expiring bearer tokens that are shown once. The first administrator and lockout recovery are host-local commands. OIDC/SSO adapter is an interface only. |
| OD-04 | Cloud estate | Which cloud or clouds (BP examples: AWS/Azure/GCP), account structure, Kubernetes, on-prem network, production/staging segmentation | Phase 0 | ADR-0011, ADR-0019 | No cloud connector. No registry or onboarding module exists yet, so nothing records accounts or environments. |
| OD-05 | AI product architecture | Models/providers, inference gateways, agent framework, RAG/vector stores, memory, data flows and tenant design | Phase 0 | ADR-0011 | No AI asset registry exists yet. No assessment of the real product. |
| OD-06 | Employee AI controls | Enterprise subscriptions, provider admin/audit APIs, CASB/DLP/SWG/browser controls and visibility gaps | Phase 0 | ADR-0011 | No usage collection and no registry to record declared AI providers. Visibility limits are not yet recorded anywhere. |
| OD-07 | Existing MDM/EDR | Actual vendor, license, device coverage, telemetry, API scopes and response actions | Phase 0 | ADR-0011 | No endpoint connector. Nothing is installed on endpoints. The integration stays optional. |
| OD-08 | Business SaaS | HR, CRM, finance, communications, project management and other critical systems | Phase 0 | ADR-0011 | No connector and no registry to declare systems in yet. |
| OD-09 | Data classification | Data classes, customer data categories, secrets, personal data, retention and transfer restrictions | Phase 0 with business/legal | ADR-0017, ADR-0003 | Ships no classification scheme in code. Labels come from settings; `unknown` is built in and outranks every configured label. `config/provisional-settings.json` holds four placeholder labels that are not the company's classification. |
| OD-10 | Legal/compliance | Operating jurisdictions, customer contracts, privacy/employment requirements, assurance targets and applicable frameworks | Phase 0 with qualified counsel/owner | None (touches ADR-0006, ADR-0013, ADR-0014, ADR-0016) | Makes no compliance claim and builds no monitoring of employees. |
| OD-11 | Risk methodology | Qualitative/quantitative model, appetite, thresholds, risk acceptance and review cadence | After asset and business context | ADR-0021 (labels only) | No risk register and no numeric score. Envelopes carry a risk class label (`low`, `medium`, `high` in the default ruleset) with no scale and no effect on routing. Only a human `executive_risk_owner` holds the permission to accept risk, and no acceptance workflow exists yet. |
| OD-12 | Employee interface | Which channel (BP examples: portal, Slack/Teams/Telegram/other); authentication, notification policy and self-service scope | After user workflow discovery | ADR-0012 | Admin API only. No console and no employee channel. |
| OD-13 | Ticketing and workflow | Which tool (BP examples: GitHub Issues, Jira, Linear, ServiceNow or other); write permissions and approval routing | Phase 0 | ADR-0010, ADR-0011, ADR-0019 | No ticketing integration, and no execution broker or coordination tool yet, so nothing is written anywhere. |
| OD-14 | External LLM approvals | Approving role, supported providers, allowed data classes, per-request UX and retention terms | Before enabling external adapter | ADR-0006, ADR-0016, ADR-0017, ADR-0019, ADR-0021 | External inference is disabled and nothing is built: no external package, no approvals module, no transport. The approving role and the allowed classifications are unset, which blocks the path. The settings would accept `security_admin`, `system_owner` or `executive_risk_owner` as approver, which disagrees with the L4 routing; the owner decides. |
| OD-15 | L3 playbooks | Which low-risk actions, specific preconditions, rollback and verification; first release may have none | After controls and testing | ADR-0009, ADR-0010, ADR-0018, ADR-0019, ADR-0021 | Ships no L3 playbook. Policy denies L3 unless the context reports an approved, enabled, unexpired playbook for the target; the shipped context reports none, so every L3 request is denied. No role is named to authorize a playbook. |
| OD-16 | Availability/recovery | Recovery time and recovery point objectives; current plan assumes temporary outage is acceptable | Before production rollout | ADR-0014, ADR-0015 | Backup and restore are built as a library with an automated restore check (counts and audit verification). No command, no schedule, no off-host target. No RTO or RPO. |
| OD-17 | Data retention | Retention schedules for evidence, logs, prompts, model traces, incident data and employee-related records | Phase 0 / legal review | ADR-0003, ADR-0007, ADR-0013, ADR-0014, ADR-0020 | No evidence module yet. Audit records and queue rows are never deleted (queue rows are the dedupe record). No retention schedule is defined. Prompt bodies are not logged. |
| OD-18 | Compliance mapping | Whether to use NIST CSF 2.0, ISO 27001, SOC 2, customer questionnaires or sector-specific obligations as target scope | After obligation discovery | None | No mapping. The frameworks in BP §21 are used only as threat and test catalogs. |

## Table 2: BP §3 register items that are not decided

The ids in this table are the BP's planning-stage register (three digits). They are not the ADR files in this directory.

| BP register id | Topic | BP status | BP constraint | Related OD | Related ADR here | What this build does meanwhile |
|---|---|---|---|---|---|---|
| ADR-015 | Hardware | DEFERRED | Do not commit to a dedicated GPU server or reuse of existing hardware before workload and model benchmarks | OD-01, OD-02 | ADR-0005, ADR-0015 | Stub inference; no hardware assumed |
| ADR-016 | Risk model | DEFERRED | Capture evidence, findings and risks and support correlation; do not yet select a scoring formula or a specific continuous-risk methodology | OD-11 | ADR-0021 (labels only) | No risk register; labels carry no scale; no score |
| ADR-017 | Technology stack | DEFERRED | No database, runtime, language, model server, scanner, queue, agent framework or cloud vendor selected | OD-02, OD-04 | ADR-0001, ADR-0002, ADR-0003, ADR-0007, ADR-0008, ADR-0009, ADR-0012, ADR-0020 | Reversible defaults, each recorded as Proposed. No scanner, model server, agent framework or cloud vendor is selected |
| ADR-018 | Employee interface | NOT FULLY DECIDED | A browser-based/admin interface is needed; employee self-service and chat channels are design candidates, not a final channel decision | OD-12 | ADR-0012 | Admin API only; no console, although BP §12.1 lists one as required |
| ADR-019 | Compliance targets | UNKNOWN / DEFERRED | Customer, market, contractual and jurisdictional obligations are needed before selecting required frameworks or certification targets | OD-10, OD-18 | None | No mapping; no claims |

Two more register items are settled in direction but not in detail, and are listed so they are not mistaken for closed:

| BP register id | Topic | BP status | What is still open | Related OD | Related ADR here |
|---|---|---|---|---|---|
| ADR-004 | Deployment | LEADING DIRECTION | Central office-hosted instance is the direction; physical server design is not selected | OD-01 | ADR-0015 |
| ADR-006 | MDM / EDR | KNOWN BUT UNSPECIFIED | An endpoint/device-management capability exists; vendor, product, license and telemetry are unknown; optional integration only | OD-07 | ADR-0011 |

## How a row is closed

1. Phase 0 (`docs/phase0/`) or a later step named in the "when to resolve" column produces the answer with evidence.
2. The related ADR is updated, or a new ADR is written if none exists.
3. The owner approves the ADR.
4. The row is marked closed here with the date and the ADR id. Rows are not deleted.
