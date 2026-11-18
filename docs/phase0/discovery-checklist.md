# Phase 0 discovery checklist

Use with `README.md` in this directory. Each row is a question that a named person can answer with evidence.

How to read the columns:

- **Evidence that answers it**: what to attach or reference. An answer without evidence is recorded as `declared`.
- **Closes or feeds**: the open decision from BP §20 that the answer closes. "Feeds" means the BP resolves that decision later than Phase 0 and this answer is only an input. "None in §20" means the BP has no OD id for the topic; the BP section that asks for it is given instead.
- **Answer, state, date**: leave blank in the template. In the filled copy, write the answer, one information state (verified, declared, inferred, disputed, unknown), who answered and the date.

Rules: write "unknown" when the answer is unknown. Do not write secrets. Do not enable or request write access. Product names in a question are the BP's own examples of what to ask about; none is assumed.

## 1. Organization and roles

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| ORG-01 | Which departments and teams exist, and who leads each? | Organization chart or HR export, dated | None in §20; BP §17.2 (organizational ownership), FR-002 | |
| ORG-02 | Which engagement types exist besides employees (for example contractors, agencies, interns), and which systems can each type reach? | Contract list; account lists per type | None in §20; BP §6.3 (employment/engagement status) | |
| ORG-03 | Who holds each of the five role templates? | Filled `role-and-approver-template.md`, confirmed by leadership | None in §20; Phase 0 gate (owner/role templates) | |
| ORG-04 | For every system found in sections 2 to 9, who is the System Owner and who is the alternate? | Owner column of the source-system matrix, confirmed by each named person | None in §20; Phase 0 gate; BP §17.2 | |
| ORG-05 | Who may accept significant business risk and policy exceptions for the company? | Written designation by leadership | Feeds OD-11 | |
| ORG-06 | Who will administer the CISO platform, and who reviews that person's actions? State it plainly if both are the same person. | Written designation | None in §20; input to ADR-0009 and ADR-0013 | |
| ORG-07 | Who will maintain the platform's code, and which programming languages can they review? | Names and stated skills | None in §20; input to ADR-0001 | |
| ORG-08 | How does a person join, change role and leave today, and which system records each step first? | Onboarding and offboarding checklists; records of recent cases | OD-03, OD-08 | |
| ORG-09 | Which security policies, incident records and risk lists already exist? | The documents, with dates and owners | OD-10 | |
| ORG-10 | Who must be told about an urgent security finding, through which channel, including outside office hours? | Contact list approved by leadership | Feeds OD-12 | |

## 2. Identity

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| IDN-01 | Which identity provider or providers authenticate staff? (BP examples to ask about: Entra ID, Google, Okta, AD, multiple providers or another setup.) | Tenant or directory page from each admin console | OD-03 | |
| IDN-02 | Which applications use SSO, and which still have local accounts? | Application list from the identity provider; list of applications with local login | OD-03, OD-08 | |
| IDN-03 | Is MFA enforced for all users and for administrators, and which methods are allowed? | Authentication policy export | OD-03 | |
| IDN-04 | Which groups or roles exist, and what does each grant? | Group export with members; mapping of group to access | OD-03 | |
| IDN-05 | Which accounts hold administrator privileges in the identity provider? Is any of them shared? | Administrator role assignment export | OD-03 | |
| IDN-06 | How are service identities (service accounts, OAuth clients, API keys, workload identities) created, owned and rotated? | Inventory export with an owner per identity | OD-03 | |
| IDN-07 | Does the identity provider offer a read API and an audit-log API, and which read-only scopes do they need? | Vendor documentation reference; confirmation by the administrator | OD-03 | |
| IDN-08 | Which SSO protocol can the identity provider offer for the CISO console, and can it pass group or role claims? | Application registration options in the admin console | OD-03; input to ADR-0004 | |
| IDN-09 | In the most recent departures, how long passed between the recorded departure and the disabled account? | Timestamps from the HR record and the identity audit log | OD-03 | |
| IDN-10 | Which identities exist outside the identity provider (local administrator accounts, break-glass accounts, vendor support accounts)? | List with owner and purpose | OD-03 | |

## 3. Cloud and infrastructure

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| CLD-01 | Which cloud providers are in use? (BP examples to ask about: AWS/Azure/GCP.) | Organization or billing console page | OD-04 | |
| CLD-02 | What is every account, project or subscription, with its purpose, environment and owner? | Organization export | OD-04 | |
| CLD-03 | Is Kubernetes or another orchestrator in use? Which clusters, and where? | Cluster list | OD-04 | |
| CLD-04 | Which on-prem or office systems exist (servers, network equipment, storage devices)? | Inventory; office network diagram | OD-04 | |
| CLD-05 | How are production, staging and development separated (accounts, networks, credentials)? | Diagram; account-to-environment mapping | OD-04 | |
| CLD-06 | Which services are reachable from the internet (domains, addresses, load balancers)? | DNS zone export; public address list | OD-04 | |
| CLD-07 | Which read-only role can be granted to a connector in each account, and which change or audit event source exists? | Role definition; audit logging configuration | OD-04 | |
| CLD-08 | Where are cloud secrets and keys stored, and who administers that store? | Service configuration; administrator list | OD-04; input to ADR-0008 | |
| CLD-09 | Is infrastructure defined as code? Where? | Repository paths | OD-04 | |
| CLD-10 | Which domains, address ranges, accounts and environments are approved as discovery scope, with which profile, exclusions and expiry? | Scope list signed by the approving role | OD-04; Phase 0 gate (approved discovery scopes) | |
| CLD-11 | Which referenced infrastructure belongs to third parties or customers and is therefore out of scope? | List with the reason for each | OD-04; BP §7.3 | |

## 4. Repositories and CI/CD

BP §20 has no OD id for repositories and CI/CD. The topic comes from BP §17.2 (Git / CI/CD dependency) and §16.2 DF-12.

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| REP-01 | Which Git platform or platforms and which organizations are in use? | Organization settings page | None in §20; BP §17.2 | |
| REP-02 | What is every repository, with its owner, visibility and the production service it deploys? | Repository export; owner confirmation | None in §20; BP §17.2 | |
| REP-03 | Which branch protection and review rules apply to default branches? | Settings export per repository | None in §20; BP §4.1 | |
| REP-04 | Who has administrator rights on the organization, and which outside collaborators exist? | Member and collaborator export | None in §20; OD-03 | |
| REP-05 | Which CI/CD systems run pipelines, where do they run, and which identities do pipelines use to deploy to which environments? | Pipeline configuration; deployment credential inventory | None in §20; BP §17.2 | |
| REP-06 | Which artifact and package registries exist, and who can publish to them? | Registry permission export | None in §20; BP §4.1 | |
| REP-07 | Are secret scanning and dependency scanning enabled, and can their findings be read through an API? | Feature settings; API documentation reference | None in §20; BP §8.1 (credential governance) | |
| REP-08 | Which application installations, integrations and access tokens can reach the organization, and with which scopes? | Installed applications export; token inventory | None in §20; BP §17.2 | |
| REP-09 | Which read-only installation scopes would a connector need? | Vendor documentation reference; administrator confirmation | None in §20; BP §17.2 | |
| REP-10 | Where are engineering issues tracked? (BP examples to ask about: GitHub Issues, Jira, Linear, ServiceNow or other.) | Tool settings page | OD-13 | |

## 5. SaaS product and production environments

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| PRD-01 | Is there a current architecture diagram of the SaaS product? | The diagram, with date and owner | OD-04, OD-05 | |
| PRD-02 | What is every production service, where does it run and who owns it? | Service catalogue or deployment manifests | OD-04 | |
| PRD-03 | Which data stores hold customer data, where are they located, who owns them and how are they encrypted? | Data store inventory; configuration | OD-09, OD-04 | |
| PRD-04 | How is tenant isolation implemented, and how is it tested? | Design document; test suite | OD-05 | |
| PRD-05 | Which runtime identities do production services use, and what can each do? | Role and permission export | OD-04 | |
| PRD-06 | Which people have production access, how is it granted and where is it logged? | Access list; access request records; log location | OD-03, OD-04 | |
| PRD-07 | Which production logs and monitoring exist, where are they stored, and do logs contain customer content? | Logging configuration; a sampled log review by the owner | OD-09, OD-17 | |
| PRD-08 | Do staging or development environments hold copies of production or customer data? | Statement by the owner, with the data refresh procedure | OD-09 | |
| PRD-09 | What is the path from commit to production, and who approves a release? | Pipeline definition; release records | None in §20; BP §4.1 | |
| PRD-10 | Which incident response process, on-call arrangement and past incident records exist? | Runbook; incident log | OD-10 | |
| PRD-11 | Which production targets may be checked by bounded active discovery, with which conservative profile and time window? | Scope entry signed by the approving role and the System Owner | OD-04; Phase 0 gate (approved discovery scopes) | |

## 6. AI product architecture

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| AIP-01 | Which model providers and models (with versions) does the product call, and from which services? | Application configuration; provider console | OD-05 | |
| AIP-02 | Where are the inference endpoints, in which region or processing location, under which account or project? | Provider console; contract or configuration evidence | OD-05 | |
| AIP-03 | Is there an inference gateway or routing layer, and does it switch between models or providers? | Gateway configuration | OD-05 | |
| AIP-04 | Which RAG pipelines exist: ingestion sources, embedding model, vector stores? How is retrieval authorized per tenant and per user? | Pipeline code or design; index and namespace layout | OD-05 | |
| AIP-05 | Which agents exist, which framework do they use, which tools can each call, under which service identity, and what memory do they keep? | Agent configuration; tool registry | OD-05 | |
| AIP-06 | Which MCP/A2A or equivalent endpoints does the product expose or consume? | Endpoint list with owner | OD-05 | |
| AIP-07 | Are customer prompts and outputs logged or cached? Where, for how long, and is any cache shared across tenants? | Logging and cache configuration | OD-05, OD-17 | |
| AIP-08 | Where are provider credentials stored, who can read them and how are they rotated? | Secret store configuration; access list | OD-05 | |
| AIP-09 | Which model artifacts, datasets or adapters are self-hosted, where did they come from and how is their integrity checked? | Artifact inventory with source and hash or signature | OD-05 | |
| AIP-10 | Which AI-specific tests exist (prompt injection, cross-tenant access, tool misuse, insecure output)? | Test suite; last results | OD-05 | |
| AIP-11 | Which usage, cost and rate limits are set per provider, and who is alerted when they are exceeded? | Provider limits page; alert configuration | OD-05 | |
| AIP-12 | What is the data flow of one typical AI request, from the user to the model and back? | Data-flow diagram reviewed by the owner | OD-05 | |

## 7. Employee AI usage and existing controls

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| EAI-01 | Which AI services are approved for employees, and under which subscription type? | Contracts or admin console pages | OD-06 | |
| EAI-02 | For each approved service, is there an admin console or an admin/audit API that shows users and usage? | Vendor documentation reference; administrator confirmation | OD-06 | |
| EAI-03 | Which IDE assistants and extensions are in use, and are they centrally managed? | Managed extension list; developer survey | OD-06 | |
| EAI-04 | Is there an AI usage policy? Which data classes are allowed with which provider? | Policy document | OD-06, OD-09 | |
| EAI-05 | Which existing controls can observe AI usage (CASB, DLP, secure web gateway, browser controls, network controls)? | Product configuration | OD-06 | |
| EAI-06 | Which usage paths cannot be observed (for example personal accounts or unmanaged devices)? | Written list of visibility gaps, agreed with the Security Administrator | OD-06; BP §16.2 DF-02 | |
| EAI-07 | Is there any inventory of employee-created scripts, agents, MCP servers, RAG collections and model API keys? | Inventory, or a statement that none exists | OD-06 | |
| EAI-08 | How does an employee ask today whether a tool is allowed, or request an exception? | Description of the current channel; recent examples | OD-06; feeds OD-12 | |
| EAI-09 | Has the legal or privacy owner reviewed any monitoring of employee AI use, and which purposes were approved? | Written review | OD-10 | |

## 8. Existing endpoint tooling

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| END-01 | Which device-management and endpoint-security products are in use? | Admin console pages | OD-07 | |
| END-02 | Which license tier is held, and does it include API access? | License record; vendor documentation reference | OD-07 | |
| END-03 | How many devices are managed compared with devices in use, by operating system, including personal devices used for work? | Console export; asset list | OD-07 | |
| END-04 | Which telemetry is available (inventory, compliance posture, detections), and through which API scopes? | Vendor documentation reference; administrator confirmation | OD-07 | |
| END-05 | Which response actions does the tool offer? Record them only; none is enabled in Phase 0. | Console capability list | OD-07 | |
| END-06 | Who administers these tools, and who receives their alerts today? | Administrator list; alert routing configuration | OD-07 | |
| END-07 | Which devices or people are outside coverage? | Gap list | OD-07; BP §16.2 DF-01 | |
| END-08 | Would any planned integration require installing something on employee devices? The BP requires that none does. | Review of each planned integration | OD-07; BP §3 register item "Endpoint software" | |

## 9. Business SaaS

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| SAS-01 | Which business applications are in use for HR, CRM, finance, communications, project management and other critical functions, with owner and administrator? | SSO application list; vendor payment records | OD-08 | |
| SAS-02 | Which of them hold customer data or personal data? | Owner statement; data export sample reviewed by the owner | OD-08, OD-09 | |
| SAS-03 | Which of them offer an admin API and audit logs, and at which license tier? | Vendor documentation reference; license record | OD-08 | |
| SAS-04 | Which third-party OAuth grants and integrations are connected to the core workspace? | OAuth grant export | OD-08 | |
| SAS-05 | Which system is authoritative for employment status and department? | Owner statement; sample record compared with the identity provider | OD-08 | |
| SAS-06 | Which ticketing or workflow tool is used, can a service identity create items in it, and how are approvals routed? (BP examples to ask about: GitHub Issues, Jira, Linear, ServiceNow or other.) | Tool settings; permission model | OD-13 | |
| SAS-07 | Which team chat platform is in use, and how do its accounts map to the identity provider? | Workspace settings | Feeds OD-12 | |
| SAS-08 | How does the company find applications bought outside IT today? | Description of the process; recent findings | OD-08 | |
| SAS-09 | Are vendor contracts and data processing terms on file for the critical applications? | The documents | OD-10 | |

## 10. Data classification and customer data

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| DAT-01 | Is there a data classification scheme? If not, which classes does leadership adopt as the initial scheme? | Policy or a recorded decision | OD-09; Phase 0 gate (initial data classification) | |
| DAT-02 | Which categories of customer data does the SaaS process or store? | Data inventory; product specification; customer agreements | OD-09 | |
| DAT-03 | For each data store, what is its class, location and owner? | Data store inventory | OD-09 | |
| DAT-04 | Where is employees' personal data held? | List of systems with owner | OD-09 | |
| DAT-05 | Which restrictions apply to where data may be stored, processed or transferred? | Contract clauses; legal statement | OD-09, OD-10 | |
| DAT-06 | Which retention and deletion rules exist today per data type, including commitments to customers? | Policy; contract clauses | OD-17 | |
| DAT-07 | Which data classes may be placed in a prompt to the CISO's local model, and which may never be sent to an external provider? | Recorded decision by the data owner | OD-09; feeds OD-14 | |
| DAT-08 | For access to raw customer content during an incident: who authorizes it, for which purpose, with what minimization and retention? | Written rule | OD-09; BP §4.5 | |
| DAT-09 | How long must the CISO's own evidence, logs, model traces, incident data and employee-related records be kept, and when must they be deleted? | Retention schedule approved by the legal or privacy owner | OD-17 | |
| DAT-10 | Where do secrets live today (secret stores, CI variables, configuration files), and who owns each location? | List of locations with owner; no values | OD-09 | |

## 11. Legal, privacy and compliance

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| LEG-01 | In which jurisdictions does the company operate, employ people and store or process data? | Incorporation records; employment locations; hosting regions | OD-10 | |
| LEG-02 | Which security commitments exist in customer contracts (audit rights, incident notification, promised assurance)? | Contract clauses | OD-10; feeds OD-18 | |
| LEG-03 | Who is the responsible privacy owner or qualified counsel? | Named person or firm, confirmed | OD-10 | |
| LEG-04 | Which employment and privacy rules limit collection of employee-related security telemetry, and which purposes has counsel approved? | Written review | OD-10; BP §12.3 | |
| LEG-05 | Which frameworks or assurance reports do customers or leadership expect? (BP examples to ask about: NIST CSF 2.0, ISO 27001, SOC 2, customer questionnaires, sector-specific obligations.) | Customer requests; sales records; leadership statement | Feeds OD-18 | |
| LEG-06 | Which audit reports, penetration test reports and completed security questionnaires already exist? | The documents | OD-10 | |
| LEG-07 | Are there legal limits on where the CISO's evidence and backups may be stored? | Legal statement | OD-10, OD-17 | |
| LEG-08 | What do contracts with AI providers say about data use, retention and training on inputs? | Contract or terms, with the version reviewed | OD-10, OD-06; feeds OD-14 | |
| LEG-09 | Which incident notification duties apply, and to whom? | Legal statement citing the source of each duty | OD-10 | |
| LEG-10 | Which obligations are still unresolved after this review, and who owns each? | List with an owner per item | OD-10; Phase 0 gate (unresolved compliance obligations) | |

## 12. Office host, network, power, backup

| Id | Question | Evidence that answers it | Closes or feeds | Answer, state, date |
|---|---|---|---|---|
| HST-01 | Can the company host and physically secure a machine in its office? In which room, and who can enter it? | Site description; access list | OD-01; BP §17.1 | |
| HST-02 | Which host form is feasible given space, power, cooling and noise? (BP lists office server, workstation or small rack host.) | Facility assessment | OD-01 | |
| HST-03 | Is there existing hardware that could be considered? Record its exact specification. No decision is made before the benchmark. | Hardware specification sheet | OD-01; feeds OD-02 | |
| HST-04 | Is there a UPS, is it sized for a graceful shutdown, and can it signal power state to the host? | UPS model data; test of a controlled shutdown | OD-01 | |
| HST-05 | On which network segment will the host sit, and who manages its firewall rules? | Network diagram; rule owner | OD-01 | |
| HST-06 | Can outbound traffic from that segment be limited to an allowlist, and by which control? | Firewall or gateway capability; a test rule | OD-01; input to ADR-0006 and ADR-0015 | |
| HST-07 | Which remote access path is approved for administrators outside the office? | Description of the path and who controls it | OD-01 | |
| HST-08 | How is the office connected to the internet, and what outages have occurred? | Provider contract; outage history | Feeds OD-16 | |
| HST-09 | Where will backups be stored, who can reach them, and is the target off the host? | Backup target description; access list | OD-01; feeds OD-16 | |
| HST-10 | How long may the CISO be unavailable, and how much recent data may be lost, before the business is harmed? | Statement by leadership | Feeds OD-16 | |
| HST-11 | Is the host disk encrypted at rest, and who holds the recovery key? | Configuration; key custody record | OD-01 | |
| HST-12 | What are the sizing inputs from BP §10.4: expected event volume, concurrent conversations, investigation concurrency, code-analysis workload, retention and search needs? | Estimates derived from the source-system matrix and owner interviews, each labelled as measured or estimated | OD-01; feeds OD-02 | |
| HST-13 | Who administers the host operating system and applies updates? | Named person | OD-01 | |
| HST-14 | Which time source will the host use, and where are service-health alerts sent? | Configuration plan | OD-01 | |

## Open decisions this checklist feeds but does not close

| Id | Decision area | When the BP resolves it | What Phase 0 collects for it |
|---|---|---|---|
| OD-02 | Local models/runtime | Benchmark after workload definition | HST-03, HST-12 |
| OD-11 | Risk methodology | After asset and business context | ORG-05, and the asset and data inventory as a whole |
| OD-12 | Employee interface | After user workflow discovery | ORG-10, EAI-08, SAS-07 |
| OD-14 | External LLM approvals | Before enabling external adapter | DAT-07, LEG-08, and the role mapping |
| OD-15 | L3 playbooks | After controls and testing | Nothing in Phase 0. END-05 and SAS-06 record what actions exist |
| OD-16 | Availability/recovery | Before production rollout | HST-08, HST-09, HST-10 |
| OD-18 | Compliance mapping | After obligation discovery | LEG-02, LEG-05, LEG-10 |

## Gate check

Tick each item only when it is complete. Wording follows the BP §18 Phase 0 exit gate.

- [ ] System and source inventory validated (sections 2 to 9; source-system matrix has a row per source).
- [ ] Initial data classification recorded (DAT-01 to DAT-03).
- [ ] Source-authority map filled (source-system matrix, authority map table).
- [ ] Discovery scopes approved, with approver, profile, exclusions and expiry (CLD-10, CLD-11, PRD-11).
- [ ] Owner and role templates filled (ORG-03, ORG-04).
- [ ] List of unresolved compliance obligations written, with an owner per item (LEG-10).
- [ ] Confirmed: no production write action is enabled.
