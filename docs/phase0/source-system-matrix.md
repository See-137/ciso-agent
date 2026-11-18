# Source-system matrix (template)

This is the source/system matrix BP §18 Phase 0 asks for. It is empty on purpose. It names no vendor and assumes none. One row describes one source system in one environment or tenant; a system that exists in production and in staging gets two rows.

The matrix feeds three things: the validated source inventory and the source-authority map in the Phase 0 exit gate, the order in which read connectors are built (BP §18 Phase 2: "order is evidence-driven"), and the choice of the first low-risk read-only source (BP §19.4 #7).

## Column definitions

| Column | What to write | Origin |
|---|---|---|
| Row id | A stable id, for example SRC-01 | This template |
| Source system | The kind of system and its name, for example "identity provider (name: ____)" | BP §18 |
| Category | identity, cloud, Git / CI/CD, AI provider or gateway, business SaaS, endpoint tooling, office infrastructure, other | BP §17.2 |
| Source owner | The System Owner role holder for this source, and the person | BP §18 |
| Environment | production, staging, development, third_party, customer_owned or unknown. The last two are never in discovery scope by inference (BP §7.3) | BP §7.3; added column |
| Authority domain | The facts or fields this source is authoritative for. Field level, not "everything". A source can be listed with no authority domain if it is only a secondary observer | BP §6.1, §6.2; added column |
| API availability | Whether an API, webhook or export exists, at which license tier, with a documentation reference. "None" and "unknown" are valid | BP §18 |
| Read capabilities | What can be read: inventory, configuration, audit events, changes, findings | BP §18 |
| Write capabilities | What the source would allow a client to change. Recorded for information only. Nothing is requested or enabled in Phase 0 | BP §18 |
| Required scopes | The exact read-only scope or role names from the vendor documentation. Write scopes are listed separately and marked "not requested" | BP §18 |
| Sync method | polling, event/webhook, snapshot, manual export by the owner, or a combination; and whether the source retains events for replay | BP §18, §10.3 |
| Rate limits | The documented limit with its reference, or "unknown". Do not estimate | BP §18 |
| Freshness expectation | How current the owner needs this source's facts to be in the registry, in the owner's words. It later becomes the source-specific freshness policy | BP §6.5; added column |
| Data sensitivity | The data classes this source exposes, using the classification from the checklist (DAT-01). "Unknown" is handled as sensitive | BP §18, §11.1 |
| Known gaps | What this source cannot see or will not provide: missing populations, missing fields, license limits, permission gaps | BP §18 |
| Connector priority | Order for building a connector, with a one-line reason. Decided after all rows are filled | Added column |
| State and evidence | The information state of this row (verified, declared, inferred, disputed, unknown), who supplied it, the date and the evidence reference | BP §7.5 |

Rules:

- Write "unknown" where the answer is unknown. A blank cell means the question was not asked.
- Do not write credentials, tokens or key material. Record where a credential would be managed.
- A row is `declared` until its content is supported by current evidence from the source itself.
- A source that is out of scope (customer-owned or unrelated third-party infrastructure, BP §7.3) is listed with its reason and gets no connector priority.

## Example rows

The three rows below are fictional and exist only to show the level of detail. They describe no real company and no real product. Delete them from the filled copy.

| Row id | Source system | Category | Source owner | Environment | Authority domain | API availability | Read capabilities | Write capabilities | Required scopes | Sync method | Rate limits | Freshness expectation | Data sensitivity | Known gaps | Connector priority | State and evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| EXAMPLE-1 | identity provider (name: ____) | identity | System Owner: ____ (EXAMPLE) | production | Authentication state; group membership | EXAMPLE: admin read API and audit-log API exist at the license tier held; documentation reference: ____ | Users, groups, administrator role assignments, sign-in and admin audit events | Exists at the source (for example disable an account). Not requested | Read-only directory scope: ____; read-only audit-log scope: ____ | Polling for inventory; event/webhook for audit events if offered; event retention at the source: ____ | Documented limit: ____ (reference: ____) | EXAMPLE: owner says a disabled account must be visible to the CISO quickly; exact expectation: ____ | Employee personal data; class: ____ | EXAMPLE: accounts local to individual applications are not listed here; service identities are issued elsewhere | EXAMPLE: first, because the other sources link to identities | declared; supplied by ____ on ____; evidence: ____ |
| EXAMPLE-2 | Git platform (name: ____) | Git / CI/CD | System Owner: ____ (EXAMPLE) | production | Repository permissions; branch controls | EXAMPLE: read API exists; read-only application installation possible; documentation reference: ____ | Repositories, members, collaborators, branch protection settings, installed applications, source-native findings if enabled | Exists at the source (for example open an issue or a pull request). Not requested | Read-only organization and repository metadata scopes: ____ | Polling; webhook for change events if an inbound path is approved (see ADR-0015) | Documented limit: ____ (reference: ____) | EXAMPLE: owner states how soon a permission change must be visible to the CISO; exact expectation: ____ | Source code and configuration; class: ____ | EXAMPLE: personal forks and repositories outside the organization are not visible | EXAMPLE: second | declared; supplied by ____ on ____; evidence: ____ |
| EXAMPLE-3 | HR / organization system, if present (name: ____) | business SaaS | System Owner: ____ (EXAMPLE) | third_party | Employment status; department | EXAMPLE: no API at the license tier held; the owner can produce an export | Employee list with status, department and manager | None through the export | None; the owner produces the file | Manual export by the owner on a schedule the owner sets: ____ | Not applicable | EXAMPLE: owner says a departure must reach the CISO no later than the next export; exact expectation: ____ | Employee personal data; class: ____ | EXAMPLE: contractors are not recorded here; the export shows no history of changes | EXAMPLE: later; needs a file-based intake and an agreed procedure | declared; supplied by ____ on ____; evidence: ____ |

## Matrix

| Row id | Source system | Category | Source owner | Environment | Authority domain | API availability | Read capabilities | Write capabilities | Required scopes | Sync method | Rate limits | Freshness expectation | Data sensitivity | Known gaps | Connector priority | State and evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SRC-01 | | | | | | | | | | | | | | | | |
| SRC-02 | | | | | | | | | | | | | | | | |
| SRC-03 | | | | | | | | | | | | | | | | |
| SRC-04 | | | | | | | | | | | | | | | | |
| SRC-05 | | | | | | | | | | | | | | | | |
| SRC-06 | | | | | | | | | | | | | | | | |
| SRC-07 | | | | | | | | | | | | | | | | |
| SRC-08 | | | | | | | | | | | | | | | | |

Add rows as needed.

## Source-authority map

The Phase 0 exit gate asks for a source-authority map. The first column below repeats the fact types from BP §6.2, which the BP labels as suggested examples. Fill the other columns from the matrix rows and add fact types as they are found. Where two sources both claim a field, list both and name the one that wins; the registry keeps every assertion and marks conflicts as disputed (BP §6.1, §7.5).

| Fact or field | Likely authoritative source per BP §6.2 | Authoritative source here (row id) | Other sources that also report it (row ids) | Agreed by (System Owner) | Date |
|---|---|---|---|---|---|
| Employment status and department | HR/organization system, if present | | | | |
| Authentication state and group membership | Identity provider | | | | |
| Cloud resource configuration | Cloud provider APIs/configuration source | | | | |
| Repository permissions and branch controls | Git platform | | | | |
| AI provider/model configuration | Provider admin APIs, gateway logs, application config or owner declaration | | | | |
| CISO risk finding and decision | CISO security record | Not a source system; owned by the CISO platform | | | |
| Accepted business risk | Authorized human decision recorded by CISO | Not a source system; recorded by the CISO platform | | | |
| | | | | | |

## Coverage gaps found while filling the matrix

List here every population, system or data path that no row covers. BP §7.2 requires that a missing source is reported as a gap and never read as "no risk found".

| Gap | Why it is not covered | Owner | Accept, or plan to close |
|---|---|---|---|
| | | | |
