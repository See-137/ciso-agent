# ADR-0012: API and console (FastAPI control-plane API on loopback; no console in this build)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (API built; documentation pages, OpenAPI, rate limit, host-local commands)
Blueprint refs: §3 (register item "Employee interface", NOT FULLY DECIDED), §5.1 #1 and #2, §10.2, §12.1, §12.2, §19.2, §19.4 #8, FR-003, FR-032, NFR-004, NFR-005, NFR-015, OD-12, Appendix C #14, Appendix D; plan gaps G22, G28

## Context
A security administration console is a "required logical capability; exact UI stack undecided" and an API is the "recommended integration surface" (§12.1). The access layer must hold no direct database or tool credentials in browser or chat clients, with identity and authorization enforced server-side (§5.1 #1). The API edge handles sessions, SSO integration, service identities, API authorization, rate limits and request validation (§5.1 #2). Admin ports must not be exposed to the public internet (§10.2). Employee channels are not decided (OD-12).

Building a console means choosing a UI stack, which the BP leaves undecided. The decision recorded in `docs/plan/decisions.md` (G28) is: API only in this build, no UI framework chosen, and the OpenAPI document is the interface description.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| FastAPI control-plane API bound to loopback; no console; the OpenAPI document describes the interface | Request and response validation from the same Pydantic schemas as the core (ADR-0001); no UI stack is chosen ahead of OD-12 | No console: BP §12.1 lists one as a required logical capability, and this build does not have it. Reviewing findings and approving requests means calling the API | Every route declares its permission and is checked server-side. No browser code, so no client-side attack surface of our own |
| The same API plus a minimal static console | Meets §12.1 in a basic form | A hand-written UI and its escaping rules, likely to be discarded when OD-12 is decided | Source content is untrusted; every rendered value must be escaped or a crafted asset name becomes script in an administrator's browser |
| Server-rendered pages from the same application | One deployable; output escaping handled by a template engine | Couples UI and API release | Fewer client-side risks than a script-heavy console |
| Single-page application framework for the console | Rich approval and investigation UX | A second toolchain and a large client dependency tree before the UX needs are known (OD-12) | Token handling in the browser and client supply chain become real concerns |

## Default chosen for the local build
The API is built (`ciso.api`, started with `python -m ciso.api --config <settings file>`). The console is not.
- FastAPI. `create_app(container)` builds a new app on each call and refuses to build if any route declares no permission. Bearer authentication through `Authenticator` (ADR-0004). Every route declares the permission it needs with one dependency, and the check is server-side only. A test lists every route and fails on one with no declared permission; the only public route is `GET /healthz`, which answers a constant body and no component detail.
- The routes today: `GET /healthz`; `GET /v1/system/health`, `GET /v1/system/whoami`, `GET /v1/openapi.json`; `GET /v1/audit` (paged, with filters) and `GET /v1/audit/verify`; `GET /v1/killswitch`, `POST /v1/killswitch/engage`, `POST /v1/killswitch/release`; `GET /v1/policy/ruleset` (version, hash and deny-all state only). There is no route that changes policy, roles, approvers or audit records, and a test checks that.
- The framework's built-in documentation pages and its default OpenAPI route are switched off, because they are unauthenticated and the pages load scripts from a public network location. The OpenAPI document, which is the interface description in this build (G28), is served at `/v1/openapi.json` to an authenticated caller holding `registry.read`; a test checks that it needs a token and that the old paths answer 401 or 404.
- Rate limit before authentication. A request is charged to its client address before any token work (one scrypt hash per attempt is the cost the limit bounds), and refunded when the token authenticates, so only failures use up the address budget. After authentication the actor has a second budget. Over a limit the answer is 429 with `Retry-After`. The value comes from settings (G22) and has no default (ADR-0019): with it unset, every route except liveness answers 503. The limiter is an in-process fixed-window counter, per minute as the setting's name says.
- Identical 401. A missing, malformed, unknown, wrong, revoked, expired or disabled-actor token all get one fixed body, built the same way before normalisation. Error bodies are short and fixed per status; exception text never reaches the client, and an unexpected exception answers 500 with a correlation id only.
- Audit around requests. A state-changing request (POST, PUT, PATCH, DELETE) is audited as an attempt before its handler runs, and an audit failure turns it into 503. Every authenticated request gets a closing `api.request` record with its status. If the audit log is unavailable, writes are refused and reads are served with the failure logged.
- Host-local commands stay off the API. Bootstrapping the first administrator and recovering a locked-out one are run on the host (`python -m ciso.app.admin`, ADR-0004), together with `killswitch-reconcile` and `audit-verify`. A test checks that no API module names the host-local service and that no served route refers to it. The kill-switch break-glass command is also host-local (ADR-0018).
- Loopback only. `Settings` refuses a bind host that is not loopback unless `allow_non_loopback_bind` is set, and that flag is meant to be set only after the host and network decision (OD-01, ADR-0015).
- The server's own loggers write through the redacting handler, and its access log is off, because it would print request lines that the audit log already records.
- No console and no employee-facing channel.

Weaknesses of this default:
- BP §12.1 is not met: there is no security administration console. The Appendix D item on authenticating administrators is met through the API alone. This is a deviation to be accepted by the owner, not a detail (follow-up F23).
- Approvals that need a faithful payload preview (BP §8.4 step 2) are harder to do well through raw API calls. NFR-015 (clear findings and approvals) is untested with real users.
- No TLS. That is acceptable on loopback only.
- Route permissions use roles only. A grant narrowed to one system still passes a route check on the role alone. Taking grant scopes into account is in progress.
- Three routes borrow the closest existing permission because identity has no exact one: health and the OpenAPI document use `registry.read`, and kill-switch status uses `killswitch.engage`. So an auditor can read the audit log and cannot read the kill-switch state, which BP §11.2 says should stay visible. Dedicated permissions are not defined.
- Every authenticated request costs a hash computation, a short database write and an audit append (two for a state-changing request), because a bearer token is checked on each request and there is no session. The audit log grows with traffic.
- The rate limiter is in process memory. It resets on restart and does not span processes. The address budget is per client address as the server sees it; behind a proxy all clients share one.
- A caller who knows a real token id and sends wrong secrets writes one audit record per attempt, within the address budget (ADR-0004).

## Why this default is reversible
Seam: the service classes are framework-free and receive their dependencies as constructor arguments; `ciso.api` is a thin layer that authenticates, checks permission, validates and calls a service. To change web framework, rewrite the routes in `ciso.api`. A console, when chosen, talks only to the API. The bind address is a settings value behind an explicit flag.

## Evidence needed to make this final
- Who uses the platform, from where, and through which remote access path (BP §10.2; ADR-0015).
- The identity system and session model (OD-03).
- The employee interface decision: portal, an existing chat platform or other; authentication, notification policy and self-service scope (OD-12).
- The per-request approval UX for external inference (OD-14).
- The owner's decision on when the console required by §12.1 is built.

## Consequences
- The platform is operable locally through an authenticated API.
- Remote and multi-user access is blocked until ADR-0004 and ADR-0015 are closed.
- A console decision should be taken together with OD-12, so the admin console and any employee portal are decided once. When a console exists, it must treat all registry and finding content as untrusted input.
