# ADR-0015: Deployment, host and network (OPEN)
Status: Proposed (reversible default; owner approval pending)
Decision state: OPEN. The only default is "binds to loopback, no public ports". Everything else waits for Phase 0.
Date: 2026-11-17
Blueprint refs: §3 (register items "Deployment", LEADING DIRECTION, and "Hardware", DEFERRED), §5.2, §10.1, §10.2, §10.3, §10.4, §17.1, §17.2 (office infrastructure dependency), §18 Phase 0 and Phase 1, §19.4 #1, NFR-002, NFR-003, NFR-016, OD-01, OD-16, Appendix C #14

## Context
The leading deployment direction is a single central CISO installation hosted in the company's office, reached through a browser or an existing communication channel, with nothing installed on employee computers (§10.1). §10.2 sets network rules: a restricted server/network segment; no model, database, broker or admin port exposed to the public internet; a controlled access gateway or company-approved remote access path; outbound-initiated TLS from connectors where supported; egress allowlists, especially for the external inference gateway; mTLS or equivalent workload identity between internal services where feasible; the office LAN is not a trust boundary. The physical host, its hardware, UPS sizing, cooling and physical access are unknown (OD-01). The BP's assumption that the company can host and physically secure a machine in its office is not verified (§17.1).

Nothing about the host or network can be decided from inside this repository.

## Options considered
These are the open choices. None is selected.

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Host form: office server, workstation or small rack host (the three forms BP OD-01 lists) | Differ in capacity, noise, power and room for inference hardware | Differ in price and facility needs | Physical access control and tamper resistance differ; the choice must follow the sizing inputs in BP §10.4 |
| Packaging: operating-system services under separate accounts | Few moving parts; isolation by OS accounts and file permissions | Host-specific installation steps | Isolation quality depends on host hardening |
| Packaging: containers on the single host | Repeatable builds; network and filesystem separation per component | A container runtime to patch and secure; image supply chain (BP §11) | Good fit for the five trust domains in BP §5.2 if configured with care |
| Network: dedicated restricted segment with an egress allowlist | Matches BP §10.2 | Needs network equipment and an owner able to configure it | Required direction per the BP; feasibility unknown |
| Remote access: company-approved remote access path or access gateway | Lets administrators work from outside the office | Depends on what the company already runs | Must not turn into a public admin port |

A deployment outside the company office would change a register item marked LEADING DIRECTION and needs its own ADR under BP §3 change control.

## Default chosen for the local build
The control-plane API binds to loopback. No port listens on any other interface. No network client library may be imported outside an allowlist of modules, and that allowlist is empty outside tests, so the build makes no outbound connections. Data lives under `data/` in the working directory.

This is a developer setup. It is not a deployment.

## Why this default is reversible
The bind address is a configuration value and nothing else has been decided. There is nothing to undo.

## Evidence needed to make this final
Phase 0 must supply the following, with evidence:

| Item | BP source |
|---|---|
| Host form, hardware specification, operating system and who administers it | OD-01, §10.4 |
| Physical location, physical access control and cooling | OD-01, §17.1 |
| UPS: present or not, sizing for graceful shutdown, whether a power-state signal is available | §10.3 |
| Network segment for the host; which addresses may reach which ports; who owns the firewall rules | §10.2 |
| Whether outbound traffic can be restricted to an allowlist, and by which control | §10.2, NFR-003 |
| Remote access path for administrators outside the office | §10.2 |
| TLS certificate source for the admin API; feasibility of mTLS or equivalent between internal services | §10.2 |
| Whether any inbound path from the internet (for example webhooks) is acceptable, and how it is authenticated | §10.2 |
| Disk encryption at rest on the host and who holds the recovery key | §11.1, NFR-007 |
| Backup target and recovery expectations | §18 Phase 0, OD-16 |
| The sizing inputs listed in BP §10.4 | §10.4, §15.1 |
| Process-isolation facilities for the five trust domains | §5.2, NFR-016 |
| Time synchronization source and where service-health alerts are sent | NFR-012 |

## Consequences
- The platform cannot be deployed for the organization from this build alone.
- Phase 1 gate items that need a host (restricted runtime, private ports, UPS and graceful-shutdown procedure) stay open.
- "External egress blocked by default" holds at the code level only. It is not enforced by a network control.
- Most other ADRs in this directory list this ADR or OD-01 under "Evidence needed", so this is the decision that unblocks the most others.
