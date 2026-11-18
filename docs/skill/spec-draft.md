# AI and Agent Security Governance: specification (draft)

Status: APPROVED by delegation, 2026-11-18. The owner asked the coordinator to decide;
the decisions are in section 10 and each can be reversed by the owner. It replaces the scope of
`docs/reference/blueprint-v1.0.txt` (a CISO for the whole company) with the scope below.
The control-plane code already built stays; what happens to each part is in section 8.

Facts about the assistant environment in this draft come from reading the vendor's
documentation on 2026-11-18. None was tested in the company's environment. Items marked
UNVERIFIED must be tested before the design depends on them (section 9).

## 1. Purpose

One security governance and monitoring layer for the company's AI activity. It covers:

1. Organizational AI systems: company LLM applications, bots, agents, automated workflows.
2. User-operated AI systems: the agents, bots and AI workflows individual employees run
   inside the company environment.

For both it answers: who is using AI, which system or agent, what it is doing, which
actions it takes, whether the user and the agent are authorized, whether the code, action
or behaviour is a security risk, and what mitigation or intervention is required.

## 2. Environment, as stated by the owner

- Claude Enterprise plan.
- Machines are domain-joined (to be confirmed by IT).
- Operating systems: unknown, so Windows, macOS and Linux are all in scope.

## 3. Components

| # | Component | Runs where | What it does |
|---|---|---|---|
| C1 | Managed policy pack | Every managed machine, pushed by IT (group policy on Windows, a managed profile on macOS, a system file on Linux) | Forces the company login, allows only company hooks, force-enables the plugin, sets the permission rules users cannot override |
| C2 | Plugin | Inside each user's assistant | Hooks that send every agent action to C3 before it runs and apply the answer (allow, deny, ask). Also carries the skill: the instructions that tell the agent the rules and how to explain a refusal. The skill advises; the hooks enforce |
| C3 | Governance service | A company server | Receives actions and activity, identifies the user and agent, asks the rules engine, records everything in the audit log, creates findings and alerts, runs approvals. This is the existing control plane plus new parts |
| C4 | Central gate adapter | Same server | The Enterprise plan can ask a company endpoint for a verdict on every prompt and tool call, for the whole company, wherever the session runs. C4 is that endpoint. It also pulls session records and the admin activity feed for audit |
| C5 | Sandbox service | An isolated server (containers or small virtual machines) | Receives a code change, runs secret and code scanners and the project's tests with no access to company systems, returns results to C3 |

Why C5 is a separate server: the assistant's own sandbox does not exist on plain Windows,
is off by default elsewhere, and does not cover hook scripts. A service the company runs
works the same for every operating system.

## 4. The funnel, on the owner's example

A new engineer uses an AI coding agent to write and push code.

| Step | What happens | Component |
|---|---|---|
| 1 Identify | Session starts under the forced company login. The session is tied to the engineer and to an agent record | C1, C3, C4 |
| 2 Monitor | Each prompt, command, file edit, connector call and sub-agent goes to the service before it runs, and to the audit log | C2, C4, C3 |
| 3 Inspect | File content is checked before it is written; the whole change is checked before commit and push | C2, C3 |
| 4 Sandbox | Before the push, the change is sent to the sandbox: scanners, then the project's tests, in isolation | C5 |
| 5 Authorize | Fixed rules decide from the person's role, the agent's class, the action type and the target (repository, branch, environment) | C3 |
| 6 Detect | Anything prohibited or risky becomes a finding with its evidence | C3 |
| 7 Report | Alert to the security owner; the engineer sees the reason and the suggested fix in the session | C3, C2 |
| 8 Act | Block, hold for a human approval, or allow. Stronger actions (suspend an agent, revoke its access) need an approval | C3 |

## 5. Coverage, stated honestly

| Case | Identify | Monitor | Block before it happens |
|---|---|---|---|
| Employee's Claude agent, managed machine, company login | Yes | Yes | Yes |
| Claude sessions in the cloud or other company surfaces, company login | Yes | Yes | Yes, through the central gate |
| Company-run agents built on the agent toolkit, company login | Yes | Yes | Yes |
| Company-run agents using API keys | By key and owner record | Only what the agent is built to report | Only through hooks built into that agent |
| Another vendor's assistant or coding agent | No | No | No |
| Personal account, unmanaged machine, locally run model | No | No | No |

For the last two rows the layer does not pretend. It reports them as coverage gaps, lists
what is known from other sources (network controls, admin consoles) where the company has
them, and never reports "clean" for something it cannot see.

Other limits: a hook sees the text of a shell command, not what the command does once it
runs; that is why step 4 exists. The inside of a connector's own server is not visible.

## 6. Rules that do not change

1. Fixed, tested rules decide allow and deny. A model may explain or suggest; it never
   decides and is never a root of trust.
2. Every decision and every action is in the tamper-evident audit log.
3. If a control cannot be consulted, the action stops.
4. Numeric safety settings have no defaults: unset means refuse.
5. A guard is not finished until removing it makes a named test fail.
6. Every milestone is reviewed independently before the next begins.
7. High-impact actions need a human approval, and nobody approves their own request.
8. The operator emergency stop overrides everything.

## 7. Rules of the old blueprint that this replaces (owner approval needed)

| Old rule | Replaced by |
|---|---|
| The mandate is the whole company's security | The mandate is the company's AI activity and its human and autonomous operators |
| No CISO software on employee machines | The plugin and the managed policy pack are installed on managed machines. Nothing else is |
| No inspection of employee AI sessions | Sessions under the company login on managed machines are monitored. Content capture is governed by section 10, decision D1 |
| No vendor or product names; no network code | Both are allowed in C1, C2 and C4 only, which exist to connect to a named product. The core service stays vendor-neutral |
| No process creation anywhere | Allowed in C5 only, which exists to run code in isolation |

## 8. What happens to what is built

| Existing part | Fate |
|---|---|
| Audit log, emergency stop, secret redaction, queue, backup and restore | Kept as is |
| Approvals | Kept as is |
| Rules engine | Kept, extended: judge an observed agent action; match on repository, branch, command type, agent class; accept an agent first seen now |
| Identity | Kept, extended: link an agent to the person operating it; organizational or employee-operated |
| Execution broker and tool registry | Kept for step 8 (the layer's own actions). Its connection to the rest waits until the rules engine is extended |
| API | Kept, extended with the decision endpoint and activity intake |
| External-model gate | Parked. Kept in the tree, not developed further |
| Planned and not built: network scanning, deep-test gates, company asset registry | Dropped |
| Planned and not built: AI inventory, employee AI governance, findings, evidence store, adversarial tests, privacy checks | Kept, moved earlier |

## 9. To verify in the real environment before depending on it

1. VERIFIED 2026-11-18 (Claude Code 2.1.316, Windows, local test): a pre-action hook that
   times out, or crashes with exit code 1, LETS THE ACTION THROUGH. The same hook with
   `"onFailure": "block"` stops the action on timeout. A hook that exits with code 2 stops
   it. The timed-out hook process was ended, not left running. Consequence for C1 and C2:
   every enforcing hook must set `onFailure: "block"`, and the managed policy pack must
   stop users from adding or changing hooks, or the control fails open.
2. VERIFIED 2026-11-18 (same test): the pre-action hook receives `session_id`,
   `tool_name`, `tool_input` (for a shell command: the exact command text),
   `tool_use_id`, `prompt_id`, `permission_mode`, `cwd`, `transcript_path`. The prompt hook
   also receives the prompt text. No field names the person or the account. Consequence:
   the hook cannot say who the user is. On domain-joined machines the hook can read the
   logged-in operating-system account (not yet tested), and the central gate delivers the
   Claude account (from the documentation, not yet tested); S1 joins the two by session.
3. UNVERIFIED: whether the central gate sees file edits, or only shell commands and
   connector calls.
4. UNVERIFIED: that the managed settings reach every surface the company uses (terminal,
   editor extensions, desktop app, cloud sessions).
5. The engineers' operating systems, and that machines are in fact centrally managed.

## 10. Decisions (taken 2026-11-18 by the coordinator at the owner's request)

| # | Decision | Taken | Why |
|---|---|---|---|
| D1 | What is stored about an employee's session | Decisions, action types, targets and findings always. Prompt and code content only when it is the evidence for a finding, redacted, encrypted, with a retention limit that has no default (unset means content is not kept). Employees are told before monitoring starts. Legal counsel confirms before it is switched on for real users | Least data that still proves a finding; matches the blueprint's privacy rules and the employee-monitoring sources found in research |
| D2 | If the central gate's endpoint is unreachable | Fail closed (the action stops). The operator emergency stop can switch the gate to monitor-only, audited | A control that cannot be consulted stops the action (section 6, rule 3) |
| D3 | Who approves held actions | The owner of the system concerned (`system_owner` for that system), else the `executive_risk_owner`; nobody approves their own request or their own agent's action | Existing approval routing (ADR-0016, ADR-0021) |
| D4 | The replaced rules in section 7 | Accepted, each confined to the component named there | The new scope cannot work without them; confining them keeps the core unchanged |
| D5 | Today's uncommitted work | Committed locally as a labelled checkpoint, not as a finished milestone | Reviewed code should not live only on disk; the broker wiring and the old M2 gate are not done and are not claimed |

The owner can reverse any of these. D1 has outside consequences: no real employee is
monitored until legal counsel has confirmed it.

## 11. Milestones

Each ends with a gate: tests, independent review, and a demonstration on the example.

| # | Milestone | Ends when |
|---|---|---|
| S0 | This specification approved; section 9 verified | The owner signs off; each unverified item has a measured answer |
| S1 | Identity and agent registry | A session is tied to a person and an agent record; an unknown agent is recorded as unknown, never as trusted |
| S2 | Decision service and rules for observed actions | A posted action gets allow, deny or ask from fixed rules, audited |
| S3 | Plugin and managed policy pack | On a test machine, a prohibited command by the agent is blocked and the engineer sees why; the user cannot switch it off |
| S4 | Central gate adapter and audit intake | A session outside the plugin's reach is still judged and recorded |
| S5 | Inspection and sandbox | A change with a planted secret and a failing test is stopped before the push |
| S6 | Findings, alerts, enforcement | The finding reaches the security owner; a held action proceeds only after a second person approves |
| S7 | Organizational agents, coverage report, hardening | Company-run agents are registered and governed; gaps are reported; code that tries to manipulate the inspector is contained |

No time estimate is given here: it depends on section 9 and is due at the end of S0.
