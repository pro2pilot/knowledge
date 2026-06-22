# 15 — Goal-mode implementation prompt

You are implementing Pro2Pilot `.knowledge` and Inspector according to the canonical product decisions.

Do not turn `.knowledge` into an agent orchestrator. Implement it as:

```txt
repo-local routing, evidence, trust, freshness, repair and PR-review system for coding agents
```

## Core principles

1. Free Core remains local-first and useful without Pro.
2. Free Inspector is a complete local product, not a teaser.
3. Pro unlocks advanced workflows inside the same Inspector.
4. Agents execute work; `.knowledge` records, verifies, queues, locks, reports and reviews.
5. No manual active-agent switching. Use Agent Registry + Active Sessions.
6. External memory is advisory only.
7. Auto merge is disabled by default.
8. Metrics are cards, not a top-level tab.
9. Command copying is fallback; buttons should run allowlisted local actions.
10. Every public claim must map to evidence.

## Implement navigation

```txt
Home
Review
Knowledge Trust
Agents Activity
Reports
Settings
Pro Preview
```

Remove/avoid top-level:

```txt
Metrics
Command Center
Work
Chat / Simple
```

## Implement Home cards

```txt
Repo Readiness
Knowledge Trust
Evidence Coverage
Routing Status
Repair Pressure
PR Review Status
Agent Activity
Memory Providers
Next Recommended Action
Recent Reports
```

## Implement Agents Activity

Replace active-agent switch with:

```txt
Agent Registry
Active Sessions
Agent Reports
Safe Queue
Locks
Parallel Worktrees
Merge Queue
Handoff
Branch Policy
```

Identity model must include:

```txt
operator_id
agent_runtime_id
agent_instance_id
session_id
run_id
task_id
workspace_id
branch
status
```

## Implement Simple/Advanced

Simple Mode:

```txt
plain-language reports
agent report footer
safe defaults
Restore Trust button when trust incomplete
```

No Inspector chat.

Advanced Mode:

```txt
raw JSON
evidence/routing details
locks/events
branch policy
agent adapters
```

## Implement Agent Report Footer

Settings:

```txt
Off
Compact
Full
Only when trust incomplete
```

Footer includes:

```txt
Knowledge trust state
estimated system tokens used
estimated context saved
Restore Trust action if needed
Open Inspector action
```

## Implement Restore Trust

Safe action:

```txt
health
routing/search refresh
trust/freshness recompute
repair queue refresh
demote stale memory to advisory
plain-language report
```

Do not change source code or merge.

## Implement concurrent work

Default:

```txt
Safe Queue
```

Advanced:

```txt
Parallel Worktrees
```

Future/Pro:

```txt
Controlled Autonomy
```

## Implement Pro-ready architecture

Free release must include:

```txt
Pro Preview
Export Pro Snapshot
license/entitlement schemas
extension slots
feature gates
```

Do not implement fake billing.

Pro decisions:

```txt
$19/mo + applicable tax per user
Stripe
Cloudflare Workers + D1 + R2
2 activations per user
7-day offline grace
no public trial
Team Pro includes agency/client workspaces
```

## Implement embedding contracts

Provide:

```txt
file contract
CLI contract
local API contract
event stream
schemas
```

## QA gates

Run:

```bash
node tools/release-gate.js --json
node tools/self-test-inspector-ui.js
node tools/self-test-team-mode.js
node tools/self-test-team-inspector-json.js
node tools/validate-release-artifact.js dist/knowledge-v3.2.0.zip --json
node benchmarks/run-benchmarks.js --suite all --fixture all --runs 5 --json
```

If any required gate fails, do not report completion.

## Final report

Return:

```txt
1. Status
2. Files changed
3. UX changes
4. Free Core changes
5. Free Inspector changes
6. Agents Activity changes
7. Trust/Evidence/Routing/Repair changes
8. Pro-ready changes
9. Embedding changes
10. QA commands and results
11. Remaining limitations
```
