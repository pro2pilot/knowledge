# 05 — Feature split matrix

## Principle

Free must contain the trust system. Pro must sell workflow depth, history, ownership, policy and team governance.

## Matrix

| Capability | Free Core | Free Inspector | Solo Pro | Team Pro | Enterprise |
|---|---:|---:|---:|---:|---:|
| File layout / schemas | yes | yes | yes | yes | yes |
| CLI `--json` | yes | yes | yes | yes | yes |
| Routing Bundle | yes | visual | advanced views | team views | org/private |
| Evidence model | yes | visual | evidence builder | ownership | custom |
| Trust/Freshness | yes | visual | history/trends | team trends | compliance |
| Repair Queue | data | visual + safe restore | repair planner | ownership board | SLA/export |
| Basic Restore Trust | yes | button | advanced restore | team restore | policy-driven |
| Basic PR Summary | yes | visual | advanced export | team PR report | GitHub/private |
| Basic PR Impact | yes | preview | PR Impact Pro | team PR impact | policy/audit |
| Agent Report Footer | yes | settings | advanced footer | team footer rules | policy |
| Safe Queue basic | yes | visual | advanced local | team dashboard | governed |
| Parallel Worktree visibility | basic | visual | local compare | team compare | org |
| Merge Queue | basic report | visual basic | advanced local | team merge queue | approval/audit |
| Memory Provider status | yes | visual | local governance | fleet status | approved providers |
| Benchmark summary | basic | visual | proof reports | team reports | compliance reports |
| Export Debug Bundle | yes | button | enhanced | team export | enterprise |
| Export Pro Snapshot | yes | button | import/view | team archive | enterprise |
| Policy Packs | no/basic hints | preview | basic packs | team packs/approvals | custom |
| Repair Ownership | no | preview | single-user notes | yes | yes |
| Audit History | raw events | recent actions | local timeline | shared audit | export/retention |
| GitHub App | no | no | maybe later | yes/later | yes |
| SSO/RBAC | no | no | no | no/basic later | yes |
| Offline enterprise file | no | no | no | no | yes later |

## Non-paywall rules

Never paywall:

```txt
routing
evidence
basic trust/freshness
basic repair queue
basic Restore Trust
basic PR summary
basic PR impact
basic local Inspector
basic agent footer
basic Safe Queue
basic Agent Activity visibility
export debug bundle
export Pro snapshot
Mem0/Pinecone status
no-cloud/no-telemetry local mode
CLI --json
embedding contracts
```

Paywall safely:

```txt
advanced PR Impact
risk scoring
policy packs
repair planner
ownership
history/trends
snapshot compare
team dashboards
merge queue workflow
provider fleet governance
audit timeline
approval workflow
GitHub automation
custom reports
client workspaces
Pro benchmark reports
Pro extension actions
```
