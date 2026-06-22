# 17 — Compliance checklist

Use this to check implementation against plan.

## Product canon

- [ ] Product described as routing/evidence/trust/freshness/repair/PR-review system.
- [ ] Not described as agent orchestrator.
- [ ] Not described as AI IDE.
- [ ] External memory described as advisory only.

## Navigation

- [ ] Sidebar: Home, Review, Knowledge Trust, Agents Activity, Reports, Settings, Pro Preview.
- [ ] No top-level Metrics tab.
- [ ] No top-level Command Center tab.
- [ ] No top-level Work tab.
- [ ] No Inspector chat tab.

## Free Core

- [ ] Routing bundle free.
- [ ] Evidence model free.
- [ ] Trust/freshness free.
- [ ] Repair queue free.
- [ ] Basic PR summary free.
- [ ] Basic PR Impact free.
- [ ] Agent report footer contract free.
- [ ] Restore Trust safe action free.
- [ ] Export Debug Bundle free.
- [ ] Export Pro Snapshot free.
- [ ] CLI commands support `--json`.

## Inspector UX

- [ ] One-file launcher exists.
- [ ] Click launcher exists and starts Inspector without a visible terminal.
- [ ] Buttons run allowlisted actions.
- [ ] Copy command is fallback only.
- [ ] Action runs are logged.
- [ ] Simple/Advanced mode setting exists.
- [ ] First-run setup collapses after save and reopens if an upgraded install lacks a completion marker.
- [ ] Home shows metrics as cards.
- [ ] Metric warning states are yellow and critical states are red.
- [ ] Knowledge Trust contains Evidence and Routing.
- [ ] Knowledge Trust contains Trust repair prompt for agent.
- [ ] Static and served Inspector share the same renderer and tabular Trust UI.

## Agents Activity

- [ ] No manual active-agent switch.
- [ ] Agent Registry exists.
- [ ] Active Sessions derived from sessions/heartbeats/locks/reports.
- [ ] Identity includes runtime, instance, operator, session, run, workspace.
- [ ] Safe Queue exists.
- [ ] Parallel Worktrees exists or is planned.
- [ ] Merge Queue exists or is planned.

## Trust system

- [ ] Trust states include Trusted, Needs Recheck, Stale, Suspect, Advisory Memory, Missing Evidence, Conflict, Blocked.
- [ ] Restore Trust does not change source code.
- [ ] Evidence is required to raise trust.
- [ ] External memory cannot raise trust.

## Pro split

- [ ] Free features remain useful.
- [ ] Pro unlocks workflow depth, history, ownership, policy and team governance.
- [ ] Solo Pro at $19/mo + applicable tax per user.
- [ ] 2 activations per user.
- [ ] 7-day offline grace.
- [ ] Team Pro includes agency/client workspaces.
- [ ] Enterprise offline architecture documented but not implemented in V1.

## License/backend

- [ ] Inspector never talks directly to D1/DB.
- [ ] License API returns signed entitlement token.
- [ ] Pro extension bundle is signed and stored in R2.
- [ ] Stripe handles billing/tax/subscriptions.
- [ ] Minimal admin CLI/endpoint planned.

## Embedding

- [ ] File contract documented.
- [ ] CLI contract documented.
- [ ] Local API contract documented.
- [ ] Event stream documented.
- [ ] LICENSE/NOTICE guidance exists.

## QA

- [ ] Source checkout tests pass.
- [ ] Clean install tests pass.
- [ ] Release artifact validates.
- [ ] Team Mode JSON corruption test passes.
- [ ] Benchmark reports have claim-evidence map.
- [ ] Marketing claims exclude preview/blocked claims.
