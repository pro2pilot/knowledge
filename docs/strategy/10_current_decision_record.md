# 10 — Decision Record: updated `.knowledge` / Pro Inspector direction

## Decision date

2026-06-07

## Decision

Adopt the new competitive positioning:

```txt
.knowledge = repo-local knowledge governance layer for AI coding agents.
Pro Inspector = team governance cockpit for agent-assisted code work.
```

## Accepted conclusions

1. The market is fragmented across context packers, memory layers, agent runtimes, PR/review platforms and deep code intelligence.
2. Fully implemented `.knowledge` has a real window because it can combine the layers into one repo-local contract.
3. The best message is not `AI IDE` or `review bot`, but `knowledge governance layer for coding agents`.
4. Free core must stay useful and local.
5. Pro Inspector must sell governance: PR impact, repair ownership, policy gates, team spaces, audit, analytics, memory governance.
6. Button-first Inspector UX is mandatory.
7. Mem0 OSS replaces Claude MEM as recommended universal optional memory provider.
8. Pinecone remains optional vector/cloud bridge.
9. Graphiti/Zep belong in Pro/Enterprise memory governance.
10. Benchmarks are required before strong public claims.

## Rejected directions

| Rejected direction | Why |
|---|---|
| Build an AI IDE | Cursor/Copilot/Claude/Devin dominate execution surfaces |
| Build a PR bot only | Greptile/Qodo/CodeRabbit/Graphite dominate PR review |
| Build a memory app | Mem0/Letta/Graphiti/Zep are stronger in pure memory |
| Make Claude MEM first-class | too Claude-specific; Mem0 OSS is agent-neutral |
| Publish strong claims before benchmarks | public repo maturity is early |
| Treat Pro Inspector as demo shell | paid layer needs credible governance workflows |

## Required implementation gates

### Gate 1 — Core release

- clean artifact;
- no source checkout leakage;
- install smoke pass;
- doctor 100/100 or justified;
- Team Mode pass;
- Inspector pass;
- no hidden network/telemetry.

### Gate 2 — Competitive free UI

- real tabs;
- Command Center;
- Trust Ledger;
- Repair Queue;
- PR Impact Preview;
- Memory Providers;
- Team Mode;
- Export/Debug;
- Pro Preview.

### Gate 3 — Pro Inspector private preview

- runnable app;
- dashboard;
- PR Impact;
- Repair Board;
- Team Spaces;
- Policy Gates;
- Memory Governance;
- Audit/History;
- snapshot import;
- realistic demo data.

### Gate 4 — Proof pack

- benchmarks;
- raw logs;
- metrics;
- screenshots or DOM proof;
- claim-evidence map;
- README/landing copy based only on measured claims.

## Updated roadmap

### Immediate P0

1. Fix any Team Mode JSON corruption.
2. Validate clean release artifact.
3. Make PR Impact real.
4. Ensure Inspector team-mode test exists.
5. Ensure Pro Inspector imports snapshots and has real screens.
6. Ensure Mem0/Pinecone provider safety.

### P1

1. GitHub App prototype.
2. Repair ownership state.
3. Policy packs v1.
4. Provider fleet status.
5. Benchmark pack.
6. Marketing proof pack.

### P2

1. SSO/RBAC.
2. Audit export.
3. Alerts.
4. Graphiti/Zep deeper integrations.
5. Private/VPC deployment path.
6. Pack registry.

## Final product claim after implementation

```txt
.knowledge makes AI-agent repo context visible, refreshable and reviewable.
Pro Inspector turns that local state into team governance: PR impact, repair ownership, policy gates, memory governance and worktree coordination.
```
