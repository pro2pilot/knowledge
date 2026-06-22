# 03 — Pro Inspector strategy after competitive analysis

## Product category

Pro Inspector is not a chat app and not an IDE. It is:

```txt
team governance cockpit for agent-assisted code work
```

Its job is to turn `.knowledge` local state into team workflows:

```txt
PR impact
repair ownership
policy gates
team/worktree surfaces
memory governance
analytics
audit/history
multi-repo visibility
```

## Why Pro Inspector is necessary

Free `.knowledge` proves the local trust model. Pro Inspector monetizes team operations.

Competitors pressure the paid layer:

| Competitor cluster | Pressure on Pro Inspector |
|---|---|
| Cursor | team agent dashboards, enterprise controls, analytics |
| Sourcegraph | deep code context, MCP/API/CLI, enterprise oversight |
| Devin Desktop | spaces, shared context, Git worktrees, PR visual QA |
| Greptile/Qodo/CodeRabbit | code review quality, rules, issue detection |
| Graphite | review inbox, stacked PRs, merge queue |
| Augment | shared memory/context engine across teams |

Therefore Pro Inspector must be deeper than a demo shell.

## Required Pro screens

### 1. Dashboard

Must show:

- repo/org health;
- active PR impact reviews;
- repair debt trend;
- policy warnings;
- memory provider status;
- active team spaces/worktrees;
- audit events;
- upgrade/license status.

### 2. PR Impact

Must implement real data path:

```txt
git diff → changed files → module map → trust/freshness → critical files → policy packs → reviewer notes
```

Required UI:

- file impact list;
- module impact cards;
- trust/freshness badges;
- critical path warnings;
- repair delta;
- policy gate status;
- generated reviewer note;
- export to GitHub/GitLab comment later.

### 3. Repair Board

Columns:

```txt
Open → Assigned → In Progress → Needs Evidence → Verified → Closed
```

Fields:

- owner;
- status;
- severity;
- affected files/artifacts;
- stale reason;
- recommended command;
- linked PR;
- due date/SLA;
- audit history.

### 4. Team Spaces / Worktrees

Must not just list workspaces. It must show:

- active agents;
- workspace path;
- branch/head;
- lock owner;
- stale lock warnings;
- dirty status;
- PR number;
- last release flow;
- stateRoot vs projectKnowledgeRoot;
- compare workspaces;
- archive workspace.

### 5. Policy Gates

Initial policy packs:

```txt
security-sensitive-code
auth-and-session
billing-and-payments
runtime-execution
database-migrations
secrets-and-signing
external-memory-advisory
team-mode-git-safety
```

Policy decision model:

```txt
allow
warn
needs-review
block
exception-requested
approved
rejected
```

### 6. Memory Governance

Providers:

| Provider | Layer | Pro purpose |
|---|---|---|
| Mem0 OSS | free optional + Pro fleet | version/status drift, local memory reports |
| Pinecone | optional vector/cloud | cloud/vector config and key safety |
| Graphiti | Pro/Enterprise | temporal provenance graph |
| Zep | Pro/Enterprise | managed/BYOC enterprise memory |

Must show:

- provider status;
- provider version;
- license/SBOM;
- enabled repos/workspaces;
- last sync;
- warning if source-of-truth boundary violated;
- unknown license warnings;
- provider drift across team.

### 7. Audit / History

Events:

```txt
repo_connected
snapshot_imported
pr_impact_generated
repair_assigned
repair_closed
policy_gate_triggered
policy_exception_approved
memory_provider_enabled
memory_provider_updated
team_workspace_registered
lock_timeout
export_generated
```

### 8. Analytics

Metrics:

- repair closure rate;
- stale half-life;
- trust bucket trend;
- PR impact reviews completed;
- policy warnings by pack;
- workspaces active;
- memory provider drift;
- no-cloud/local status for repos;
- adoption by repo/team.

## Pro Inspector data contracts

Pro app must consume exported `.knowledge` artifacts, not import core internals directly.

Required schemas:

```txt
models/pro-inspector-snapshot.schema.json
models/pr-impact.schema.json
models/repair-board.schema.json
models/team-spaces.schema.json
models/policy-gates.schema.json
models/memory-governance.schema.json
models/provider-fleet-status.schema.json
models/audit-event.schema.json
```

Required free export command:

```bash
node .knowledge/tools/export-pro-snapshot.js --json
```

## Product quality bar

Pro Inspector can be called credible only if:

- it is runnable;
- build/test/lint pass;
- screens are real and navigable;
- demo data is structured and realistic;
- PR Impact data graph is implemented, not placeholder text;
- Repair Board has state transitions;
- Team Spaces compare and warnings exist;
- Memory Governance shows provider fleet;
- Audit events are visible;
- the app can import a sanitized `.knowledge` snapshot;
- no backend dependency is required for local demo mode.

## Paid roadmap

### P0 — Private preview credibility

- real Pro app shell;
- snapshot import;
- Dashboard;
- PR Impact;
- Repair Board;
- Team Spaces;
- Memory Governance;
- Audit History;
- export/demo pack.

### P1 — Paid pilot

- GitHub App prototype;
- repair ownership;
- policy gates;
- team metrics;
- alerts;
- versioned policy packs.

### P2 — Enterprise

- SSO/OIDC/SAML;
- RBAC;
- audit export;
- private/VPC deployment;
- BYOC memory provider;
- compliance export;
- pack registry signing.

## Competitive non-negotiables

If Pro Inspector lacks these, competitors will win:

| Missing feature | Who wins |
|---|---|
| PR Impact | Greptile/Qodo/CodeRabbit/Graphite |
| Team/agent dashboard | Cursor/Devin |
| Deep code context | Sourcegraph |
| Memory governance | Mem0/Zep/Graphiti/Augment |
| Policy/audit | enterprise suites |
| Clean UX | Cursor/Devin |

## Pro Inspector tagline

```txt
Turn repo-local agent knowledge into team governance.
```

Alternative:

```txt
Review agent-assisted work by trust, freshness, repair debt and PR impact — not just line diff.
```
