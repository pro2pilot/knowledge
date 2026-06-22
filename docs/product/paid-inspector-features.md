# 02 — Запланированные функции платного Pro2Pilot Inspector

## Назначение файла

Этот файл фиксирует платный product surface для Inspector. Он нужен, чтобы команда не смешивала бесплатную repo-local прозрачность с коммерческим team/governance value.

## Короткая формула платного Inspector

**Pro2Pilot Inspector = human operating surface для agent knowledge state: multi-worktree, multi-agent, multi-repo, PR impact, repair ownership, policies, approvals, history, GitHub App, alerts, team metrics, SSO/RBAC/audit and hosted/private deployment.**

## Главная граница

Free core отвечает на вопросы:

- что агент знает;
- чему можно доверять;
- что stale/suspect;
- что нужно recheck;
- какие команды выполнить дальше.

Paid Inspector отвечает на вопросы:

- кто отвечает за repair;
- как это влияет на PR;
- какие risky/policy-sensitive области затронуты;
- что происходит по нескольким worktrees/agents/repos;
- как это доказать в audit/review;
- как команда/организация управляет этим системно.

## Платные capability-блоки

### 1. Multi-repo Dashboard

**Paid value:** управленческий обзор для leads/platform teams.

Функции:

- все repos в одном workspace;
- repo health score;
- trust distribution;
- stale pressure;
- repair queue pressure;
- PR impact queue;
- policy violations;
- active agents/workspaces;
- latest flow status;
- owner/team mapping;
- repo grouping by product/team/client.

UI:

- `All repos`
- `At risk`
- `Needs repair`
- `PR review`
- `Policy warnings`
- `Team activity`

### 2. Team Mode UI

**Paid value:** collaboration layer поверх team mode.

Функции:

- active agents;
- workspace registry;
- branches/worktrees;
- locks;
- owners;
- stale workspaces;
- branch mismatch warnings;
- dirty worktree warnings;
- last flow status;
- PR status;
- archive/unarchive workspace;
- compare workspace states;
- workspace-to-PR mapping.

UI-кнопки:

- `Enable Team Mode`
- `Register Workspace`
- `Open Workspace`
- `Lock Flow`
- `Release Lock`
- `Generate Team PR Summary`
- `Archive Workspace`
- `Compare Workspaces`

Free boundary: free can show local readonly team context. Paid manages multiple workspaces, owners, comparisons, history and policies.

### 3. PR Impact Graph

**Paid value:** прямой buyer value для tech leads.

Функции:

- changed files → modules;
- changed files → critical paths;
- changed files → trust/freshness buckets;
- changed files → evidence coverage;
- repair queue delta;
- policy overlays;
- suggested reviewer notes;
- risk score;
- visual diff;
- changed curated knowledge files;
- affected docs/wiki links;
- before/after state.

UI-кнопки:

- `Analyze PR`
- `Open Impact Graph`
- `Post GitHub Comment`
- `Suggest Reviewers`
- `Export Risk Notes`
- `Require Recheck`

### 4. GitHub App

**Paid value:** workflow automation inside PR review.

Функции:

- PR comments;
- checks;
- labels;
- reviewer suggestions;
- repair queue links;
- PR summary publishing;
- policy violation checks;
- required status checks;
- “stale knowledge touched” warning;
- “critical path touched” warning;
- optional bot commands in comments.

GitHub checks:

- `knowledge/doctor`
- `knowledge/pr-impact`
- `knowledge/policy`
- `knowledge/repair-queue`
- `knowledge/team-workspace`

### 5. Repair Ownership

**Paid value:** превращает repair queue в командную работу.

Функции:

- assignee;
- owner/team;
- status;
- priority;
- SLA;
- comments;
- history;
- due date;
- linked PR;
- linked GitHub issue;
- exports;
- repair aging dashboard;
- closure rate.

UI modes:

- Kanban;
- table;
- module view;
- PR-linked view;
- stale-only view;
- critical-only view.

### 6. Policy Packs

**Paid value:** commercial review rules for sensitive domains.

Initial policy packs:

1. `runtime-execution`
2. `auth-security`
3. `billing-payments`
4. `data-migration`
5. `secrets-handling`
6. `permissions-rbac`
7. `ai-agent-tools`
8. `compliance-export`
9. `release-readiness`
10. `multi-worktree-safety`
11. `memory-provider-governance`
12. `mcp-tool-risk`

Функции policy pack:

- file/path patterns;
- module categories;
- required evidence;
- required tests;
- required approvals;
- forbidden actions;
- allowed tool policies;
- PR comment template;
- reviewer suggestion logic;
- audit export fields.

### 7. Approval Workflows

**Paid value:** enterprise/team control для risky actions.

Функции:

- approve risky action;
- approve trust raise;
- approve policy exception;
- approve external memory import;
- approve generated knowledge merge;
- approve PR with suspect modules;
- approval history;
- signed export;
- GitHub required check integration.

Approval states:

```text
requested -> approved | rejected | expired | superseded
```

### 8. History & Diffs

**Paid value:** аналитика и audit trail.

Функции:

- trust over time;
- stale half-life;
- module drift;
- repair queue history;
- PR impact history;
- policy violations over time;
- team adoption trend;
- workspace state history;
- before/after diff for knowledge artifacts;
- retention settings by plan.

### 9. Alerts

**Paid value:** командная операционка.

Channels:

- Slack;
- email;
- GitHub comments/checks;
- webhook;
- future: Teams/Discord.

Alert examples:

- critical path touched with suspect knowledge;
- repair SLA breached;
- stale modules exceed threshold;
- team workspace lock stale;
- dirty main branch detected;
- legacy Claude MEM shared across worktrees warning;
- external memory conflict with current evidence.

### 10. SSO / RBAC / Audit

**Paid value:** enterprise requirement.

Функции:

- SAML/OIDC;
- SCIM optional;
- org/workspace roles;
- repo access roles;
- audit export;
- admin policy settings;
- read-only reviewer role;
- service accounts;
- API tokens;
- retention policy.

Roles:

| Role | Purpose |
|---|---|
| Owner | billing, org settings, SSO, retention |
| Admin | repos, policies, GitHub App, team settings |
| Lead | repair ownership, PR impact, approvals |
| Reviewer | PR impact, risk notes, read-only policies |
| Agent Operator | workspace registration, flows, summaries |
| Viewer | read-only dashboards |

### 11. Multi-worktree Control

**Paid value:** team mode paid/team surface.

Функции:

- registry;
- central state;
- workspace comparison;
- active locks;
- branch/head map;
- agent map;
- safe merge checklist;
- stale workspace detection;
- archive workflow;
- PR handoff.

### 12. Cross-repo Knowledge Map

**Paid value:** org/platform buyers.

Функции:

- shared modules across repos;
- duplicated risks;
- dependency map;
- common policy violations;
- common stale areas;
- client/project groupings;
- source-of-truth conflict detection;
- pack coverage.

### 13. Team Metrics / ROI Dashboard

**Paid value:** proves adoption and business value.

Metrics:

- PR coverage rate;
- PRs with knowledge summary;
- repair closure rate;
- stale item age;
- trust trend;
- repeated repo crawl reduction estimate;
- team flow runs;
- active agents;
- policy exceptions;
- time-to-repair;
- critical warnings caught pre-merge;
- adoption by repo/team.

### 14. Hosted / Private / VPC Deployment

**Paid value:** commercial deployment.

Deployment modes:

1. Hosted SaaS.
2. Private cloud.
3. Customer VPC.
4. Air-gapped/self-host enterprise later.

Paid backend responsibilities:

- user/org auth;
- multi-repo indexing metadata;
- repair ownership/history;
- policy packs;
- GitHub App events;
- alerts;
- audit export;
- retention;
- dashboards.

Important: paid backend must not require uploading source code by default. Preferred design: upload metadata, trust artifacts and summaries only, with explicit user controls for source snippets.

### 15. Pack Registry

**Paid value:** marketplace/team standardization.

Функции:

- signed policy/workflow packs;
- version pinning;
- pack compatibility matrix;
- changelog;
- approval before upgrade;
- private org packs;
- partner packs later;
- pack usage metrics.

Pack types:

- policy packs;
- workflow packs;
- stack packs;
- agency/client packs;
- compliance packs;
- migration packs.

### 16. Advanced Memory Provider Governance

**Paid value:** memory governance across teams.

Функции:

- Mem0 and Pinecone provider fleet status across workspaces;
- Graphiti provider card for self-host temporal graph memory;
- Zep provider card for managed/BYOC enterprise memory;
- legacy Claude MEM migration warnings across workspaces;
- MCP memory connector registry;
- warnings when memory is shared across worktrees;
- per-workspace memory path policy;
- external memory provenance;
- memory conflict detection;
- memory import approval;
- memory-to-evidence promotion workflow;
- source-of-truth enforcement;
- reports/metrics inclusion.

### 17. Buttons instead of commands — paid version

Paid Inspector should allow action from UI where safe:

| Button | Behavior |
|---|---|
| `Run release on workspace` | Queues local/runner job with explicit target workspace. |
| `Analyze PR` | Pulls PR changed files and builds impact graph. |
| `Assign repair` | Sets owner/status/SLA. |
| `Post PR summary` | Writes GitHub comment/check. |
| `Require policy approval` | Adds approval requirement. |
| `Archive workspace` | Soft archives workspace state. |
| `Compare with main` | Shows trust/repair/knowledge delta. |
| `Create GitHub issue` | Converts repair item to issue. |
| `Export audit bundle` | Generates signed audit package. |
| `Install connector` | Explicitly installs enabled external connector with license notice. |

## Packaging model

Packaging names are product labels, not entitlement rules in the free package.
Concrete prices, limits, and feature-to-plan bindings must live in the separate
paid Inspector commercial config after they stabilize.

Candidate labels:

- Free / Local Inspector;
- Pro2Pilot Inspector Pro;
- Pro2Pilot Inspector Team;
- Pro2Pilot Inspector Scale;
- Pro2Pilot Inspector Enterprise;
- Policy Packs;
- Workflow Packs;
- Managed Launch;
- Sovereign Deployment.

The free package may show capability previews and contextual conversion
signals, but it must not decide which paid package unlocks a capability.

## Priority roadmap

### P0 — Monetization-ready minimum

1. Interactive Inspector shell.
2. Repo connector / artifact import.
3. Trust graph filters.
4. Repair queue board.
5. PR impact local/GitHub App MVP.
6. Team mode workspace registry UI.
7. Policy pack MVP.
8. Basic user/org/workspace model.
9. Basic billing gate.
10. Export audit/debug bundle.

### P1 — Strong team product

1. Repair ownership history.
2. GitHub checks/comments/labels.
3. Alerts.
4. Team metrics.
5. Multi-repo dashboard.
6. Workspace comparison.
7. Pack registry v1.
8. memory provider governance.
9. API/webhooks.
10. Retention controls.

### P2 — Enterprise expansion

1. SSO/OIDC/SAML.
2. RBAC deep permissions.
3. Audit export.
4. Private/VPC deployment.
5. Cross-repo knowledge map.
6. Advanced policy approvals.
7. SCIM.
8. Dedicated support workflows.
9. Compliance pack library.
10. Partner pack marketplace.

## What not to build first

Do not start paid Inspector with:

- generic workflow canvas competing with n8n/Dify;
- full AI agent builder;
- proprietary runtime replacing Codex/Claude;
- mandatory hosted repo code upload;
- heavy enterprise suite before team value is proven;
- “pretty but shallow” dashboard without PR/review/repair actions.

## Success criteria

The paid Inspector becomes credible when a team can:

1. connect a repo;
2. see trust/freshness/repair state visually;
3. register two or more workspaces/agents;
4. analyze a PR;
5. see changed files mapped to trust and critical paths;
6. assign repair ownership;
7. post reviewer-facing output to GitHub;
8. enforce at least one policy pack;
9. export audit/debug bundle;
10. show adoption/repair/PR coverage metrics to a lead.

