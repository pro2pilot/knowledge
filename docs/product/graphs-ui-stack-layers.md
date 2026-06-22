# 04 — Графы, UI, кнопки, стек и слои `.knowledge 3.2.0`

## Назначение файла

Этот файл описывает визуальную систему `.knowledge 3.2.0`: как устроены режимы, какие графы должен показывать Inspector, какие кнопки заменяют команды, какой стек нужен и как слои взаимодействуют между собой.

## Общая UI-идея

Интерфейс должен быть минималистичным, плотным и “операционным”, вдохновленным текущим стилем Pro2Pilot Inspector:

- темная/нейтральная рабочая поверхность;
- карточки с ясными статусами;
- graph-first center;
- правый detail panel;
- верхний command/action strip;
- минимум декоративности;
- максимум trust, risk, next action;
- free/paid граница встроена аккуратно: free показывает локальную правду, paid открывает командное управление.

## Информационная архитектура Inspector

```mermaid
flowchart LR
    A[Home / Readiness] --> B[Routing]
    A --> C[Trust]
    A --> D[Repair]
    A --> E[PR Impact]
    A --> F[Team Mode]
    A --> G[Policies]
    A --> H[Metrics]
    A --> I[Settings]

    B --> B1[Routing Bundle]
    B --> B2[Source-of-truth Order]
    B --> B3[Recommended First Reads]

    C --> C1[Trust Graph]
    C --> C2[Why Not Trusted]
    C --> C3[Stale Items]
    C --> C4[Critical Files]

    D --> D1[Repair Queue]
    D --> D2[Repair Board]
    D --> D3[Repair Exports]

    E --> E1[Changed Files]
    E --> E2[Affected Modules]
    E --> E3[Critical Path Overlay]
    E --> E4[Reviewer Notes]

    F --> F1[Workspace Registry]
    F --> F2[Agents]
    F --> F3[Branches / Worktrees]
    F --> F4[Locks / Events]

    G --> G1[Policy Packs]
    G --> G2[Approvals]
    G --> G3[Exceptions]

    H --> H1[Doctor]
    H --> H2[Flow Runs]
    H --> H3[Trust Trend]
    H --> H4[Repair Closure]

    I --> I1[Local Paths]
    I --> I2[External Memory]
    I --> I3[GitHub App]
    I --> I4[License / Provenance]
```

## Архитектура системы

```mermaid
flowchart TB
    subgraph Repo[Target Repository / Worktree]
        Code[Source code]
        Tests[Tests]
        KCurated[Branch-local curated knowledge\nmodules / evidence / wiki / decisions]
        KRuntimeRepo[Repo-local runtime state\nmaintenance / metrics / search / inspector]
    end

    subgraph Core[.knowledge Core]
        Tools[Node tools]
        Flow[flow.js]
        Doctor[doctor.js]
        Search[local search]
        Graphs[Mermaid graph renderer]
        StaticInspector[Static local Inspector]
        AgentIntegrations[Codex / Claude Code / OpenCode integrations]
    end

    subgraph Team[team mode Team Root - optional]
        Registry[registry.json]
        RepoState[repos/<repoId>/repo.json]
        WorkspaceState[workspaces/<workspaceId>/state]
        Locks[locks]
        Events[events/*.ndjson]
    end

    subgraph Paid[Pro2Pilot Inspector Paid - optional]
        WebApp[Interactive web app]
        Backend[Hosted/private backend]
        DB[(Postgres)]
        GitHubApp[GitHub App]
        Alerts[Slack / Email / Webhooks]
        PolicyPacks[Policy Pack Registry]
    end

    subgraph External[Optional memory providers / tools]
        Mem0[Mem0 OSS]
        LegacyClaude[Legacy Claude MEM artifacts]
        MCP[MCP servers]
        Pinecone[Pinecone local/cloud]
    end

    Code --> Flow
    Tests --> Flow
    KCurated --> Flow
    Flow --> KRuntimeRepo
    Flow --> StaticInspector
    Flow --> Search
    Flow --> Graphs
    Doctor --> KRuntimeRepo
    Tools --> AgentIntegrations

    Flow -->|team mode| WorkspaceState
    WorkspaceState --> Registry
    Flow --> Locks
    Flow --> Events

    StaticInspector -->|local artifacts| KRuntimeRepo
    WebApp -->|imports metadata| KRuntimeRepo
    WebApp -->|team metadata| Team
    WebApp --> Backend
    Backend --> DB
    Backend --> GitHubApp
    Backend --> Alerts
    Backend --> PolicyPacks

    Mem0 -. optional advisory provider .-> Flow
    LegacyClaude -. legacy advisory only .-> Flow
    MCP -. optional bridge .-> Flow
    Pinecone -. optional bridge .-> Flow
```

## Source-of-truth graph

```mermaid
flowchart TD
    A[Current source code] --> B[Current tests]
    B --> C[.knowledge/evidence/*.json]
    C --> D[.knowledge/modules/*.json]
    D --> E[.knowledge/decisions.json]
    E --> F[.knowledge/wiki/*.md]
    F --> G[.knowledge/sessions/*]
    G --> H[External retrieved memory]

    A -. beats .-> D
    B -. beats .-> F
    C -. can raise trust .-> D
    H -. cannot override .-> A
    H -. cannot raise trust alone .-> C
```

Правило UI: этот граф должен быть постоянно доступен как explainability modal. Пользователь должен понимать, почему Inspector не доверяет summary без source/test evidence.

## Free vs Paid surface

```mermaid
flowchart LR
    subgraph Free[Free Local Inspector]
        F1[Single repo]
        F2[Static local HTML]
        F3[Trust + freshness]
        F4[Repair queue JSON]
        F5[PR summary markdown]
        F6[Command copy buttons]
        F7[Basic team context readonly]
    end

    subgraph Paid[Paid Inspector]
        P1[Multi-repo dashboard]
        P2[Interactive trust graph]
        P3[Repair ownership]
        P4[PR impact graph]
        P5[GitHub App]
        P6[Policy packs]
        P7[History + alerts]
        P8[SSO/RBAC/audit]
        P9[Hosted/private/VPC]
    end

    F1 --> P1
    F3 --> P2
    F4 --> P3
    F5 --> P4
    F6 --> P5
    F7 --> P7
```

## team mode / team mode topology

```mermaid
flowchart TB
    Main[repo-main/.knowledge\ncanonical curated knowledge]

    subgraph Worktrees[Git worktrees / branches]
        W1[worktrees/codex-task-1/.knowledge\nbranch-local curated knowledge]
        W2[worktrees/claude-task-2/.knowledge\nbranch-local curated knowledge]
        W3[worktrees/opencode-task-3/.knowledge\nbranch-local curated knowledge]
    end

    subgraph TeamRoot[../.knowledge-team]
        R[registry.json]
        Repo[repos/<repoId>/repo.json]
        WS1[workspaces/codex-task-1/state]
        WS2[workspaces/claude-task-2/state]
        WS3[workspaces/opencode-task-3/state]
        L[locks]
        E[events/YYYY-MM-DD.ndjson]
    end

    Main -->|git worktree add| W1
    Main -->|git worktree add| W2
    Main -->|git worktree add| W3

    W1 -->|flow writes runtime| WS1
    W2 -->|flow writes runtime| WS2
    W3 -->|flow writes runtime| WS3

    WS1 --> R
    WS2 --> R
    WS3 --> R
    R --> Repo
    Repo --> L
    Repo --> E

    W1 -->|PR merge curated knowledge| Main
    W2 -->|PR merge curated knowledge| Main
    W3 -->|PR merge curated knowledge| Main
```

## Runtime flow graph

```mermaid
sequenceDiagram
    participant User
    participant Inspector
    participant Flow as flow.js
    participant Git as git-context
    participant Store as json/team-store
    participant Repo as targetRoot
    participant State as stateRoot

    User->>Inspector: Click Run Release
    Inspector->>Flow: flow release --json
    Flow->>Git: detect branch/head/worktree/dirty
    Flow->>Store: acquire lock
    Flow->>Repo: scan code/tests/curated knowledge
    Flow->>State: write routing/search/metrics/inspector
    Flow->>Store: append events
    Flow->>Store: release lock
    Flow-->>Inspector: JSON result + context
    Inspector-->>User: Health, warnings, next actions
```

## PR impact workflow graph

```mermaid
flowchart TD
    A[PR opened / updated] --> B[Detect changed files]
    B --> C[Map files to modules]
    C --> D[Overlay trust buckets]
    D --> E[Overlay freshness]
    E --> F[Overlay critical paths]
    F --> G[Check repair queue delta]
    G --> H[Apply policy packs]
    H --> I{Risk acceptable?}
    I -->|yes| J[Generate reviewer notes]
    I -->|no| K[Require recheck / approval]
    J --> L[Post GitHub comment / export markdown]
    K --> L
```

## Memory provider bridge graph

```mermaid
flowchart LR
    M0[Mem0 OSS recommended optional provider] --> R[Memory provider registry]
    Legacy[Legacy Claude MEM artifacts] -. migration only .-> R
    MCP[MCP memory server] --> R
    Pine[Pinecone local/cloud] --> R

    R --> S[Status + provenance]
    S --> M[Reports / metrics]
    S --> I[Inspector Memory Providers panel]

    S -. advisory only .-> KB[.knowledge knowledge graph]
    KB --> T[Trust engine]

    Code[Current code] --> T
    Tests[Current tests] --> T
    Evidence[Evidence] --> T

    S -. cannot override .-> Code
    S -. cannot raise trust alone .-> Evidence
```

Team mode warning:

```mermaid
flowchart TD
    A[Team mode enabled] --> B{provider runtime under stateRoot?}
    B -->|yes| C[Show healthy]
    B -->|no or legacy shared| D[Show advisory warning]
    D --> E[Offer Mem0/Pinecone status and legacy migration note]
    E --> F[Write receipt or migration note with explicit user approval]
```

## UI layout

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Pro2Pilot .knowledge Inspector                    repo/team · branch · agent │
├───────────────┬───────────────────────────────────────────────┬──────────────┤
│ Left nav      │ Main graph / board / table                    │ Detail panel │
│               │                                               │              │
│ Readiness     │  Trust graph / PR impact / Team map           │ Selected     │
│ Routing       │                                               │ module/file  │
│ Trust         │  Filters: trusted stale suspect critical      │              │
│ Repair        │                                               │ Why not      │
│ PR Impact     │  Command strip: Run Doctor · Release · PR     │ trusted      │
│ Team Mode     │                                               │              │
│ Policies      │                                               │ Evidence     │
│ Metrics       │                                               │ Next action  │
│ Settings      │                                               │ Buttons      │
└───────────────┴───────────────────────────────────────────────┴──────────────┘
```

## Основные кнопки и режимы

### Global command strip

| Button | Free/Paid | Действие | CLI/API |
|---|---|---|---|
| `Run Doctor` | Free | Проверить health. | `doctor.js --json` |
| `Run Import` | Free | Первичный импорт/маршрутизация. | `flow.js import --json` |
| `Run Release` | Free | Полный refresh. | `flow.js release --json` |
| `Build Inspector` | Free | Пересобрать static UI. | `build-visual-inspector.js --json` |
| `Search` | Free | Локальный поиск. | `search-knowledge.js` |
| `Generate PR Summary` | Free | Markdown summary. | `generate-pr-summary.js --json` |
| `Export Debug Bundle` | Free | Local zip without secrets. | `export-debug-bundle.js --json` |
| `Enable Team Mode` | Free/Paid | Включить team mode явно. | `team-init.js`, `workspace-register.js` |
| `Analyze PR` | Paid | Interactive PR impact. | backend/GitHub App |
| `Assign Repair` | Paid | Owner/status/SLA. | paid backend |
| `Post GitHub Comment` | Paid | Publish PR impact. | GitHub App |
| `Require Approval` | Paid | Approval workflow. | paid backend |
| `Check Memory Providers` | Free/Paid | Mem0/Pinecone status and legacy migration note. | `memory-provider.js status-all --json` |

### Readiness mode

Purpose: стартовая панель.

Shows:

- doctor score;
- last flow;
- routing status;
- trust distribution;
- repair count;
- stale count;
- critical warnings;
- branch/worktree warning;
- next action.

Buttons:

- `Run Doctor`
- `Run Release`
- `Open Repair Queue`
- `Copy Agent Start Prompt`

### Routing mode

Purpose: показать, что агенту читать первым.

Shows:

- routing bundle;
- first-read path;
- module map;
- source-of-truth order;
- “why this route” explanation.

Buttons:

- `Rebuild Routing`
- `Copy First Read`
- `Open Source Files`

### Trust mode

Purpose: trust/freshness operating surface.

Shows:

- graph by module;
- buckets;
- stale overlays;
- evidence coverage;
- why-not-trusted;
- required tests.

Buttons:

- `Filter suspect`
- `Filter stale`
- `Show evidence`
- `Create repair item`
- `Copy recheck command`

### Repair mode

Purpose: actionable knowledge debt.

Free:

- local queue table;
- copy command;
- export markdown.

Paid:

- Kanban;
- owner/status/SLA;
- comments/history;
- GitHub issue sync.

Buttons:

- `Repair selected`
- `Assign owner`
- `Create GitHub issue`
- `Export queue`

### PR Impact mode

Purpose: review AI-assisted changes.

Free:

- markdown preview;
- changed files if local git data available;
- affected modules and warnings.

Paid:

- interactive graph;
- GitHub App;
- labels/checks/comments;
- policy overlays.

Buttons:

- `Analyze PR`
- `Generate reviewer notes`
- `Post comment`
- `Require recheck`

### Team Mode

Purpose: multi-worktree/multi-agent coordination.

Free:

- current mode;
- repoId;
- workspaceId;
- agentId;
- branch/head;
- lock owner;
- warnings;
- copy commands.

Paid:

- active workspaces;
- compare states;
- owner/team assignment;
- archive flow;
- GitHub PR mapping;
- history.

Buttons:

- `Team Init`
- `Register Workspace`
- `Team Status`
- `Worktree Status`
- `Lock Flow`
- `Archive Workspace`
- `Compare Workspaces`

### Policies mode

Purpose: governance overlays.

Free:

- advisory/basic policy warnings from local config.

Paid:

- policy packs;
- approval workflows;
- exceptions;
- audit export.

Buttons:

- `Apply policy pack`
- `Request approval`
- `Export policy report`

### Memory Providers mode

Purpose: external memory must be visible and subordinate.

Shows:

- Mem0 OSS status;
- Pinecone status;
- legacy Claude MEM migration warning when detected;
- MCP memory connectors;
- source path;
- version;
- license/provenance;
- isolated/shared warning;
- last sync;
- conflicts.

Buttons:

- `Check status`
- `Enable connector`
- `Disable connector`
- `Open license`
- `Export provenance`

## Стек

### Free core stack

| Layer | Recommended stack | Notes |
|---|---|---|
| CLI tools | Node.js, plain JS | Already aligned with current repo. |
| Data | JSON, Markdown, NDJSON | Human-reviewable, Git-friendly. |
| Static Inspector | HTML/CSS/vanilla JS or lightweight bundled JS | Must open locally without backend. |
| Graphs | Mermaid `.mmd`, JSON graph data | Good for docs and GitHub rendering. |
| Search | Local JSON index | No remote dependency. |
| Git helpers | Node child_process `git` wrapper | Must quote paths safely. |
| Tests | Node test runner / custom self-tests | Include temp repos/worktrees. |

### Paid Inspector stack

| Layer | Recommended stack | Reason |
|---|---|---|
| Frontend | React + TypeScript + Vite | Fast dashboard iteration. |
| Graph UI | React Flow or Cytoscape.js | Trust/PR/team graph. |
| Tables | TanStack Table | Repair queues, PRs, repos. |
| Backend | Node.js/TypeScript | Shared ecosystem with core. |
| DB | Postgres | Multi-tenant, audit, history. |
| Queue | BullMQ/Redis or managed queue | GitHub events, PR analyses, alerts. |
| Auth | OIDC/SAML provider integration | Enterprise readiness. |
| GitHub | GitHub App | PR comments/checks/labels. |
| Deployment | SaaS first, private/VPC later | Faster validation. |

### Data layers

```mermaid
flowchart TB
    L1[Layer 1: Source repo\ncode/tests/git] --> L2[Layer 2: Curated knowledge\nmodules/evidence/wiki/decisions]
    L2 --> L3[Layer 3: Runtime generated state\nrouting/search/metrics/inspector]
    L3 --> L4[Layer 4: Team state\nregistry/workspaces/locks/events]
    L4 --> L5[Layer 5: Paid workflow state\nownership/history/policies/alerts]
    L5 --> L6[Layer 6: Audit/export/reporting]
```

## Function / feature / mode descriptions

| Mode | Short description |
|---|---|
| Repo-local mode | Default mode. `.knowledge` lives in one repo and writes runtime state into that repo-local `.knowledge`. |
| Team Mode / team mode | Explicit mode for multi-worktree/multi-agent work with shared team registry and separated workspace states. |
| Inspector Free | Static local surface for trust/debug/repair/search/PR preview. |
| Inspector Pro | Advanced local/solo UI, interactive graphs, local PR impact and enhanced exports. |
| Inspector Team | Multi-worktree/team dashboard, GitHub App, repair ownership, team metrics. |
| Inspector Enterprise | Multi-repo, SSO/RBAC/audit, private/VPC, advanced policy and compliance exports. |
| Memory provider interface | Mem0/Pinecone optional connectors; legacy Claude MEM advisory-only migration note; provider status appears in reports/metrics. |
| Policy Pack mode | Overlay rules for sensitive areas such as auth, billing, runtime execution and MCP tools. |
| PR Impact mode | Maps changed files to modules/trust/freshness/evidence/critical paths and reviewer notes. |
| Repair mode | Converts stale/suspect knowledge into queue items and, in paid, owned team work. |

## Минимальный UI DoD для 3.2.0

- Home/readiness view works.
- Trust graph/table works.
- Repair queue works.
- Routing bundle view works.
- PR summary preview works.
- Team mode panel works.
- Command center exists.
- Memory Providers panel exists.
- All buttons either execute through explicit local runner or copy exact command.
- Free/payed locked actions are clearly labeled, not hidden.
- Static local Inspector still works without server.
- Paid UI can be scaffolded separately without breaking core.

