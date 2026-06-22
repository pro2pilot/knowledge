# 05 — UI, stack, layers and graphs after competitive analysis

## Design principle

The Inspector must not feel like a generated HTML report. It must feel like a minimal repo cockpit.

```txt
Button-first, evidence-first, local-first.
```

The user should be able to answer in under 30 seconds:

```txt
What does the agent know?
What is trusted?
What is stale?
What needs repair?
What PR impact exists?
Which memory providers are enabled?
Which worktree/agent is active?
What button should I press next?
```

## Free Inspector layout

```txt
┌──────────────────────────────────────────────────────────────────────────────┐
│ .knowledge Inspector 3.2.0       Repo mode · No cloud · No telemetry         │
│ Repo: pro2pilot/knowledge        Branch: main · Doctor 100/100              │
├───────────────┬──────────────────────────────────────────────────────────────┤
│ Overview      │  Trust  Freshness  Repair  PR Impact  Memory  Team          │
│ Command Center│ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐               │
│ Routing       │ │ 8 safe │ │ 2 stale│ │ 3 open │ │ 1 warn │               │
│ Trust Ledger  │ └────────┘ └────────┘ └────────┘ └────────┘               │
│ Freshness     │                                                              │
│ Repair Queue  │ Next actions                                                 │
│ PR Impact     │ [Run Doctor] [Refresh Release] [Review PR Impact]            │
│ Memory        │ [Toggle Mem0] [Team Status] [Export Debug Bundle]            │
│ Team Mode     │                                                              │
│ Pro Preview   │ Repair Queue                                                  │
└───────────────┴──────────────────────────────────────────────────────────────┘
```

## Pro Inspector layout

```txt
┌──────────────────────────────────────────────────────────────────────────────┐
│ Pro Inspector             Org: Acme      PRs 12 · Repairs 31 · Policies 4   │
├───────────────┬──────────────────────────────────────────────────────────────┤
│ Dashboard     │ Team governance cockpit                                      │
│ Repos         │ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐               │
│ PR Impact     │ │ PR risk│ │ Repair │ │ Policy │ │ Memory │               │
│ Repair Board  │ └────────┘ └────────┘ └────────┘ └────────┘               │
│ Team Spaces   │                                                              │
│ Policies      │ Active PR impact reviews                                     │
│ Memory Gov    │ Changed files → modules → trust → criticality → policy       │
│ Audit         │                                                              │
│ Analytics     │ Team Spaces                                                  │
└───────────────┴──────────────────────────────────────────────────────────────┘
```

## Layer graph

```mermaid
flowchart TB
    Agents[Claude Code / Codex / OpenCode / Cline / Devin / Copilot] --> Core[.knowledge Core]
    Core --> RB[Routing Bundle]
    Core --> Trust[Trust/Freshness]
    Core --> Repair[Repair Queue]
    Core --> PR[PR Summary / PR Impact Preview]
    Core --> Inspector[Free Local Inspector]
    Core --> Mem[Memory Provider Interface]
    Mem --> Mem0[Mem0 OSS]
    Mem --> Pine[Pinecone]
    Mem --> Graphiti[Graphiti Pro]
    Mem --> Zep[Zep Enterprise]
    Core --> Team[Team Mode / Multi-worktree]
    Core --> Snapshot[Pro Snapshot Export]
    Snapshot --> Pro[Pro Inspector]
    Pro --> PRPro[PR Impact Graph]
    Pro --> RepairPro[Repair Board]
    Pro --> Policy[Policy Gates]
    Pro --> TeamPro[Team Spaces]
    Pro --> Audit[Audit / Analytics]
```

## Competitive layer graph

```mermaid
flowchart LR
    Pack[Repomix / gitingest\nContext packing] --> K[.knowledge]
    Memory[Mem0 / Graphiti / Letta\nMemory persistence] --> K
    Runtime[Cline / Aider / Claude / Cursor / Devin\nAgent runtime] --> K
    Review[PR-Agent / Greptile / Qodo / CodeRabbit / Graphite\nPR review] --> K
    Search[Sourcegraph\nDeep code intelligence] --> K
    K --> Free[Free local governance core]
    K --> Paid[Pro Inspector team governance]
```

## Trust graph

```mermaid
flowchart TD
    Code[Current source code] --> Truth[Canonical truth]
    Tests[Current tests] --> Truth
    Evidence[Evidence JSON] --> Checked[Checked knowledge]
    Modules[Module summaries] --> Routing[Routing knowledge]
    Decisions[Decisions] --> Context[Decision context]
    Wiki[Wiki] --> Context
    Sessions[Sessions] --> Context
    External[Mem0 / Pinecone / Graphiti / Zep] --> Advisory[Advisory context only]
    Truth --> Agent[Agent action]
    Checked --> Agent
    Routing --> Agent
    Context --> Agent
    Advisory -. cannot raise trust .-> Agent
```

## PR Impact graph

```mermaid
flowchart TD
    Diff[Git diff] --> Files[Changed files]
    Files --> Modules[Module mapping]
    Modules --> Trust[Trust/Freshness status]
    Files --> Critical[Critical files]
    Trust --> Risk[Impact risk]
    Critical --> Risk
    Repair[Repair queue delta] --> Risk
    Policies[Policy packs] --> Risk
    Memory[Memory provider hints] --> Risk
    Risk --> Notes[Reviewer notes]
    Notes --> Pro[Pro Inspector]
    Notes --> Export[PR comment/export]
```

## Team Mode graph

```mermaid
flowchart TB
    Main[main repo .knowledge] --> Git[Git PR/Merge]
    W1[worktree codex-task-1] --> Git
    W2[worktree claude-task-2] --> Git
    W3[worktree opencode-task-3] --> Git
    TeamRoot[.knowledge-team] --> Registry[registry.json]
    TeamRoot --> Locks[locks]
    TeamRoot --> Events[events.ndjson]
    TeamRoot --> S1[workspace state 1]
    TeamRoot --> S2[workspace state 2]
    TeamRoot --> S3[workspace state 3]
    S1 --> Inspector[Team Mode tab]
    S2 --> Inspector
    S3 --> Inspector
    Inspector --> Pro[Pro Team Spaces]
```

## Button-first action map

| UI button | Free / Pro | Command / action |
|---|---|---|
| Run Doctor | Free | `doctor.js --json` |
| Refresh Release | Free | `flow.js release --json` |
| Review PR Impact | Free preview / Pro full | `pr-impact.js --json` or Pro graph |
| Open Repair Queue | Free / Pro | local queue / assigned board |
| Toggle Mem0 | Free | provider preview/install/disable |
| Memory Governance | Pro | fleet/provider screen |
| Compare Worktrees | Pro | team workspace compare |
| Export Debug Bundle | Free | redacted bundle |
| Export Pro Snapshot | Free → Pro | sanitized snapshot |
| Policy Review | Pro | policy gate evaluation |
| Assign Repair | Pro | board ownership |

## Implementation stack

### Free Inspector

```txt
Static HTML/CSS/vanilla JS
No external assets
Generated from local JSON
Opens as file://
Optional local server only serves same generated UI
```

### Pro Inspector

Preferred:

```txt
React + TypeScript + Vite
```

Minimum acceptable for private preview:

```txt
Dependency-light static shell with real screens, schemas, imports and build/test/lint
```

But it must not stay string-template demo shell forever.

## UI acceptance criteria

Free UI:

- all tabs render;
- all empty states render;
- all error states render;
- all buttons copy valid commands;
- no external assets;
- no local path leaks;
- team-mode data does not corrupt JSON;
- memory provider cards are truthful;
- Pro Preview is honest and non-blocking.

Pro UI:

- real navigation;
- dashboard;
- PR Impact graph;
- Repair Board;
- Team Spaces;
- Policy Gates;
- Memory Governance;
- Audit/History;
- Analytics;
- snapshot import;
- realistic demo data;
- build/test/lint pass.
