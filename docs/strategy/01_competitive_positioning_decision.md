# 01 — Competitive positioning decision для `.knowledge`

## Ответ на вопрос: согласен ли я с конкурентным анализом?

Да, **в основном согласен**. Анализ правильно определяет главное окно: `.knowledge` не должен конкурировать как AI IDE, review bot или generic memory layer. Его лучшая категория:

```txt
knowledge governance layer for coding agents
```

Это точнее, чем более широкий тезис “AI-company OS”. Для общего Pro2Pilot как большого продукта этот тезис может быть полезен, но для `.knowledge` и Pro Inspector лучше использовать более узкое, доказуемое и дифференцирующее позиционирование:

```txt
repo-local knowledge contract and governance cockpit for AI coding agents
```

## С чем согласен полностью

### 1. Нет одного прямого конкурента, который закрывает все слои сразу

У конкурентов есть отдельные сильные части:

- Repomix/gitingest — context packing;
- Mem0/Graphiti/Letta — memory/persistence;
- Cursor/Copilot/Claude Code/Devin/Cline/Aider — execution/agent surfaces;
- Greptile/Qodo/CodeRabbit/Graphite/PR-Agent — PR review;
- Sourcegraph — deep enterprise code intelligence;
- Serena — MCP/semantic toolkit.

Но сочетание:

```txt
repo-local evidence-first trust model
+ token-efficient first-read bundle
+ cross-agent persistent memory bridge
+ repair queue
+ dedicated Inspector UI
+ team/multi-worktree status
```

остается редким и фактически является окном для `.knowledge`.

### 2. Главный market message должен быть не “AI IDE”

Запрещенный messaging:

```txt
AI IDE
another coding assistant
review bot
memory app
chat for your repo
```

Правильный messaging:

```txt
Knowledge governance layer for coding agents.
Repo-local trust, freshness, repair and PR-impact surface.
A knowledge contract that survives whichever agent runtime you use.
```

### 3. Pro Inspector должен продавать governance, а не чат

Платный слой должен быть built around:

- auditability;
- policy gates;
- team/worktree surfaces;
- memory bridge governance;
- PR impact;
- repair ownership;
- analytics;
- push-button operations;
- multi-repo / team dashboards;
- SSO/RBAC/audit later.

Не нужно строить “чат в браузере” как главный платный продукт.

### 4. Button-first Inspector — обязательное отличие

Ключевая фраза:

```txt
Move .knowledge from smart folder to real product.
```

Это достигается не только JSON reports, а через кнопки:

```txt
Run Doctor
Refresh Release
Review PR Impact
Toggle Memory Bridge
Open Repair Queue
Compare Worktrees
Export Debug Bundle
Open Pro Snapshot
```

## Где я уточняю анализ

### Уточнение 1 — Claude MEM нужно заменить на Mem0 OSS

В конкурентном анализе в нескольких местах упоминается `Claude MEM / MCP-style bridge`. После отдельного memory-provider решения правильнее так:

```txt
Claude MEM: legacy-only, not first-class path.
Mem0 OSS: recommended optional universal memory provider.
```

Причина: Mem0 OSS подходит любому агенту, а не только Claude-centered workflow. Claude Code memory можно оставить как read-only compatibility / legacy detection, но не как главный provider.

### Уточнение 2 — multi-worktree больше не уникален сам по себе

Devin/Desktop-like tools уже демонстрируют spaces, shared context and git worktree thinking. Поэтому нельзя продавать Team Mode как “никто такого не делает”. Нужно продавать его как:

```txt
auditable repo-local team-state isolation for agent worktrees
```

Иными словами, отличие не в наличии worktrees, а в том, что `.knowledge` сохраняет trust/repair/PR-impact/state artifacts внутри repo-local governance contract.

### Уточнение 3 — PR Impact должен быть реальным

Greptile, Qodo, CodeRabbit and Graphite уже сильны в review workflows. Если Pro Inspector не делает real PR Impact, paid tier будет слабым.

Minimum PR Impact:

```txt
changed files → modules → trust/freshness → criticality → repair delta → policy warnings → reviewer notes
```

### Уточнение 4 — current implementation не может использовать fully-implemented claims

Анализ сравнивает рынок с **fully implemented `.knowledge`**. Если текущая реализация имеет падающий Team Mode, demo-only Pro Inspector или fake runtime bridge, нельзя писать market claims как факт.

## Финальный positioning

### One-line

```txt
.knowledge is a repo-local knowledge governance layer for AI coding agents.
```

### Developer version

```txt
A first-read routing bundle, trust/freshness ledger, repair queue and local Inspector that make agent repo context visible, refreshable and reviewable.
```

### Team lead version

```txt
Pro Inspector turns local `.knowledge` state into PR impact, repair ownership, policy gates, team/worktree surfaces and memory governance.
```

### Enterprise version

```txt
A local-first, agent-neutral knowledge governance layer with auditable artifacts, provider boundaries, policy-ready reports and optional private deployment paths.
```

## Direct competitor response matrix

| Competitor | Do not compete as | Compete as |
|---|---|---|
| Cursor | better IDE | auditable repo memory behind any IDE/agent |
| Sourcegraph | cheaper deep code search only | lighter repo-shippable trust/freshness/repair layer |
| Devin Desktop | home for every agent | knowledge layer that survives any runtime/team surface |
| Greptile/Qodo | another PR reviewer | broader repo governance with PR impact as one surface |
| CodeRabbit/Graphite | PR workflow clone | repair/trust/memory/team context feeding review |
| Mem0/Graphiti/Letta | memory replacement | governance wrapper around memory providers |
| Repomix/gitingest | context packer | context packer + trust + repair + Inspector |
| Cline/Aider/Claude/Copilot | agent runtime | runtime-neutral knowledge contract |

## Positioning risks

| Risk | Why serious | Mitigation |
|---|---|---|
| Calling it an AI IDE | Cursor/Copilot/Claude/Devin win | Say `agent-neutral knowledge contract` |
| Calling it a PR bot | Greptile/Qodo/CodeRabbit win | Say `PR impact is one governance surface` |
| Calling it memory | Mem0/Letta/Graphiti win | Say `memory is advisory, trust is evidence-first` |
| Weak UI | product remains smart folder | button-first Inspector |
| Weak PR Impact | paid tier loses to review SaaS | implement changed-files → trust/criticality/policy graph |
| Weak Team Mode | Devin/workspace tools win | prove isolated state, locks/events, worktree compare |
| Weak social proof | competitors have stars/customers | benchmark artifacts, demos, case studies |

## Decision

Proceed with this strategy:

```txt
Free .knowledge = repo-local knowledge governance core.
Pro Inspector = team governance cockpit for agent-assisted code work.
Memory providers = optional/advisory bridges.
Team Mode = auditable multi-worktree state isolation.
PR Impact = mandatory paid wedge.
```
