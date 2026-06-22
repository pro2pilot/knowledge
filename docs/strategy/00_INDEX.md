# Pro2Pilot `.knowledge` 3.2.0 — обновленный пакет документов с учетом конкурентного анализа

Дата: 2026-06-07  
Статус: стратегическое обновление после анализа `Конкурентний ландшафт для fully-implemented .knowledge.md`.

## Главный вывод

Я принимаю конкурентный анализ как правильную базовую рамку: `.knowledge` нужно позиционировать не как AI IDE, не как review bot и не как memory app, а как:

```txt
repo-local knowledge governance layer for coding agents
```

Или в чуть более продуктовой форме:

```txt
.knowledge = repo-local control plane for agent knowledge:
routing + trust/freshness + repair + PR impact + memory bridges + Inspector
```

Критическое уточнение: этот вывод справедлив именно для **fully implemented `.knowledge`**, а не для полуготовой реализации. Пока не закрыты Team Mode, release artifact hygiene, real PR Impact, polished Inspector, memory-provider tests and Pro Inspector shell, нельзя использовать strong market claims.

## Что изменилось относительно предыдущих документов

1. Уточнено позиционирование: `knowledge governance layer for coding agents` вместо общего `AI-company OS`.
2. Уточнены главные конкуренты по слоям:
   - Sourcegraph: deep code intelligence / MCP / enterprise context;
   - Cursor: polished IDE/team agent dashboard;
   - Devin Desktop: agent spaces + shared worktrees;
   - Greptile / Qodo / CodeRabbit / Graphite: PR review and repair workflows;
   - Repomix / gitingest: token/context packers;
   - Mem0 / Graphiti / Letta: memory and temporal knowledge building blocks;
   - Cline / Aider / Serena / PR-Agent: runtime/toolkit/review open-source blocks.
3. Уточнена free/paid граница:
   - Free = strong single-repo local trust/debug + button-first Inspector;
   - Pro Inspector = team/multi-repo governance, policy gates, analytics, audit, team spaces, real PR impact and provider fleet governance.
4. Уточнен memory provider план:
   - Claude MEM bridge не нужен как first-class path;
   - Mem0 OSS = recommended optional universal memory provider;
   - Pinecone = optional vector/cloud provider;
   - Graphiti = Pro/Enterprise temporal graph/provenance;
   - Zep = Pro/Enterprise managed/BYOC memory.
5. Ужесточены требования к интерфейсу: button-first repo cockpit, а не просто static report page.
6. Ужесточен агентский prompt: если хотя бы одна проверка падает, статус не 10/10.

## Файлы пакета

1. `01_competitive_positioning_decision.md` — согласие/несогласие с конкурентным анализом и финальное positioning decision.
2. `02_free_core_strategy.md` — обновленная бесплатная логика `.knowledge`.
3. `03_pro_inspector_strategy.md` — обновленный Pro Inspector как paid governance layer.
4. `04_monetization_and_gTM.md` — цены, packaging, launch motion и market narrative.
5. `05_ui_stack_layers_and_graphs.md` — интерфейс, графы, stack, screens and button-first UX.
6. `06_team_mode_market_guided.md` — Team Mode / multi-worktree как конкурентно важная функция.
7. `07_memory_provider_strategy.md` — Mem0/Pinecone/Graphiti/Zep и deprecation Claude MEM.
8. `08_benchmark_and_marketing_proof.md` — benchmark-исследования для доказательства claims.
9. `09_goal_agent_prompt_competitive_10_10.md` — новый жесткий prompt агенту в режиме цели.
10. `10_current_decision_record.md` — краткий ADR: что теперь считается обязательным.

## Рекомендуемые пути в репозитории

```txt
.knowledge/docs/strategy/00_INDEX.md
.knowledge/docs/strategy/01_competitive_positioning_decision.md
.knowledge/docs/strategy/02_free_core_strategy.md
.knowledge/docs/strategy/03_pro_inspector_strategy.md
.knowledge/docs/strategy/04_monetization_and_gTM.md
.knowledge/docs/strategy/05_ui_stack_layers_and_graphs.md
.knowledge/docs/strategy/06_team_mode_market_guided.md
.knowledge/docs/strategy/07_memory_provider_strategy.md
.knowledge/docs/strategy/08_benchmark_and_marketing_proof.md
.knowledge/docs/strategy/09_goal_agent_prompt_competitive_10_10.md
.knowledge/docs/strategy/10_current_decision_record.md
```

## Definition of Done по стратегии

Проект считается aligned с этим пакетом, если:

- public messaging не обещает `AI IDE` и не пытается выглядеть как Cursor;
- README/landing говорят про repo-local knowledge governance;
- free Inspector реально button-first и полезен без Pro;
- Pro Inspector имеет реальные screens для PR Impact, Repair Board, Team Spaces, Policy Gates, Memory Governance;
- Team Mode проходит multi-worktree tests;
- PR Impact не является заглушкой;
- Mem0 OSS optional bridge работает честно или помечен как runtime-not-installed;
- release artifact чистый и не содержит source checkout мусора;
- benchmark pack генерирует proof для claims.
