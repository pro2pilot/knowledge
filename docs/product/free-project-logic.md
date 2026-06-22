# 01 — Бесплатная логика проекта `.knowledge`

## Назначение файла

Этот файл фиксирует, что должно входить в бесплатную, open-core и repo-local часть `.knowledge`. Его можно добавить в проект как продуктовый ориентир и как guardrail для будущей разработки: бесплатный слой должен быть полезным сам по себе, а не выглядеть как обрезанная демо-версия платного Inspector.

## Короткая формула бесплатного слоя

**`.knowledge Free Core` = локальный control plane для одного репозитория, который дает агентам и людям first-read routing, trust/freshness, repair queue, scoped search, source-of-truth rules, PR summary, базовый Visual Inspector, local metrics и agent integrations без обязательного облака, логина, телеметрии и hosted backend.**

## Непереговорные принципы

| Принцип | Что означает в реализации | Что нельзя делать |
|---|---|---|
| Local-first | Все базовые артефакты создаются и читаются локально из репозитория. | Требовать cloud account для базового flow. |
| Repo-native | `.knowledge/` лежит рядом с кодом, может ревьюиться и версионироваться. | Прятать основной state только в внешней БД. |
| No telemetry by default | Никакой фоновой отправки данных. Update check только вручную или явно включенный advisory режим. | Автоматически отправлять repo paths, snippets, metrics. |
| Source of truth discipline | Code > tests > evidence > modules > decisions > wiki > sessions > external memory. | Поднимать trust только на основе summary или LLM-ответа. |
| Strong free Inspector | Free Inspector показывает реальные проблемы и next actions. | Делать Inspector пустым teaser’ом. |
| CLI and JSON | Все ключевые команды имеют пригодный для automation `--json`. | Оставлять важный результат только в human text output. |
| Portable paths | Windows/PowerShell, пробелы и кириллица в путях поддерживаются тестами. | Полагаться на symlink как обязательный механизм. |
| Explicit memory providers | Mem0 OSS/Pinecone/MCP-memory are optional advisory bridges. Claude MEM is legacy migration data only. | Давать external memory право перекрывать code/tests/evidence. |

## Бесплатные capability-блоки

### 1. Install Health

**Цель:** сразу ловить плохую установку.

Минимальная логика:

- проверить наличие `.knowledge/Quick-Start.md`, `.knowledge/tools/flow.js`, `.knowledge/tools/doctor.js`, templates, docs;
- проверить Node version;
- проверить nested `.git` warning;
- проверить права записи для runtime folders;
- проверить корректность path resolution;
- вывести human summary и `--json`.

UI-кнопки:

- `Run install check`
- `Fix missing folders`
- `Copy setup command`
- `Open Quick-Start`

### 2. Repo-local artifact model

**Цель:** сделать `.knowledge` понятным и ревьюируемым.

Бесплатно должны быть видны:

```text
.knowledge/
  Quick-Start.md
  AGENTS.md / CLAUDE.md integration helpers
  modules/
  evidence/
  wiki/
  decisions.json
  sessions/
  maintenance/
    routing_bundle.json
    repair_queue.json
    pr_summary.md
    quality_report.json
    graphs/
  metrics/
  search/
  inspector/
```

Правило:

- curated artifacts можно коммитить;
- generated/runtime artifacts должны быть явно классифицированы: tracked, generated, ignored, local-only;
- Free Inspector обязан показывать эту классификацию.

### 3. Routing Bundle View

**Цель:** агент не должен начинать с хаотичного repo crawl.

Бесплатная логика:

- `routing_bundle.json` как first operational read после setup/import;
- readable view в Inspector;
- source-of-truth order;
- recommended next files;
- module map;
- warnings по suspect/stale modules;
- кнопка `Rebuild routing bundle`.

CLI:

```bash
node .knowledge/tools/build-routing-bundle.js --json
node .knowledge/tools/flow.js import --json
node .knowledge/tools/flow.js release --json
```

### 4. Trust + Freshness Buckets

**Цель:** пользователь видит, чему можно доверять, а что требует проверки.

Бесплатные buckets:

- `trusted`
- `near_trusted`
- `routing_trusted`
- `advisory_only`
- `suspect`
- `low_confidence`
- `stale`
- `needs_recheck`

Для каждого модуля Inspector должен показывать:

- текущий bucket;
- confidence;
- freshness status;
- evidence coverage;
- linked source files;
- linked tests;
- last checked timestamp;
- why-not-trusted explanation.

Нельзя:

- разрешать manual “Mark trusted” без evidence gate;
- скрывать suspect/stale за красивым score;
- поднимать trust из external memory.

### 5. Why Not Trusted

**Цель:** убрать магию trust score.

Для каждого low-trust объекта показывать причины:

- missing evidence;
- stale source files;
- missing tests;
- low confidence ingest;
- broken wiki link;
- source file moved/deleted;
- generated summary without code-backed proof;
- external memory only;
- conflict between module summary and current code.

UI-кнопки:

- `Show evidence`
- `Show changed files`
- `Generate repair task`
- `Copy recheck command`

### 6. Repair Queue

**Цель:** knowledge debt становится actionable work.

Бесплатная repair queue должна включать:

- priority;
- subject;
- affected artifacts;
- affected source files;
- reason;
- suggested command;
- owner optional/local-only;
- status local-only: `open`, `in_progress`, `blocked`, `done`, `wontfix`;
- export to markdown.

UI-кнопки:

- `Repair selected`
- `Copy repair command`
- `Open affected module`
- `Export repair queue`

Важно: в free режиме это локальная очередь без командной синхронизации, SLA, comments history и GitHub App automation. Эти части уходят в paid.

### 7. Stale Items

**Цель:** агент не должен доверять старым summaries.

Бесплатно показывать:

- artifact;
- stale reason;
- source files changed since artifact;
- affected module;
- recommended recheck;
- whether stale blocks trust.

UI-кнопки:

- `Recheck stale item`
- `Open source`
- `Copy command`

### 8. Critical Files / Critical Paths

**Цель:** risky areas не должны быть невидимыми.

Бесплатно:

- critical/important files list;
- mapping file → module;
- evidence coverage;
- trust bucket;
- changed since last evidence;
- recommended tests.

Примеры critical categories:

- auth;
- billing;
- runtime execution;
- data migration;
- permissions;
- agent/tool execution;
- secrets;
- deployment;
- observability.

Paid expansion: interactive critical-path explorer, overlays for PR impact, policies, owners and approvals.

### 9. Wiki Graph

**Цель:** documentation context становится navigable.

Бесплатно:

- typed links;
- broken links;
- orphan pages;
- module-to-wiki relations;
- graph data generated as JSON/Mermaid;
- static Inspector visualization.

UI-кнопки:

- `Build wiki graph`
- `Show orphan pages`
- `Copy fix command`

### 10. Search Preview / Local Search

**Цель:** пользователь не обязан открывать raw JSON.

Бесплатно:

- локальный search index;
- search scopes: `project`, `templates`, `cookbook`, `all`;
- index stats;
- last build timestamp;
- result type badges: module/evidence/wiki/session/template/cookbook;
- no remote search by default.

CLI:

```bash
node .knowledge/tools/search-knowledge.js "query" --scope=project --json
node .knowledge/tools/search-knowledge.js "query" --scope=cookbook --json
node .knowledge/tools/build-search-index.js --json
```

### 11. PR Summary Preview

**Цель:** дать reviewer-facing summary без paid dependency.

Бесплатно:

- generate `.knowledge/maintenance/pr_summary.md`;
- show markdown preview in Inspector;
- changed files;
- affected modules;
- trust buckets;
- repair queue delta;
- critical files touched;
- recommended reviewer notes;
- copy/export.

Paid expansion:

- visual diff;
- GitHub PR comments;
- labels/checks;
- reviewer suggestions;
- history and team ownership.

### 12. Doctor + Metrics

**Цель:** измеримый readiness check.

Бесплатно:

- `doctor.js` status;
- quality report;
- routing health;
- search health;
- inspector build health;
- estimated orientation token stats;
- metrics JSON and markdown;
- smoke benchmark disclaimers;
- local baseline.

Нельзя:

- обещать универсальное ускорение на всех репозиториях;
- скрывать tiny-repo overhead;
- называть estimates production tokenizer-verified benchmark без проверки.

### 13. Visual Inspector Baseline

**Цель:** бесплатный local Inspector должен быть рабочим.

Free Inspector должен быть:

- static/local HTML;
- без login;
- без hosted backend;
- без team collaboration;
- без persisted historical analytics beyond local files;
- без multi-repo dashboard;
- rebuildable command;
- self-contained для screenshots/demos/debugging.

Блоки free Inspector:

1. Health
2. Routing bundle
3. Trust buckets
4. Why not trusted
5. Repair queue
6. Stale items
7. Critical files
8. Wiki graph
9. Search preview
10. PR summary preview
11. Active agent
12. Lock owner
13. Worktree/branch status
14. Command Center
15. Export debug bundle
16. No-cloud badge
17. External memory status
18. Basic Team Mode panel when team metadata exists

### 14. Command Center: кнопки вместо команд

Free UI должен снижать необходимость писать команды вручную.

Кнопки free слоя:

| Кнопка | CLI под капотом | Output |
|---|---|---|
| `Run Doctor` | `node .knowledge/tools/doctor.js --json` | health + warnings |
| `Run Import` | `node .knowledge/tools/flow.js import --json` | routing/search baseline |
| `Run Release` | `node .knowledge/tools/flow.js release --json` | full readiness refresh |
| `Build Inspector` | `node .knowledge/tools/build-visual-inspector.js --json` | static inspector |
| `Build Search` | `node .knowledge/tools/build-search-index.js --json` | search index |
| `Generate PR Summary` | `node .knowledge/tools/generate-pr-summary.js --json` | markdown summary |
| `Render Graphs` | `node .knowledge/tools/render-graph-execution.js --json` | Mermaid diagrams |
| `Export Debug Bundle` | `node .knowledge/tools/export-debug-bundle.js --json` | zip without secrets |
| `Check Memory Providers` | `node .knowledge/tools/memory-provider.js status-all --json` | provider status |
| `Check Worktree` | `node .knowledge/tools/worktree-status.js --json` | git/worktree status |

Implementation note: static HTML cannot safely execute local commands by itself in a browser. Therefore the free UI needs one of these patterns:

- `copy command` buttons only;
- optional local `serve-inspector.js` command runner with explicit opt-in;
- VS Code/desktop wrapper later;
- never silent command execution from static HTML.

### 15. Agent Integrations

Бесплатно:

- Codex integration docs/files;
- Claude Code integration docs/files;
- OpenCode integration docs/files;
- custom agent entrypoint;
- AGENTS.md/CLAUDE.md bridge;
- source-of-truth and trust rules embedded into agent guidance;
- no vendor lock-in.

### 16. Memory Provider Interface

Бесплатная логика:

- Mem0 OSS is the recommended optional universal local memory backend;
- Pinecone remains optional vector/cloud retrieval bridge;
- показывать status, license, version pin, storage/source path;
- показывать warning, что external memory is not source of truth;
- давать Preview/Install receipt/Update receipt/Uninstall/Status commands только как explicit opt-in;
- писать metadata в `.knowledge/external_memory/registry.json` и provider manifests;
- включать записи в reports/metrics как external retrieved memory / auxiliary memory.

Важное поведение:

- если team mode включен, по умолчанию нельзя смешивать workspace states;
- если legacy Claude MEM найден как shared across worktrees, Inspector/doctor должны предупреждать;
- Graphiti and Zep stay in the paid Inspector layer as provider contracts/cards;
- external memory не поднимает trust без evidence.

### 17. Basic Team Mode panel в free Inspector

Free Inspector может показывать локальную/readonly team context panel, если найден `teamRoot` или stateRoot содержит team metadata:

- current mode: `repo` / `team`;
- repoId;
- workspaceId;
- agentId;
- targetRoot;
- branch/head;
- lock owner;
- active workspaces summary;
- last flow result;
- warnings;
- copied commands for next step.

Граница free:

- не назначать владельцев;
- не хранить командную историю beyond local files;
- не давать multi-repo dashboard;
- не давать hosted sync;
- не давать GitHub App automation;
- не давать Slack/email alerts.

## Что должно остаться бесплатным навсегда

1. Установка open-core `.knowledge`.
2. Repo-local режим.
3. Routing bundle.
4. Trust/freshness statuses.
5. Repair queue as local JSON/Markdown.
6. Local search index.
7. Source-of-truth order.
8. Doctor report.
9. Metrics baseline.
10. PR summary markdown.
11. Static local Inspector baseline.
12. Agent integrations.
13. GitHub Action templates baseline.
14. External memory status as optional bridge.
15. Manual update check without auto-update.
16. Basic command copy buttons.
17. Local debug bundle export without secrets.

## Что не должно входить в free core

| Исключено из free | Почему |
|---|---|
| Hosted backend | Это commercial ops/support cost. |
| Login/accounts | Не нужно для local trust/debug. |
| Multi-repo dashboard | Командная управленческая ценность. |
| Repair ownership with SLA/history/comments | Требует team roles and audit. |
| GitHub App comments/checks/labels | Automation layer. |
| Long historical analytics | Командная retention/value. |
| SSO/RBAC/audit export | Enterprise value. |
| Policy packs with commercial enforcement | Governance SKU. |
| Alerts Slack/email/GitHub | Team operations. |
| Cross-repo knowledge map | Org/platform buyer value. |
| Hosted/private/VPC deployment | Commercial deployment. |

## Acceptance criteria для free core

- `node .knowledge/tools/flow.js release --json` успешно обновляет routing, trust, repair, search, metrics, pr summary and inspector artifacts.
- Static Inspector открывается без сервера.
- Inspector показывает не меньше 12 meaningful blocks, включая trust, repair, stale, critical files and command center.
- Все reports доступны как JSON/Markdown.
- Free mode работает без network.
- Update checks disabled by default.
- No telemetry.
- Source-of-truth order clearly visible.
- External memory cannot override current code/tests/evidence.
- Repo-local regression tests проходят после добавления team mode.

## Короткий текст для README

```md
## Free open-core boundary

The free `.knowledge` core is a useful local control plane for one repository. It includes routing bundle, trust/freshness, repair queue, local search, source-of-truth rules, doctor/metrics, PR summary, agent integrations and a static local Visual Inspector. It runs locally, requires no hosted backend, sends no telemetry by default and keeps code/tests/evidence above summaries or external memory.

Paid Pro2Pilot Inspector is the optional workflow layer for teams: multi-repo dashboards, interactive PR impact, repair ownership, policy packs, GitHub App automation, history, alerts, SSO/RBAC/audit and hosted/private/VPC deployment.
```

