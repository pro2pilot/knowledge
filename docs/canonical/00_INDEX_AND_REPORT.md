# Pro2Pilot `.knowledge` — canonical artifacts pack

## Назначение пакета

Этот пакет фиксирует выводы, к которым мы пришли по `.knowledge 3.2.0`, Free Inspector, будущему Pro unlock, агентам, multi-agent/concurrent work, trust/evidence/routing/repair, UX, QA, benchmarks, embedding и FAQ.

Файлы можно использовать как:

- стандарт проверки соответствия реализации плану;
- источник для `docs/`, `README`, `FAQ`, UI-copy и сайта;
- основу для agent prompts;
- checklist для release/QA;
- product spec для Free/Core/Pro split;
- материал для будущего VS Code extension и browser Inspector;
- embedding/license guidance для приложений, которые используют `.knowledge` под капотом.

## Главная формула продукта

```txt
.knowledge is a repo-local routing, evidence, trust, freshness, repair and PR-review system for coding agents.
```

Коротко:

```txt
.knowledge makes agent knowledge inspectable, evidence-backed, fresh and repairable.
```

## Что `.knowledge` НЕ делает

```txt
.knowledge does not manage or run agents.
.knowledge does not replace Claude, Codex, Cursor, OpenCode, Antigravity, Cline or other runtimes.
.knowledge does not trust external memory automatically.
.knowledge does not auto-merge by default.
```

## Что `.knowledge` делает

```txt
.knowledge observes, identifies, records, verifies, routes, repairs, queues, locks, reviews and reports agent activity and knowledge state.
```

## Файлы пакета

| Файл | Зачем нужен |
|---|---|
| `00_INDEX_AND_REPORT.md` | Навигация по пакету и краткий отчет. |
| `01_PRODUCT_CANON.md` | Product canon: что такое `.knowledge`, чем оно не является, основные термины. |
| `02_FREE_CORE_SPEC.md` | Что входит в бесплатный Core: files, CLI, schemas, trust/evidence/routing/repair. |
| `03_FREE_INSPECTOR_UX_SPEC.md` | UX free Inspector: Home, Review, Knowledge Trust, Agents Activity, Reports, Settings. |
| `04_PRO_SUBSCRIPTION_SPEC.md` | Pro subscription внутри free Inspector: Stripe/Cloudflare/R2/license/entitlements. |
| `05_FEATURE_SPLIT_MATRIX.md` | Четкое разделение Free Core / Free Inspector / Solo Pro / Team Pro / Enterprise. |
| `06_AGENT_ACTIVITY_AND_CONCURRENT_WORK.md` | Agent identity, active sessions, Safe Queue, Parallel Worktrees, Merge Queue. |
| `07_TRUST_EVIDENCE_ROUTING_REPAIR.md` | Как работает routing/evidence/trust/freshness/repair и Restore Trust. |
| `08_AGENT_REPORT_FOOTER_AND_SIMPLE_ADVANCED.md` | Simple/Advanced mode без чата в Inspector; footer в чате агента. |
| `09_VSCODE_BROWSER_AND_EMBEDDING.md` | VS Code extension, browser Inspector, local API, headless contracts. |
| `10_MEMORY_PROVIDER_STRATEGY.md` | Mem0/Pinecone/Graphiti/Zep/legacy Claude memory strategy. |
| `11_PR_REVIEW_AND_MERGE_QUEUE.md` | PR Review, PR Impact, Merge Queue, approval policy. |
| `12_QA_BENCHMARK_RELEASE_GATES.md` | QA gates, release checks, benchmark proof and marketing claim rules. |
| `13_LICENSE_ATTRIBUTION_EMBEDDING_FAQ.md` | Apache-2.0/NOTICE/attribution guidance for apps using `.knowledge`. |
| `14_SITE_FAQ_DRAFT.md` | Draft FAQ for website/docs. |
| `15_AGENT_IMPLEMENTATION_PROMPT.md` | Goal-mode prompt to align implementation to these specs. |
| `16_UI_COPY_AND_LABELS.md` | UI labels, short descriptions, warnings, empty states, settings copy. |
| `17_COMPLIANCE_CHECKLIST.md` | Machine-readable-style checklist for implementation review. |

## Where to put these files in project

Suggested paths:

```txt
.knowledge/docs/canon/00_INDEX_AND_REPORT.md
.knowledge/docs/canon/01_PRODUCT_CANON.md
.knowledge/docs/canon/02_FREE_CORE_SPEC.md
.knowledge/docs/canon/03_FREE_INSPECTOR_UX_SPEC.md
.knowledge/docs/canon/04_PRO_SUBSCRIPTION_SPEC.md
.knowledge/docs/canon/05_FEATURE_SPLIT_MATRIX.md
.knowledge/docs/canon/06_AGENT_ACTIVITY_AND_CONCURRENT_WORK.md
.knowledge/docs/canon/07_TRUST_EVIDENCE_ROUTING_REPAIR.md
.knowledge/docs/canon/08_AGENT_REPORT_FOOTER_AND_SIMPLE_ADVANCED.md
.knowledge/docs/canon/09_VSCODE_BROWSER_AND_EMBEDDING.md
.knowledge/docs/canon/10_MEMORY_PROVIDER_STRATEGY.md
.knowledge/docs/canon/11_PR_REVIEW_AND_MERGE_QUEUE.md
.knowledge/docs/canon/12_QA_BENCHMARK_RELEASE_GATES.md
.knowledge/docs/canon/13_LICENSE_ATTRIBUTION_EMBEDDING_FAQ.md
.knowledge/docs/canon/14_SITE_FAQ_DRAFT.md
.knowledge/docs/canon/15_AGENT_IMPLEMENTATION_PROMPT.md
.knowledge/docs/canon/16_UI_COPY_AND_LABELS.md
.knowledge/docs/canon/17_COMPLIANCE_CHECKLIST.md
```

## Implementation status labels

Use only these labels in reports:

```txt
planned
implemented
tested
release-candidate
production-ready
blocked
preview-only
```

Do not call anything `10/10` unless all relevant gates pass in source checkout and clean install.
