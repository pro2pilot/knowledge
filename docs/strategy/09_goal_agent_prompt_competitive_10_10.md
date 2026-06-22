# 09 — Goal prompt: implement competitive 10/10 `.knowledge 3.2.0` + Pro Inspector

Use this prompt in goal mode.

---

Ты — senior product-engineering, full-stack, QA, release and technical-marketing agent. Твоя задача — довести `.knowledge 3.2.0` и Pro Inspector до состояния, которое выдерживает конкурентное сравнение с Cursor, Sourcegraph, Devin Desktop, Greptile/Qodo/CodeRabbit/Graphite, Mem0/Graphiti/Letta, Repomix/gitingest, Cline/Aider/Serena/PR-Agent.

Нельзя просто написать “10/10”. Если хотя бы одна обязательная проверка падает, статус не 10/10. Полумеры не подходят. Исправляй, перезапускай полный QA, повторяй до полного закрытия.

## 0. Product positioning to implement

Do not build an AI IDE. Do not build a review bot. Do not build a generic memory app.

Build:

```txt
.knowledge = repo-local knowledge governance layer for AI coding agents
Pro Inspector = team governance cockpit for agent-assisted code work
```

Free `.knowledge` must prove:

```txt
routing + trust/freshness + repair + PR impact preview + local Inspector + memory provider safety + Team Mode status
```

Pro Inspector must prove:

```txt
PR Impact + Repair Ownership + Team Spaces + Policy Gates + Memory Governance + Audit/History + Analytics
```

## 1. Read first

Read these docs before editing:

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
```

If these files are not present, create them from the supplied planning package or continue with equivalent content.

## 2. Baseline inventory

Run:

```bash
git status --short
grep -Rni "claude mem\|claude-mem\|claude_mem\|Claude MEM\|CLAUDE MEM" . || true
grep -Rni "<local-project-path>\|<tmp-benchmark-path>\|<local-user>\|<workspace-name>" . || true
```

Create:

```txt
.knowledge/maintenance/competitive-10-10-inventory.md
```

Include:

- current failures;
- release artifact status;
- Team Mode status;
- Inspector status;
- Pro Inspector status;
- memory providers;
- Claude MEM leftovers;
- local path leaks;
- test commands available.

## 3. P0: Release artifact and Team Mode

These are blockers. Fix before polishing.

Required pass:

```bash
node tools/self-test-install-policy.js
node tools/self-test-team-mode.js
node tools/package-release.js
node tools/validate-release-artifact.js dist/knowledge-v3.2.0.zip --json
```

Then test clean install:

```bash
mkdir -p <tmp-install-root>/knowledge-install-smoke
cd <tmp-install-root>/knowledge-install-smoke
git init
unzip /path/to/dist/knowledge-v3.2.0.zip
node .knowledge/tools/install-check.js --json
node .knowledge/tools/flow.js import --no-color --json
node .knowledge/tools/doctor.js --json
node .knowledge/tools/build-visual-inspector.js
node .knowledge/tools/self-test-team-mode.js
```

If Team Mode fails due to Inspector JSON corruption, fix sanitizer correctly:

```txt
sanitize values before JSON.stringify
or parse-transform-stringify
never regex-replace serialized JSON in a way that corrupts escaped snippets
```

## 4. Free Inspector: button-first repo cockpit

Make free Inspector real and polished.

Required tabs:

```txt
Overview
Command Center
Routing
Trust Ledger
Why Not Trusted
Freshness
Repair Queue
Critical Files
Wiki Graph
Search
PR Summary
PR Impact Preview
Memory Providers
Team Mode
Integrations
Metrics
Export / Debug
Pro Preview
```

Required cards:

- trust distribution;
- stale items;
- repair queue;
- PR impact warnings;
- memory providers;
- team/worktree status;
- doctor score;
- no-cloud/no-telemetry.

Required buttons:

```txt
Run Doctor
Refresh Release
Build Inspector
Search
Generate PR Summary
Review PR Impact
Export Debug Bundle
Team Status
Memory Status
Preview Mem0
Export Pro Snapshot
```

Required tests:

```bash
node tools/self-test-inspector-ui.js
```

Add team-mode UI test that parses `inspector/data.json` and DOM after team-mode generation.

## 5. PR Impact must be real

This is competitive P0 because Greptile/Qodo/CodeRabbit/Graphite pressure the paid layer.

Implement at least:

```txt
git diff → changed files → module mapping → trust/freshness → criticality → repair delta → policy warnings → reviewer notes
```

Free:

```bash
node .knowledge/tools/pr-impact.js --json
```

Pro:

- interactive PR Impact screen;
- graph/list view;
- reviewer note export;
- demo data and snapshot import.

Tests:

- critical file touched;
- stale module touched;
- source changed but evidence missing;
- generated runtime file staged;
- no changed files empty state.

## 6. Memory providers

Remove Claude MEM as first-class provider. It is legacy-only.

Implement:

```txt
Mem0 OSS = recommended optional universal provider
Pinecone = optional vector/cloud provider
Graphiti = Pro/Enterprise temporal graph
Zep = Pro/Enterprise managed/BYOC memory
```

Core commands:

```bash
node .knowledge/tools/memory-provider.js list --json
node .knowledge/tools/memory-provider.js preview mem0-oss --json
node .knowledge/tools/memory-provider.js status-all --json
node .knowledge/tools/memory-mem0.js health --json
node .knowledge/tools/memory-mem0.js add --text "..." --scope repo --json
node .knowledge/tools/memory-mem0.js search "query" --json
node .knowledge/tools/memory-mem0.js sync-report --json
```

If Mem0 runtime is not installed, report `runtime_not_installed`. Do not pretend.

Test:

```bash
node tools/self-test-memory-providers.js
node tools/self-test-external-memory.js
```

Must prove:

```txt
external_memory_override_count = 0
external memory cannot raise trust
provider status works offline
secrets redacted
```

## 7. Pro Inspector must be more than demo shell

In the adjacent Pro Inspector directory, build real runnable app shell.

Required commands:

```bash
npm install
npm run lint
npm run test
npm run build
npm run dev
```

Required screens:

```txt
Dashboard
Repos / Workspaces
PR Impact
Repair Board
Team Spaces
Policy Gates
Memory Governance
Provider Fleet Status
Audit / History
Analytics
Settings / License
```

Required capabilities:

- import sanitized `.knowledge` snapshot;
- render PR impact data;
- repair board state transitions;
- team spaces/worktree compare;
- memory provider fleet status;
- policy gates;
- audit event timeline;
- demo data without backend.

If using a dependency-light static shell due to network limits, still implement:

- structured components;
- schemas;
- meaningful tests;
- realistic demo data;
- no string-template-only fake app as final state.

## 8. Pro/free boundary

Free core may contain:

- Pro preview cards;
- Pro snapshot export;
- provider manifests;
- schemas.

Free core must not contain:

- Pro app implementation;
- paid-only backend;
- fake billing;
- hidden cloud dependency.

Pro app may consume exported snapshots.

## 9. Benchmarks and proof pack

Implement or update:

```txt
.knowledge/benchmarks/
```

Minimum runnable/stubbed honestly:

- B1 Repo Orientation;
- B2 Trust/Freshness;
- B3 Repair Queue;
- B4 PR Impact;
- B8 Team Mode;
- B10 No-cloud;
- B11 Memory Provider Safety.

Generate:

```txt
results/runs.jsonl
results/summary.md
results/summary.json
results/metrics.csv
results/marketing/claim_evidence_map.md
```

No marketing claim without evidence.

## 10. Required final QA

Run all:

```bash
node tools/self-test-install-policy.js
node tools/self-test-memory-providers.js
node tools/self-test-external-memory.js
node tools/self-test-team-mode.js
node tools/self-test-inspector-ui.js
node tools/flow.js release --no-color --json
node tools/build-visual-inspector.js
node tools/doctor.js --json
node tools/package-release.js
node tools/validate-release-artifact.js dist/knowledge-v3.2.0.zip --json
```

Clean install:

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/flow.js import --no-color --json
node .knowledge/tools/doctor.js --json
node .knowledge/tools/build-visual-inspector.js
node .knowledge/tools/self-test-team-mode.js
node .knowledge/tools/memory-provider.js status-all --json
```

Pro:

```bash
npm install
npm run lint
npm run test
npm run build
```

Security/privacy:

- no local path leaks;
- no `.git` in install artifact;
- no generated runtime state in release artifact;
- no unexpected network calls in status/build/doctor;
- no secrets in exports.

## 11. Final status rules

You may say `10/10` only if all pass:

- source tests pass;
- clean install tests pass;
- Team Mode tests pass source and release artifact;
- Inspector UI tests pass repo and team mode;
- PR Impact works with real data;
- memory provider policy works;
- Pro Inspector has real screens and passes build/test;
- release artifact is clean;
- docs match implementation;
- benchmark proof pack exists or limitations are explicitly marked.

If not, say:

```txt
Status: not 10/10.
Blockers:
1. ...
2. ...
Next action:
...
```

## 12. Final report format

Return:

```txt
1. Executive summary
2. Competitive positioning implemented
3. Free/core changes
4. PR Impact implementation
5. Team Mode status
6. Memory provider status
7. Free Inspector UI proof
8. Pro Inspector implementation
9. Release artifact validation
10. Benchmark/proof pack
11. QA commands and results
12. Remaining limitations
13. Exact commands for user
14. Files changed
```

No hype. No fake completion. No hidden assumptions.
