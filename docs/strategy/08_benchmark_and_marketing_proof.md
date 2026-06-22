# 08 — Benchmark and marketing proof after competitive analysis

## Why benchmarks are now mandatory

The competitive landscape shows a clear problem: many competitors already have stronger social proof, enterprise pages, pricing pages, stars, dashboards, or review workflows.

Therefore `.knowledge` must not rely on abstract claims. It needs proof artifacts:

```txt
raw logs + metrics + screenshots + reproducible benchmark scripts + limitations
```

## Claims that need proof

| Claim | Benchmark needed |
|---|---|
| Agents rediscover fewer files | B1 Repo Orientation |
| Trust/freshness catches stale summaries | B2 Trust/Freshness |
| Repair queue is actionable | B3 Repair Queue |
| PR Impact helps review | B4 PR Impact |
| Inspector is better than raw JSON | B5 Inspector UX |
| Search is useful | B6 Scoped Search |
| Handoff survives sessions/runtimes | B7 Agent Handoff |
| Multi-worktree has no state collision | B8 Team Mode |
| Git policy prevents artifact pollution | B9 Git Policy |
| Core works offline/no telemetry | B10 Local-first Privacy |
| Mem0/Pinecone stay advisory | B11 Memory Provider Safety |
| Policy packs improve governance | B12 Policy Packs |
| Scale is stable | B13 Performance/Scale |

## Required benchmark outputs

```txt
.knowledge/benchmarks/results/runs.jsonl
.knowledge/benchmarks/results/summary.json
.knowledge/benchmarks/results/summary.md
.knowledge/benchmarks/results/metrics.csv
.knowledge/benchmarks/results/charts/*.svg
.knowledge/benchmarks/results/marketing/claim_evidence_map.md
.knowledge/benchmarks/results/marketing/proof_cards.md
.knowledge/benchmarks/results/marketing/readme_section.md
.knowledge/benchmarks/results/marketing/landing_section.md
.knowledge/benchmarks/results/marketing/social_posts.md
```

## Claim evidence map

Every marketing claim must map to:

```txt
benchmark id
metric name
raw artifact
summary file
limitations
```

Example:

| Claim | Benchmark | Metric | Evidence | Limitation |
|---|---|---|---|---|
| Agents opened fewer files before first plan | B1 | files_opened_before_plan | B1 summary + runs.jsonl | repo/task dependent |
| External memory cannot raise trust | B11 | override_attempts_blocked | trust_before/after | synthetic conflict |
| Multi-worktree avoids state collision | B8 | state_cross_contamination_count | team test logs | temp repo scenario |

## Competitive proof requirements

### Against Repomix/gitingest

Prove:

```txt
.knowledge is not just context packing.
```

Metrics:

- first relevant file found;
- trust reason coverage;
- repair actions generated;
- PR impact warnings.

### Against Mem0/Letta/Graphiti

Prove:

```txt
memory is visible but bounded by trust.
```

Metrics:

- external memory override count = 0;
- advisory label accuracy;
- provenance coverage.

### Against PR review tools

Prove:

```txt
PR Impact includes knowledge freshness and repair debt, not only diff comments.
```

Metrics:

- critical touch detection;
- stale module detection in PR;
- reviewer note usefulness.

### Against Cursor/Devin

Prove:

```txt
.knowledge survives across runtimes and worktrees.
```

Metrics:

- agent handoff resume time;
- state contamination count;
- workspace compare accuracy.

### Against Sourcegraph

Prove:

```txt
local-first lightweight install with visible trust/freshness.
```

Metrics:

- install-to-inspector time;
- offline command success;
- no network call count;
- artifact transparency.

## Marketing copy rules

Allowed before benchmarks:

```txt
Designed to...
Built to...
A local-first approach to...
Private preview...
```

Allowed after benchmarks:

```txt
In benchmark B1 on N repos / M tasks, X changed by Y%.
```

Forbidden without proof:

```txt
best
first
guaranteed
10x
enterprise-ready
safe by default
eliminates hallucinations
```

## First public proof pack

Minimum launch pack:

1. `B1 Repo Orientation` before/after.
2. `B2 Trust/Freshness` stale summary downgrade.
3. `B3 Repair Queue` injected issue → repair action.
4. `B4 PR Impact` critical PR warning.
5. `B8 Team Mode` multi-worktree no corruption.
6. `B10 No-cloud` offline/local proof.
7. `B11 Memory Provider Safety` Mem0 advisory-only proof.

## Output formats

### README proof block

```md
## Measured proof

- B1: Agents opened X% fewer files before first plan on N tasks.
- B2: Stale knowledge was downgraded with X precision / Y recall.
- B8: N parallel worktree runs completed with zero state contamination.

Raw logs and methodology: `.knowledge/benchmarks/results/`.
```

### Landing proof block

```txt
Problem → measured result → artifact → CTA
```

### HN/Reddit posture

Use:

```txt
We tested X. Here is what worked, failed, and what we need feedback on.
```

Do not use:

```txt
We built the future of coding agents.
```
