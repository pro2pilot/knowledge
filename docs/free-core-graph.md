# Free Core Trust Graph

The free/core graph must be useful without Pro Inspector. It explains local trust and routing; it does not replace source code, tests, or evidence.

## Canon Boundary

| Graph capability | Free core | Pro Inspector |
|---|---|---|
| Source-of-truth order | Included: code, tests, evidence, modules, decisions, wiki, sessions, external memory | Included with richer explanations and policy overlays |
| Wiki graph | Included: typed links, inferred seed links, broken edges, orphan pages | Included with editing workflows and history |
| Module-to-wiki relations | Included: module cards connect to wiki index, architecture notes, and runbooks | Included with ownership, SLA, and multi-repo aggregation |
| Trust status on nodes | Included: trusted/routing/advisory/suspect visual classes | Included with advanced scoring and trends |
| External memory boundary | Included: advisory-only node and edge | Included with provider governance and fleet status |
| Interactive exploration | Static local SVG and diagnostics | Interactive graph, filters, drilldowns, persisted views |
| PR impact graph | Basic local PR impact data is free | Advanced interactive PR impact graph is Pro |
| Temporal memory graph | Not included | Graphiti/Zep-style temporal/provider graph is outside free/core |

## 3.2.4 Readiness Target

| Criterion | Target | Implementation |
|---|---:|---|
| Data usefulness | 9/10 | Fresh graph has source-truth, module, wiki nodes, and inferred relations even before custom links exist. |
| Visual usefulness | 9/10 | Inspector shows lanes, colored relation legend, metrics, diagnostics, and rebuild command. |
| Canon alignment | 9/10 | Free graph stays local/static and explains trust; Pro-only interactive/history/provider fleet behavior remains out of scope. |
| QA coverage | 9/10 | Public verification rebuilds the graph, runs strict wiki lint, and checks Doctor. Deeper release regression tests stay in the maintainer source tree. |

## Commands

```bash
node .knowledge/tools/build-wiki-graph.js
node .knowledge/tools/lint-wiki.js --strict
node .knowledge/tools/doctor.js
node .knowledge/tools/build-visual-inspector.js
```

## What The Free Graph Is Not

- It is not Graphiti, Zep, or a temporal memory database.
- It is not a cloud dashboard.
- It is not a team billing or governance UI.
- It does not make wiki or external memory source of truth.
- It does not raise trust automatically from advisory memory.
