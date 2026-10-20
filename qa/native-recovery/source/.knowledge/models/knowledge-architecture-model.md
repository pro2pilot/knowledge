# Knowledge Architecture Model

`.knowledge` is a repo-local control plane for AI coding agents.

## Layers

```txt
current code and tests
  -> evidence JSON
  -> module cards + maps + decisions
  -> routing bundle + trust/freshness reports
  -> wiki graph + cookbook
  -> local search index
  -> Visual Inspector
  -> optional external memory bridge
  -> agent skills and commands
```

## Core artifacts

### `maintenance/routing_bundle.json`

The compact first-read bundle for agents. It should be the first file read after setup.

### `freshness.json`

Tracks the curated set of files that knowledge artifacts depend on.

### `maintenance/trust_report.json`

Trust and freshness status per module. It prevents stale summaries from silently misleading agents.

### `maintenance/quality_report.json`

Doctor output: structure health, missing references, invalid JSON, search/routing artifacts, and safety warnings.

### `maps/`

Directory maps, dependency maps, entrypoints, critical paths, file criticality, and wiki graph.

### `modules/`

Compact module cards used for routing and risk awareness.

### `evidence/`

Code-backed facts, test links, symbol facts, and traces. Evidence is stronger than prose summaries and weaker than current code/tests.

### `wiki/`

Long-form explanations, architecture notes, runbooks, and concepts. Wiki is advisory unless backed by evidence and current code/tests.

### `docs/cookbook/`

Operational recipes for repeatable agent workflows.

### `search/index.json`

Compact local search index over knowledge artifacts.

### `inspector/`

Local Visual Inspector artifacts. Rebuild with `node .knowledge/tools/build-visual-inspector.js`.

### `external_memory/`

Optional cold-archive bridge. External memory is retrieved context only, not source of truth.

## Reliability rule

No generated knowledge artifact is allowed to override current code or tests.

## Discovery rule

Discovery is not trust. New files discovered by scan/discover are candidates until an agent rechecks code and updates module cards/evidence.
