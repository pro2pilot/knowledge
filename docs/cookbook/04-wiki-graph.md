# Cookbook: Free Core Trust Graph

Use this when the Inspector graph looks empty, disconnected, or hard to explain.

## What It Builds

`build-wiki-graph.js` now creates the free/core trust graph:

- source-of-truth order;
- module cards;
- wiki pages;
- typed wiki links;
- inferred module/wiki seed relations;
- broken-edge and orphan-page diagnostics.

Wiki pages are still advisory unless backed by current code, tests, or evidence.

## Add Typed Links

Small wiki pages can add explicit typed links:

```yaml
links:
  supports: []
  contradicts: []
  depends_on: []
  supersedes: []
  related: []
```

## Rebuild And Check

```bash
node .knowledge/tools/build-wiki-graph.js
node .knowledge/tools/lint-wiki.js --strict
node .knowledge/tools/doctor.js
node .knowledge/tools/build-visual-inspector.js
```

The graph should not be zero-edge after a normal install/import. If it is, treat that as a release-blocking regression.
