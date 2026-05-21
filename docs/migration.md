# Migration Guide

When an older `.knowledge` exists:

1. Back it up.
2. Preserve `wiki/`, `modules/`, `evidence/`, `decisions.json`, `glossary.json`, and handoff files.
3. Do not copy runtime locks, temp files, local logs, or secrets.
4. Run `node .knowledge/tools/flow.js import`.
5. Inspect `repair_queue.json` and `quality_report.json`.

When migrating from `.knowledge`, extract the new archive so the repository contains `.knowledge/` directly.
