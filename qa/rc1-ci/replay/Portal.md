# .knowledge Portal

A compact navigation page for the public `.knowledge` distribution.

## Start here

- `README.md` — product overview.
- `Quick-Start.md` — canonical instruction for any agent.
- `maintenance/routing_bundle.json` — first-read project bundle after setup.
- `inspector/index.html` — local Visual Inspector after it is built.

## Core workflows

- `flows/import.md` — setup and migration.
- `flows/release.md` — readiness flow.
- `flows/scan.md` — scan and freshness.
- `flows/lint.md` — wiki graph and lint.
- `flows/doctor.md` — health checks.

## User-facing docs

- `docs/cookbook/` — practical recipes.
- `docs/inspector.md` — local inspector guide.
- `docs/github-actions.md` — CI examples.
- `docs/integration-matrix.md` — agent integration matrix.
- `docs/metrics-benchmarks.md` — benchmark methodology.
- `docs/migration.md` — migration notes.

## Commands

```bash
node .knowledge/tools/flow.js import
node .knowledge/tools/flow.js release
node .knowledge/tools/doctor.js
node .knowledge/tools/build-visual-inspector.js
```
