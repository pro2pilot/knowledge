# Free Core

Free Core is the open local system: file layout, schemas, CLI, routing bundle, evidence, trust/freshness, repair queue, PR review data, agent activity metadata, Safe Queue primitives, embedding contracts and JSON/Markdown reports.

Free Core does not require login, cloud, telemetry, Stripe, license keys, external memory runtimes, or commercial add-ons.

Required local commands include:

```bash
node .knowledge/tools/doctor.js --json
node .knowledge/tools/flow.js release --no-color --json
node .knowledge/tools/pr-impact.js --json
node .knowledge/tools/restore-trust.js --safe --json
node .knowledge/tools/build-wiki-graph.js
node .knowledge/tools/agent-session.js report --json
node .knowledge/tools/team-status.js --json
node .knowledge/tools/worktree-status.js --json
```

The free graph surface is documented in `docs/free-core-graph.md`.
