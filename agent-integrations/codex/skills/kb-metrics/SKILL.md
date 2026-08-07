---
name: kb-metrics
description: Collect local context, file, health, and graph metrics without turning estimates into model-performance claims.
---

Run `node .knowledge/tools/flow.js release`, then inspect:

- `.knowledge/maintenance/pr_summary.md` for the canonical human-readable result;
- `.knowledge/metrics/baseline.json` for machine-readable evidence;
- `.knowledge/agent-integrations/_shared/metrics-reporting.md` for the reporting contract.

Report exactly one state: workspace-to-task narrowing, estimated overhead, neutral, or unavailable/not comparable. Always label it as a deterministic local context estimate, not provider-reported model-token usage. Never convert overhead, neutral, stale, or not-comparable results into a positive savings value.
