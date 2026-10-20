---
description: Collect .knowledge local context, file, health, and graph metrics without turning estimates into model-performance claims
agent: build
---

!`node .knowledge/tools/flow.js release`

Read `.knowledge/maintenance/pr_summary.md` and follow `.knowledge/agent-integrations/_shared/metrics-reporting.md`. Report exactly one state: workspace-to-task narrowing, estimated overhead, neutral, or unavailable/not comparable. Always label it as a deterministic local context estimate, not provider-reported model-token usage.
