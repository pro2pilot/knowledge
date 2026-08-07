---
name: kb-pr-summary
description: Generate a PR-facing summary of trust, health, metrics, and repair queue state.
---

Run `node .knowledge/tools/generate-pr-summary.js`, then use `.knowledge/maintenance/pr_summary.md` in PR review.

In the final response after meaningful work, include the PR summary path together with doctor status, wiki lint status, suspect or low-confidence areas, repair queue state, routing bundle path, and the routing-context estimate state or its unavailable/not-comparable reason.
