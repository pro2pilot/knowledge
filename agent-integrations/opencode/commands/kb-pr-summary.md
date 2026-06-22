---
description: Run .knowledge kb-pr-summary workflow
agent: build
---

!`node .knowledge/tools/generate-pr-summary.js`

In the final response after meaningful work, include `.knowledge/maintenance/pr_summary.md` together with doctor status, wiki lint status, suspect or low-confidence areas, repair queue state, routing bundle path, and metrics or token-savings status.
