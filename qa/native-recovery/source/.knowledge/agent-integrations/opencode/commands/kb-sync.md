---
description: Run .knowledge sync and summarize trust impact
agent: build
---

Run:

!`node .knowledge/tools/sync-tracked.js`

Then read:

- @.knowledge/maintenance/trust_report.json
- @.knowledge/maintenance/sync_log.json
- @.knowledge/maintenance/automation_status.json
- @.knowledge/maintenance/repair_queue.json

Summarize changed files, suspect modules, low-confidence modules, and repair items.
