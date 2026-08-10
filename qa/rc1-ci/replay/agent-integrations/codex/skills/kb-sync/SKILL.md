---
name: kb-sync
description: Refresh .knowledge freshness, trust report, stale items, repair queue, and append-only events after code changes.
---

Run:

`node .knowledge/tools/sync-tracked.js`

Use `node .knowledge/tools/sync-tracked.js --scan` to rebaseline the current curated scope.

Use `node .knowledge/tools/sync-tracked.js --scan --discover` when new important files may have been added outside hook/watcher coverage, then inspect repair queue before updating module cards or evidence.

Then inspect:

- `.knowledge/maintenance/trust_report.json`
- `.knowledge/maintenance/sync_log.json`
- `.knowledge/maintenance/automation_status.json`
- `.knowledge/maintenance/repair_queue.json`

Summarize changed files, suspect modules, low-confidence modules, and repair items.
