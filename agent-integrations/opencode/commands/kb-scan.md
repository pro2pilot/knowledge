---
description: Rebaseline the current .knowledge scope
agent: build
---

Run:

!`node .knowledge/tools/sync-tracked.js --scan`

Then inspect @.knowledge/maintenance/trust_report.json.

For new-file discovery, run:

!`node .knowledge/tools/sync-tracked.js --scan --discover`

Then inspect @.knowledge/maintenance/repair_queue.json before adding any new files to module cards or evidence.
