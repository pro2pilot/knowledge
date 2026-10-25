---
description: Merge-ingest current repository into .knowledge without overwriting curated knowledge
agent: build
---

Run safe merge ingest:

!`node .knowledge/tools/ingest-existing-project.js --merge && node .knowledge/tools/sync-tracked.js --scan && node .knowledge/tools/build-routing-bundle.js && node .knowledge/tools/build-search-index.js && node .knowledge/tools/doctor.js`

Then inspect @.knowledge/project_index.json and @.knowledge/maintenance/trust_report.json.
