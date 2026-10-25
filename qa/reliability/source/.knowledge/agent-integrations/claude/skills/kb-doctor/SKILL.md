---
name: kb-doctor
description: Validate .knowledge health before relying on it.
disable-model-invocation: true
---

Run `node .knowledge/tools/doctor.js`.

Then read `.knowledge/maintenance/quality_report.json`.

If status is `broken` or `degraded`, rely on `.knowledge` only for routing and repair the listed issues before trusting summaries.
