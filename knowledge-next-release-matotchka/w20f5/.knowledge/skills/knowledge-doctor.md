# Knowledge Doctor

Use to check whether `.knowledge` is structurally safe for agent work.

Run:

```bash
node .knowledge/tools/doctor.js
```

Then inspect `.knowledge/maintenance/quality_report.json`.

If status is `broken` or `degraded`, repair the reported issues before relying on `.knowledge` beyond routing.
