---
description: Run .knowledge kb-metrics workflow
agent: build
---

!`node .knowledge/tools/collect-metrics.js`

After meaningful work, report `.knowledge/metrics/baseline.json`, estimated tokens saved, and estimated percent saved when routing metrics exist. If metrics are missing or stale, say that explicitly.
