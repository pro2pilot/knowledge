---
description: Maintain .knowledge wiki safely
agent: plan
---

Use `.knowledge/wiki/` for long-form architecture, runbooks, and concepts.

After wiki changes run:

!`node .knowledge/tools/build-search-index.js && node .knowledge/tools/build-routing-bundle.js && node .knowledge/tools/doctor.js`
