---
name: kb-wiki
description: Maintain the .knowledge wiki layer safely.
---

Use `.knowledge/wiki/` for architecture notes, runbooks, concepts, and durable explanations.

Wiki is advisory unless backed by current code/tests and evidence JSON.

After edits, run:

`node .knowledge/tools/build-search-index.js`
`node .knowledge/tools/build-routing-bundle.js`
`node .knowledge/tools/doctor.js`
