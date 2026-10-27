---
name: kb-routing
description: Rebuild and use the compact .knowledge routing bundle before planning.
disable-model-invocation: true
---

Run `node .knowledge/tools/build-routing-bundle.js`.

Then read `.knowledge/maintenance/routing_bundle.json` and use it as the first routing context. Open only the module cards, wiki pages, source files, and tests it points to.

If the bundle lists high-risk, suspect, or low-confidence modules, re-read the relevant source code before behavior claims or edits.
