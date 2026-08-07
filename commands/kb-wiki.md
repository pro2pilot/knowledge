# kb-wiki

Use `.knowledge/wiki/` for durable human-readable explanations, architecture notes, runbooks, and concepts.

Wiki is advisory unless backed by current code/tests and `.knowledge/evidence/*.json`.

After wiki changes:

```bash
node .knowledge/tools/build-search-index.js
node .knowledge/tools/build-routing-bundle.js
node .knowledge/tools/doctor.js
```
