---
name: kb-ingest
description: Bootstrap or merge-ingest an existing repository into .knowledge without overwriting curated knowledge.
disable-model-invocation: true
---

Use safe merge mode by default:

```bash
node .knowledge/tools/ingest-existing-project.js --merge
node .knowledge/tools/sync-tracked.js --scan
```

Do not use `--force` unless the user explicitly wants backups and overwrite behavior.

After ingest, inspect:

- `.knowledge/project_index.json`
- `.knowledge/modules/module_registry.json`
- `.knowledge/maintenance/trust_report.json`
- `.knowledge/maintenance/repair_queue.json`
