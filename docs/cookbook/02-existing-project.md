# Cookbook: Existing Project / Migration

1. Back up any existing `.knowledge/` folder.
2. Merge valuable folders: `wiki/`, `modules/`, `evidence/`, `decisions.json`, `glossary.json`.
3. Run:

```bash
node .knowledge/tools/flow.js import
```

Never overwrite existing knowledge without backup and merge intent.
