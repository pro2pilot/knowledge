# Cookbook: Existing Project / Migration

1. Back up any existing `.knowledge/` folder.
2. Merge valuable folders: `wiki/`, `modules/`, `evidence/`, `decisions.json`, `glossary.json`.
3. Run:

```bash
node .knowledge/tools/install-agent-integrations.js --runtime codex
node .knowledge/tools/flow.js import
node .knowledge/inspector.js
```

Replace `codex` with the active runtime if this repository is being operated by another supported agent.

Never overwrite existing knowledge without backup and merge intent.
If `First-run setup` appears in Inspector, complete it before trusting generated reports.
