# Cookbook: New Project

1. Extract `.knowledge/` into the repository root.
2. Tell an agent: `Read .knowledge/Quick-Start.md and execute it.`
3. Or run manually:

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime codex
node .knowledge/tools/flow.js import
node .knowledge/inspector.js
```

Replace `codex` with the active runtime: `claude`, `opencode`, `openclaw`, `hermes`, `gemini`, `copilot`, `devin`, `windsurf`, `continue`, `roo`, or `aider`.

Expected output:

- agent integrations installed;
- routing bundle generated;
- search index generated;
- doctor report created;
- live Inspector opened;
- `First-run setup` completed if shown.
