---
name: kb-concurrent-safe
description: Check whether current work is safe for multiple bots/agents sharing one .knowledge layer.
disable-model-invocation: true
---

Check:

1. `KNOWLEDGE_AGENT_ID` is set or choose a stable one for this session.
2. The agent is working in its own git branch or worktree.
3. `.knowledge/maintenance/concurrency_policy.json` exists.
4. `.knowledge/tools/lib/json-store.js` exists.
5. Shared `.knowledge` writes are done through maintenance tools.
6. Existing watcher/hook state does not indicate stale or conflicting processes.

Recommended command:

```bash
KNOWLEDGE_AGENT_ID=<agent-name> node .knowledge/tools/sync-tracked.js
```

If unsafe, explain which condition failed and how to proceed safely.
