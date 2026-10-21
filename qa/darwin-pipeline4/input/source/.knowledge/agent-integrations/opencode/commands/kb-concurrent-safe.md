---
description: Check whether current session is safe for concurrent multi-agent work
agent: plan
---

Read:

- @.knowledge/maintenance/concurrency_policy.json
- @.knowledge/maintenance/automation_status.json

Check that this session has a stable `KNOWLEDGE_AGENT_ID`, separate branch/worktree, and that writes go through `.knowledge/tools/*`.
