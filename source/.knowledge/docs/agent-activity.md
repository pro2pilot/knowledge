# Agent Activity

`.knowledge` does not use a manual active-agent switch.

It uses:

- Agent Registry
- Active Sessions
- Agent Activity Events
- Handoff Metadata
- Safe Queue
- Locks
- Parallel Worktree metadata
- Merge readiness reports

Required identity fields include `operator_id`, `agent_runtime_id`, `agent_instance_id`, `session_id`, `run_id`, `task_id`, `workspace_id`, `branch` and `status`.

Commands:

```bash
node .knowledge/tools/agent-session.js start --runtime claude-code --json
node .knowledge/tools/agent-session.js heartbeat --json
node .knowledge/tools/agent-session.js finish --json
node .knowledge/tools/agent-session.js report --json
```
