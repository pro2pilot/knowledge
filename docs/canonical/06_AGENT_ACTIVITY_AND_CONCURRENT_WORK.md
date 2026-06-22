# 06 — Agent Activity and concurrent work

## Core decision

No manual `Switch Active Agent`.

Instead:

```txt
Agent Registry + Active Sessions + Agent Activity
```

Users do not switch a global active agent. Connected agents auto-register sessions. The Inspector derives active state from heartbeats, locks, workspaces and recent reports.

## Identity model

```json
{
  "operator_id": "andrii",
  "operator_email": "andrii@example.com",
  "agent_runtime_id": "claude-code",
  "agent_runtime_label": "Claude Code",
  "agent_instance_id": "claude-code-andrii-mbp-01",
  "agent_display_name": "Claude #1",
  "session_id": "sess_...",
  "run_id": "run_...",
  "task_id": "task_...",
  "workspace_id": "ws_...",
  "branch": "agent/auth-fix",
  "worktree_path": "../worktrees/agent-auth-fix",
  "status": "running",
  "started_at": "...",
  "last_heartbeat_at": "..."
}
```

## Required distinction

| Field | Meaning |
|---|---|
| `agent_runtime_id` | Type of agent: Claude, Codex, OpenCode, etc. |
| `agent_instance_id` | Specific agent instance/session. Needed when 5 Claude agents work at once. |
| `operator_id` | Human/user/account responsible. |
| `session_id` | Conversation/terminal/session. |
| `run_id` | One concrete execution. |
| `workspace_id` | Work area/worktree. |
| `task_id` | Task being worked on. |

## Registration levels

### Level 1 — Adapter/wrapper

Best mode. Agent is launched with env/config:

```txt
KNOWLEDGE_OPERATOR_ID
KNOWLEDGE_AGENT_RUNTIME_ID
KNOWLEDGE_AGENT_INSTANCE_ID
KNOWLEDGE_WORKSPACE_ID
```

### Level 2 — Instruction self-report

Agent instructions include:

```bash
node .knowledge/tools/agent-session.js start --runtime claude-code --json
node .knowledge/tools/agent-session.js finish --json
```

### Level 3 — Inferred

Fallback from git author, branch, cwd, recent reports. Mark as:

```txt
actor_confidence = inferred
```

## Agents Activity UI

```txt
Active now
Waiting
Ready for review
Locks
Recent reports
```

Table columns:

```txt
Agent
User
Task
Workspace
Branch
Status
Lock
Last activity
```

Actions:

```txt
Open report
Prepare handoff
Release stale lock
Archive session
Open workspace
Open merge queue
```

No action:

```txt
Switch active agent
```

## Modes

### Observe

`.knowledge` only observes and reports.

### Guided

`.knowledge` suggests actions; user clicks safe actions manually.

### Active Agent

One active agent at a time in practice, but no global switch. Handoff is automatic via reports.

### Safe Queue

Default multi-agent mode in one repo.

```txt
read can be parallel
write zones are locked
agent waits if zone is locked
```

Lock zone examples:

```txt
file
directory
module
critical path
policy scope
```

### Parallel Worktrees

Advanced/team mode. Each agent works in separate branch/worktree. `.knowledge` tracks workspace, branch, report and merge readiness.

### Controlled Autonomy

Future/advanced mode. Agents may run allowed actions and create PRs. Merge requires policy gates.

## Safe Queue default

```txt
If agent B wants a locked zone, it waits.
No merge conflicts by default.
```

## Parallel Worktrees flow

```txt
create worktree
register workspace
agent works
agent produces report
.knowledge generates integration report
merge queue decides next action
```

## Handoff

Handoff is not switching. It is context continuity.

Generate on:

```txt
session finish
session fail
lock release
workspace complete
```

Read on:

```txt
new related session start
workspace resume
merge review
```
