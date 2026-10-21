# Concurrent Agent Model

`.knowledge` is designed for repositories where different agents may work on the same project: Codex, Claude Code, OpenCode, and custom bots.

## Recommended topology

```txt
repo/
  .knowledge/              # shared repo-local knowledge layer
../worktrees/
  codex-task-1/            # branch bot/codex-task-1
  claude-task-2/           # branch bot/claude-task-2
  opencode-task-3/         # branch bot/opencode-task-3
```

## Rules

1. Give every bot a stable `KNOWLEDGE_AGENT_ID`.
2. Prefer a separate branch or worktree per bot.
3. All agents may read `.knowledge/` freely.
4. Writes should go through `.knowledge/tools/*` or code that uses `.knowledge/tools/lib/json-store.js`.
5. Shared JSON writes must use `.knowledge/.lock` and atomic temp-file rename.
6. Agent-local runtime state belongs in `.knowledge/.runtime/` or `.knowledge/sessions/active_tasks/<agent_id>.json`.
7. Canonical updates should be merged through normal git review or one maintainer agent.

## Safe commands

```bash
export KNOWLEDGE_AGENT_ID=codex-01
node .knowledge/tools/flow.js release
node .knowledge/tools/sync-tracked.js --scan
node .knowledge/tools/doctor.js
```

## Unsafe actions

- Editing generated JSON snapshots from multiple agents without the lock.
- Sharing one dirty working tree among many bots.
- Treating module cards as source of truth for suspect or low-confidence areas.
- Treating discovered files as trusted before code recheck.
- Overwriting project-specific `.knowledge` records during a system update.

## Merge strategy

- Current code and tests are source of truth.
- Keep verified decisions, invariants, evidence, wiki pages, and module cards.
- Treat generated maintenance snapshots as refreshable.
- Resolve contradictions explicitly in `.knowledge/contradictions.json`.
