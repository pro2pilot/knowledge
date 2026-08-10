# Team Worktree PR Cookbook

Use this flow when two or more agents work on separate branches/worktrees.

```bash
node .knowledge/tools/team-init.js --team-root ../.knowledge-team --target-root . --json
node .knowledge/tools/workspace-register.js --team-root ../.knowledge-team --target-root ../worktrees/codex-task-1 --workspace-id codex-task-1 --agent-id codex-01 --json
node .knowledge/tools/workspace-register.js --team-root ../.knowledge-team --target-root ../worktrees/claude-task-2 --workspace-id claude-task-2 --agent-id claude-01 --json
node .knowledge/tools/worktree-status.js --target-root ../worktrees/codex-task-1 --team-root ../.knowledge-team --workspace-id codex-task-1 --json
node .knowledge/tools/flow.js release --team-root ../.knowledge-team --target-root ../worktrees/codex-task-1 --workspace-id codex-task-1 --agent-id codex-01 --exclusive --json
node .knowledge/tools/team-pr-summary.js --team-root ../.knowledge-team --workspace-id codex-task-1 --json
```

Before opening the PR:

- confirm `worktree-status` has no branch mismatch;
- confirm no generated runtime files are staged accidentally;
- confirm exclusive flow locks were released;
- review the generated team PR summary;
- commit only source changes and curated knowledge that should merge back.

After merge:

```bash
node .knowledge/tools/flow.js release --json
node .knowledge/tools/workspace-unregister.js --team-root ../.knowledge-team --workspace-id codex-task-1 --json
node .knowledge/tools/team-status.js --team-root ../.knowledge-team --json
```

