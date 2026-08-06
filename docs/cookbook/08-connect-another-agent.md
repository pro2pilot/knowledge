# Cookbook: Connect Another Agent

Use this when `.knowledge/` is already installed in a repository and a new
agent/runtime needs to join the same repo.

Do not reinstall `.knowledge/`. Do not run `--all` unless a human explicitly
asks for every supported integration.

From the repository root:

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime <new-agent>
node .knowledge/tools/flow.js doctor
```

Replace `<new-agent>` with one supported runtime:

```txt
codex, claude, opencode, openclaw, hermes, gemini, copilot, devin, windsurf, continue, roo, aider
```

Then the new agent reads:

```txt
.knowledge/maintenance/routing_bundle.json
.knowledge/maintenance/handoff_summary.json
```

If another agent has active unmerged work, use separate branches or worktrees
and set a stable `KNOWLEDGE_AGENT_ID`.

## Integration coexistence

AGENTS.md-compatible runtimes (`codex`, `openclaw`, `hermes`, and `devin`) share one neutral managed block, so installing a new runtime does not replace another runtime-specific block. Devin and Windsurf are additionally isolated in `.devin/rules/knowledge.rules` and `.windsurf/rules/knowledge.md`. Re-running an installer is idempotent and preserves text outside `.knowledge` managed blocks.
