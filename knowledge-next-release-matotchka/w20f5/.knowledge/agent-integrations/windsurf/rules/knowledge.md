---
trigger: always_on
---

# Windsurf Cascade .knowledge bridge

For meaningful scoped work, run `node .knowledge/tools/agent-task.js begin`
before broad repository exploration and read the exact returned
`route.first_read.content`. Preserve its workflow ID and SHA, then call
`node .knowledge/tools/agent-task.js finish` after the primary change and
physical tests. This allows one safe task-relevant Repair-on-touch closure to
reuse the same native verification evidence without hiding unrelated debt.

When a repository-root `AGENTS.md` contains the `.knowledge` managed block,
treat it as the shared cross-agent contract. This Windsurf rule is only the
Cascade-specific discovery bridge; do not duplicate or override the shared
instructions.

Use `.knowledge/Quick-Start.md` for setup and the committed agent-task result
for final reporting. Never describe the deterministic local context estimate as
provider-reported model-token usage, speed, cost, or general accuracy.

For concurrent work, set a stable `KNOWLEDGE_AGENT_ID` and use a separate
worktree or branch.

If a meaningful task or required `.knowledge` write is blocked, do not silently
skip it. Use `node .knowledge/tools/recording-blockers.js list` when available
and relay its `chat_notice` in the user's preferred language, naming the
blocked item and reason. Mask secret values. Obey a user boundary that excludes
`.knowledge/`; leave the blocker visibly `blocked_by_user_scope` and never
bypass the scope. Say: “Если это не секрет, сообщите в чате или выберите
действие в Inspector”. This instruction is not a mechanical guarantee for
every runner.
