# Shared .knowledge bridge for AGENTS.md-compatible agents

This managed block is intentionally runtime-neutral. Codex, OpenClaw, Hermes, Devin, and other agents that consume a repository-root `AGENTS.md` may share it without replacing one another's instructions.

{{TRUST_ROUTING}}

If `.agents/skills/` exists, use the installed workflows when they match the task. Do not require that folder for agents that only consume `AGENTS.md`.

{{FINAL_REPORT_CONTRACT}}

For meaningful work, report exactly one routing-context estimate state:
workspace-to-task narrowing, estimated overhead, neutral, or
unavailable/not comparable. This is a deterministic local context estimate,
not provider-reported model-token usage.

For concurrent agent work, set a stable `KNOWLEDGE_AGENT_ID` and use separate git worktrees or branches. A newly connected AGENTS.md-compatible agent must reuse this shared managed block instead of adding a second runtime-specific `.knowledge` block.
