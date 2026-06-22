# Claude Code .knowledge notes

{{TRUST_ROUTING}}

Prefer installed skills under `.claude/skills/` for audit, routing bundle refresh, search index, doctor checks, sync, handoff, ingest, concurrent-agent checks, metrics collection, and PR summary generation.

Do not omit routing or metrics outcomes from the final reply. If `.knowledge/metrics/baseline.json` is missing or stale, say so explicitly instead of silently skipping token-savings reporting.

{{FINAL_REPORT_CONTRACT}}

For concurrent agent work, set a stable `KNOWLEDGE_AGENT_ID` and use separate git worktrees/branches.
