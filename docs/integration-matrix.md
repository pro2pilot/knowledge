# Integration Matrix

| Integration | Status | Path | Purpose |
|---|---:|---|---|
| Codex skills | ready | `.agents/skills/` | Give Codex repeatable `.knowledge` workflows. |
| Claude Code skills | ready | `.claude/skills/` | Give Claude Code the same workflows and safety rules. |
| OpenCode commands | ready | `.opencode/commands/` | Add command-style access to scan/lint/doctor/search/handoff. |
| Git hooks | optional | `.git/hooks/*` managed block | Refresh knowledge after commit/merge/checkout. |
| GitHub Actions | templates | `.knowledge/github-action-templates/` | Run health/PR/evaluation workflows in CI after copying templates. |
| Pinecone Local | optional bridge | `external_memory/` | Local/dev/CI cold-archive emulator mode. |
| Pinecone Cloud | optional bridge | `external_memory/` | Managed cold archive for large static corpora. |
| Local inspector | optional UI | `serve-inspector.js` | Screenshots, demos, onboarding, debugging. |
