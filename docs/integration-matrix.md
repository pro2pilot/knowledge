# Integration Matrix

| Integration | Status | Path | Purpose |
|---|---:|---|---|
| Codex | ready | `AGENTS.md`, `.agents/skills/` | Give Codex repo instructions and repeatable `.knowledge` workflows. |
| Claude Code | ready | `CLAUDE.md`, `.claude/skills/` | Give Claude Code the same workflows and safety rules. |
| OpenCode | ready | `.opencode/commands/` | Add command-style access to scan/lint/doctor/search/handoff. |
| Gemini CLI | ready | `GEMINI.md` | Add a repo-local instruction bridge into `.knowledge`. |
| GitHub Copilot | ready | `.github/copilot-instructions.md` | Add Copilot repository instructions for `.knowledge`. |
| Devin | ready | `.devin/rules/knowledge.md` | Add Devin/Cascade-style repo rules for `.knowledge`. |
| Windsurf Cascade | ready | `.devin/rules/knowledge.md` | Add Cascade-compatible repo rules for `.knowledge`. |
| Continue | ready | `.continue/rules/knowledge.md` | Add Continue rule-based `.knowledge` instructions. |
| Roo Code | ready | `.roo/rules/knowledge.md` | Add Roo Code rule-based `.knowledge` instructions. |
| Aider | ready | `CONVENTIONS.md`, `.aider.conf.yml` | Add Aider read-only conventions for `.knowledge`. |
| OpenClaw / Hermes / Pi | documented bridge | `.knowledge/Quick-Start.md` or `AGENTS.md` if supported | Use generic instructions until a stable repo-local rules convention is confirmed. |
| Git hooks | optional | `.git/hooks/*` managed block | Refresh knowledge after commit/merge/checkout. |
| GitHub Actions | templates | `.knowledge/github-action-templates/` | Run health/PR/evaluation workflows in CI after copying templates. |
| Pinecone Local | optional bridge | `external_memory/` | Local/dev/CI cold-archive emulator mode. |
| Pinecone Cloud | optional bridge | `external_memory/` | Managed cold archive for large static corpora. |
| Local inspector | optional UI | `inspector.js` | Screenshots, demos, onboarding, debugging. |
