# Integration Matrix

| Integration | Status | Path | Purpose |
|---|---:|---|---|
| Codex | ready | `AGENTS.md`, `.agents/skills/` | Give Codex repo instructions and repeatable `.knowledge` workflows. |
| Claude Code | ready | `CLAUDE.md`, `.claude/skills/` | Give Claude Code the same workflows and safety rules. |
| OpenCode | ready | `.opencode/commands/` | Add command-style access to scan/lint/doctor/search/handoff. |
| OpenClaw | ready | `AGENTS.md`, `.agents/skills/` | Add OpenClaw repo instructions and workspace skills for `.knowledge`. |
| Hermes | ready bridge | `AGENTS.md` | Add a documented generic repo-local bridge without creating an unconfirmed vendor folder. |
| Gemini CLI | ready | `GEMINI.md` | Add a repo-local instruction bridge into `.knowledge`. |
| GitHub Copilot | ready | `.github/copilot-instructions.md` | Add Copilot repository instructions for `.knowledge`. |
| Devin | ready via documented `AGENTS.md`; vendor canary pending | `AGENTS.md`, `.devin/rules/knowledge.rules` | Use the shared root bridge as the primary contract and keep a separate specialized Devin rule without sharing Windsurf files. |
| Windsurf Cascade | ready | `.windsurf/rules/knowledge.md` | Add a dedicated Windsurf workspace rule with `trigger: always_on`. |
| Continue | ready | `.continue/rules/knowledge.md` | Add Continue rule-based `.knowledge` instructions. |
| Roo Code | ready | `.roo/rules/knowledge.md` | Add Roo Code rule-based `.knowledge` instructions. |
| Aider | ready | `CONVENTIONS.md`, `.aider.conf.yml` | Add Aider read-only conventions for `.knowledge`. |
| Pi / other agents | documented bridge | `.knowledge/Quick-Start.md` | Use generic instructions until a stable repo-local rules convention is confirmed. |
| Git hooks | optional | `.git/hooks/*` managed block | Refresh knowledge after commit/merge/checkout. |
| GitHub Actions | templates | `.knowledge/github-action-templates/` | Run health/PR/evaluation workflows in CI after copying templates. |
| Pinecone Local | optional bridge | `external_memory/` | Local/dev/CI cold-archive emulator mode. |
| Pinecone Cloud | optional bridge | `external_memory/` | Managed cold archive for large static corpora. |
| Local inspector | optional UI | `inspector.js` | Screenshots, demos, onboarding, debugging. |

## Coexistence rules

- Codex, OpenClaw, Hermes, and Devin reuse one runtime-neutral `.knowledge` managed block in the repository-root `AGENTS.md`. Installation order does not change the block or remove user-authored content.
- Codex and OpenClaw may additionally share `.agents/skills/`; Hermes does not remove that folder.
- Devin and Windsurf always use different vendor files: `.devin/rules/knowledge.rules` and `.windsurf/rules/knowledge.md`. Devin receives its documented primary instructions through `AGENTS.md`; the vendor-specific `.rules` bridge is supplemental until a live Devin discovery canary is recorded.
- Windsurf rules use frontmatter with `trigger: always_on`. If a shared root `AGENTS.md` also exists, the Windsurf rule acts only as a concise runtime bridge and does not duplicate the full shared contract.

## Integration write safety

Before writing any bridge, the installer builds a complete write plan and validates the repository root, every existing parent segment, and every existing target. Symlinks, junctions, reparse points, non-directory parents, and paths outside the repository are rejected before mutation. `--all --confirm-all` uses the same full-plan preflight: one unsafe destination blocks the complete install rather than partially installing other agents.
