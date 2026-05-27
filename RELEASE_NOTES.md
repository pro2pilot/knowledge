# Release Notes

## v3.1.9 - Install and Git policy hardening

v3.1.9 focuses on making `.knowledge` installs, updates, release packaging, and Git behavior safe and reproducible for agents and humans.

### Added

- `tools/package-release.js` for building a curated install artifact: `dist/knowledge-v3.1.9.zip`.
- `tools/install-check.js` for validating fresh installs, detecting nested `.knowledge/.git`, and producing machine-readable reports.
- `tools/update-system-files.js` for updating framework/system files without overwriting project-specific knowledge.
- `tools/git-policy.js`, `.knowledge` Git policy docs, and Git policy templates.
- `tools/self-test-install-policy.js` covering fresh install, bad install repair, update preservation, Git ignore behavior, and Windows-safe paths.
- Codex release-preparation workflow skill.

### Changed

- Public install archives are packaged as `.knowledge/...` and exclude source repository metadata, runtime state, logs, generated reports, caches, and local release artifacts.
- Installed `.knowledge/.gitignore` is generated from `templates/git-policy/.knowledge.gitignore`, separate from the source repository `.gitignore`.
- Text files in the release ZIP are normalized to LF.
- README and Quick Start now document three explicit paths: fresh install, existing `.knowledge` update, and migration from non-`.knowledge`.
- `config.yaml` and seed/schema markers are updated to `3.1.9`.

### Fixed

- `install-check --fix --yes` now reports `pre_fix`, `fixes_applied`, and `post_fix`, with top-level status matching the post-fix result.
- A nested `.knowledge/.git` is moved to a safe backup only when explicitly requested with `--fix --yes`.
- Git add smoke tests verify generated/runtime artifacts are ignored by default.
- Package release summaries distinguish excluded entries from recursive excluded files.

### Upgrade Note

For an existing `.knowledge` installation, do not replace the whole folder. Extract the new release artifact to a temporary folder and run:

```bash
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --dry-run
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --apply --yes
```

Project-specific knowledge such as `wiki/`, `modules/`, `evidence/`, `decisions.json`, `maintenance/`, `maps/`, and `sessions/` is preserved unless the user explicitly resets it.

### QA

- JavaScript syntax checks
- JSON parse checks
- Package release build
- Install policy self-test
- Fresh artifact smoke test
- Bad install repair smoke test
- Existing update preservation smoke test
- Git add smoke test for generated/runtime ignores

### Assets

- `knowledge-v3.1.9.zip`
- `knowledge-v3.1.9.zip.sha256`

### Known Limitations

- `update-system-files.js` does not prune deprecated system files automatically. This is intentional for safety; removal should be a separate reviewed action.

## v3.1.8 - First public release

Initial public release of `.knowledge by Pro2Pilot`.

### Added

- One first-read routing bundle.
- Trust and freshness status.
- Repair queue.
- Local search scopes.
- Visual Inspector.
- Cookbook flows.
- Official templates.
- Secret scan baseline.
- Pinecone Local / Pinecone Cloud bridge, disabled by default.
- Codex, Claude Code, OpenCode integrations.
- Optional advisory update checks, disabled by default.
- Apache-2.0 core.

### Notes

Metrics are order-of-magnitude and based on a synthetic SaaS-shape fixture. Tiny repositories may show overhead because the routing bundle has fixed structure cost.
