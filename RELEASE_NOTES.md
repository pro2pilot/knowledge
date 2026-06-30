# Release Notes

## v3.2.4 - Install source and integration selection hotfix

v3.2.4 tightens the public install path so agents select the current curated
release asset instead of old generic assets, GitHub source archives, or source
checkouts copied into target repositories.

> **Install note:** For new installs, always start from
> https://github.com/pro2pilot/knowledge/releases/latest and download the
> attached asset named `knowledge-vX.Y.Z.zip` that matches the latest release
> tag. Do not use GitHub "Source code" archives, GitHub "Download ZIP",
> `default.knowledge.zip`, `.knowledge.zip`, `knowledge.zip`, or `git clone` as
> an install package.

### Fixed

- Update checks now accept only the exact `knowledge-v<tag>.zip` asset from the
  latest GitHub release and no longer fall back to generic or older ZIP assets.
- First-run integration install no longer treats `--all` as a normal setup path;
  installing every agent bridge now requires explicit `--all --confirm-all`.
- A no-runtime integration run now returns `runtime_required` without creating
  `AGENTS.md`, `CLAUDE.md`, `.agents/`, `.claude/`, `.opencode/`, or other
  vendor bridge folders.

### Added

- Agent-facing docs for connecting another agent later to the same already
  installed `.knowledge/` repository.
- A focused update-selection self-test that proves old/generic assets are not
  selected when a current exact release asset exists.

## v3.2.3 - Install source-checkout hotfix

v3.2.3 closes an install footgun where an agent could clone this repository
into a target project, leave it as `knowledge-src/`, and then import that
source checkout as if it were project code.

> **Install note:** Do not use GitHub "Download ZIP" as the install package. Use the release asset only.

### Added

- Root `INSTALL.md` with an agent-focused install contract.
- Machine-readable `install-policy.json` for agents and tooling.
- `install-check` detection for source checkouts in the target root, including `knowledge-src/`.
- Release self-tests that prove source checkouts are blocked before import and ignored by direct ingest/sync fallbacks.

### Changed

- `flow import` now runs `install-check` before ingest.
- `ingest-existing-project.js` ignores detected `.knowledge` source checkouts instead of registering them as project modules.
- `sync-tracked.js --scan --discover` ignores detected `.knowledge` source checkouts.
- README keeps the install warning visible while moving detailed agent-only instructions into a collapsed contract.

### Fixed

- A fresh install can no longer silently produce `knowledge_src` modules and large repair queues from installer source files left in the target project.

## v3.2.2 - Release cleanup and bridge integrations

v3.2.2 cleans the public install surface and adds explicit bridge support for OpenClaw and Hermes.

> **Install note:** Do not use GitHub "Download ZIP" as the install package. Use the release asset only.

### Added

- `--runtime openclaw` installs `AGENTS.md` plus `.agents/skills/`.
- `--runtime hermes` installs the generic `AGENTS.md` bridge without creating an unconfirmed vendor folder.
- Quick-Start and integration docs now list OpenClaw and Hermes directly while Pi remains a manual bridge target.

### Changed

- Active version and schema markers are updated to `3.2.2`.
- Release artifact commands and validation examples now point to `dist/knowledge-v3.2.2.zip`.
- Graphiti and Zep are described as not bundled in the free/core install asset.

### Removed

- Stale debug/pro export commands and marketing-pack generation from the public release line.
- Source runtime proof folders that are not part of the install asset.

## v3.2.1 - Free Core trust graph hardening

v3.2.1 raises the local free-core graph from a sparse wiki-dot view to an actionable source-of-truth and routing graph.

> **Install note:** Do not use GitHub "Download ZIP" as the install package. Use the release asset only.

### Added

- A generated `free_core_trust_graph` view in `maps/wiki_graph.json`.
- Source-of-truth order nodes for code, tests, evidence, module cards, decisions, wiki, sessions, and external memory.
- Inferred module-to-wiki and source-of-truth edges so a fresh release no longer renders as disconnected dots.
- Inspector graph diagnostics for relation counts, broken edges, orphan pages, readiness, and rebuild commands.
- A focused free-core graph self-test that fails if the graph regresses to zero useful relations.
- `docs/free-core-graph.md` with the free/core graph boundary and readiness checklist.

### Changed

- Active version and schema markers are updated to `3.2.1`.
- Visual Inspector now labels the graph as **Free Core Trust Graph** and renders colored relation lanes instead of a generic wiki graph.
- Wiki lint now checks orphan status only for wiki pages, not for source-of-truth or module graph nodes.
- README is now a shorter install/source hub with a link map to the human-readable site docs.
- Website planning assets now target the 3.2.1 release line and include an `Embed .knowledge in your app` documentation page.
- Release artifact commands and validation examples now point to `dist/knowledge-v3.2.1.zip`.

### Fixed

- The free graph is no longer practically useless on a fresh seed with no typed wiki links.
- The release packager and validator block generated QA maintenance files and non-install maintainer notes from the install ZIP.
- Source-of-truth and external-memory advisory boundaries are visible in the free Inspector instead of living only in prose docs.

## v3.2.0 - Universal final-report hardening

v3.2.0 aligned installed agent integrations around one stricter final-report contract, update checks, and memory-provider boundaries.

### Highlights

- Shared final-report contract across installed agents.
- Visual Inspector update UI and explicit local update apply boundary.
- Mem0 and Pinecone adapter CLIs that keep external memory advisory-only.
- Graphiti and Zep provider manifests kept outside the free/core release artifact.

## v3.1.9 - Install and Git policy hardening

v3.1.9 focused on safe install/update packaging, Git policy, and reproducible release artifacts.

## v3.1.8 - First public release

Initial public release of `.knowledge by Pro2Pilot`.
