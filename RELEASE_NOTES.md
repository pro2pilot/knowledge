# Release Notes

## v3.2.1 - Free Core trust graph hardening

v3.2.1 raises the local free-core graph from a sparse wiki-dot view to an actionable source-of-truth and routing graph.

> **Install note:** Do not use GitHub "Download ZIP" as the install package. Use the release asset only.

### Added

- A generated `free_core_trust_graph` view in `maps/wiki_graph.json`.
- Source-of-truth order nodes for code, tests, evidence, module cards, decisions, wiki, sessions, and external memory.
- Inferred module-to-wiki and source-of-truth edges so a fresh release no longer renders as disconnected dots.
- Inspector graph diagnostics for relation counts, broken edges, orphan pages, readiness, and rebuild commands.
- A focused free-core graph self-test that fails if the graph regresses to zero useful relations.
- `docs/free-core-graph.md` with the free/pro graph boundary and readiness checklist.
- `docs/site-github-canonical-boundary.md` with the canonical split between website explanation and GitHub implementation proof.

### Changed

- Active version and schema markers are updated to `3.2.1`.
- Visual Inspector now labels the graph as **Free Core Trust Graph** and renders colored relation lanes instead of a generic wiki graph.
- Wiki lint now checks orphan status only for wiki pages, not for source-of-truth or module graph nodes.
- README is now a shorter install/source hub with a link map to the human-readable site docs.
- Website planning assets now target the 3.2.1 release line and include an `Embed .knowledge in your app` documentation page.
- Release artifact commands and validation examples now point to `dist/knowledge-v3.2.1.zip`.

### Fixed

- The free graph is no longer practically useless on a fresh seed with no typed wiki links.
- The release packager and validator block generated QA maintenance files plus private strategy/product/pro-spec notes from the install ZIP.
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
