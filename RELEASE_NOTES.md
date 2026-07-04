# Release Notes

## v3.2.9 - Inspector update polish and Local FastEmbed hardening

v3.2.9 improves the local Inspector update experience and tightens Mem0 Local
FastEmbed runtime behavior for agent-guided installs.

### Changed

- Simplified the live Inspector update panel to one Update action backed by the
  existing launch-time release check.
- After an update is applied, the current Inspector session now refreshes the
  displayed update state and current version immediately.
- Clarified Mem0 setup diagnostics so agents distinguish offline status, live
  runtime health, and operational list/add/search/recall smoke checks.
- Added a Local FastEmbed ONNX model-cache diagnostic for live Mem0 operations,
  with guidance to repair Python/FastEmbed runtime instead of moving shared
  provider storage.
- Added a Local FastEmbed model download timeout diagnostic for first-run model
  warmup, including long-timeout retry guidance and cached Python runtime reuse.
- Added a shared Mem0 provider storage adoption recipe for existing projects
  that need to return to the per-user default with explicit `--provider-scope
  shared`.
- Live Mem0 Python selection now prefers the configured runtime from
  `config.meta.json` over stale runtime-status cache entries.
- Mem0 provider status now reports `configured=true` when `config.json` exists,
  even if there is no install approval receipt.
- Live Mem0 add/search/recall/list now require explicit provider config before
  storage startup, preventing an accidental fallback to default `/tmp/qdrant`.

### Verification

- Full local release gate passed.
- Public artifact validation passed with 319 entries and 0 violations.
- Inspector next-action, launcher, UI, action, and update e2e checks passed.
- Mem0 focused checks passed, including provider choice, shared storage,
  unsupported FastEmbed runtime guard, cache diagnostics, and status semantics.
- Live Mem0 Local FastEmbed health/add/search/recall/list passed using
  `intfloat/multilingual-e5-large` at 1024 dimensions.
- Docker/Linux release gate passed during release preparation.
- Native macOS/iOS runtime testing was not run for this release. macOS
  compatibility is covered only indirectly through POSIX/Linux Docker checks.

## v3.2.7 - Mem0 embedding backend choice and Inspector file links

v3.2.7 makes Mem0 embedding selection an explicit agent-guided install choice
and fixes Visual Inspector Trust Graph next-action file links. Agents can keep
setup simple, choose OpenAI API or Local FastEmbed separately, validate
dimensions before creating Qdrant collections, and open referenced files from
the live Inspector without copying paths by hand.

### Added

- `node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --json`.
- OpenAI embedding configuration with `text-embedding-3-small`.
- Local FastEmbed configuration with pinned `fastembed==0.5.1`, model
  dimension detection, model warmup guidance, and smoke-test flow.
- A dedicated cookbook recipe for OpenAI API vs Local FastEmbed onboarding.
- FastEmbed runtime guard guidance for unsupported Python runtimes, preferring
  Python 3.12 before install or smoke.
- Deterministic Inspector next-action smoke coverage for live `/api/files/open`
  behavior.
- Source-only maintainer release policy, packaging, validation, release gate,
  post-release asset, conformance, impact, SBOM, notices, and source deliverable
  tooling.
- Required-entry profiles for public runtime, source release, and
  maintainer-only release surfaces.

### Fixed

- FastEmbed setup refuses to reuse a Qdrant collection created for another
  provider, model, or embedding dimension.
- Mem0 configuration now separates LLM provider, embedding provider, vector
  store, and history store in generated JSON.
- Visual Inspector Trust Graph next-action file links now use the live
  `/api/files/open` endpoint with token protection and path traversal checks.
- Release packaging excludes restore-trust runtime reports from public zips.
- `docs/release-gates.md` is removed from the public release source and blocked
  from future public artifacts.
- Maintainer-only release/QA/CI tooling is excluded from installed user
  `.knowledge` artifacts and is forbidden by artifact validation rules if it
  leaks back into a ZIP.
- Mem0 cookbook `OPENAI_API_KEY` examples now use safe placeholders instead of
  secret-like sample assignments.
- Source-only post-release checks now block wrong GitHub release author or asset
  uploader, unsafe custom download directory cleanup, tag mismatch, and digest
  mismatch when GitHub reports a SHA-256 digest.
- Source-only release gates delete the stale candidate ZIP before packaging and
  skip artifact-dependent checks when package or validation fails.
- Release artifact validation now rejects ZIP path tricks, duplicate normalized
  entries, Unicode non-NFC names, unsupported compression, CRC mismatch,
  local/central header mismatch, central-directory size drift, excessive
  size/ratio, artifact/package version mismatch, and common secret/token leakage
  patterns.

## v3.2.6 - Mem0 guided setup and recipe gate

v3.2.6 turns Mem0 OSS onboarding into a product flow instead of an agent-written
recipe. A weak agent can run one setup command, get a receipt/config/recipe,
see live runtime status, and keep Mem0 clearly advisory-only.

## v3.2.5 - Inspector first-run, updater, graph shelf, and shutdown

v3.2.5 makes the local Inspector the obvious post-install control surface. After
install/import, `.knowledge` is already usable and the agent-facing follow-up now
states that Inspector is open for First-run setup of behavior, autonomy rules,
and chat/report preferences.

### Added

- Live Inspector `Turn off` button to close the server and release the port.
- Collapsible Free Core Trust Graph shelf immediately under Knowledge Trust
  metrics.
- In-page graph node detail panel for module, wiki/advisory, and source-of-truth
  nodes.
- Real Inspector update dry-run/apply flow using the verified release asset and
  `update-system-files.js`.
- Deterministic updater e2e simulation for future release zips.

### Fixed

- Inspector launcher now normalizes project roots to `.knowledge` before logging,
  so it no longer creates a stray `maintenance/` folder beside `.knowledge`.
- Update status is visible on Home when a newer release is available or a check
  fails.

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
