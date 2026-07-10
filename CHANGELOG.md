# Changelog

## 3.2.11 Mem0 list normalization patch

- Prepared the next release source directory from the final 3.2.10 release
  line.
- Fixed live Mem0 `list` output so records from Mem0 2.x responses are exposed
  as top-level `records`/`results`, including stable `id` fields for follow-up
  delete/cleanup commands.
- Added regression coverage for the observed `raw.raw.results` response shape
  so agents no longer need to traverse raw provider internals to find memory
  ids.
- Hardened SPARK Battle QA so `failed=0` means zero unexpected semantic
  failures, with explicit expected-negative and environment-blocked outcomes.
- Added real local FastEmbed utility assertions for persisted add and non-empty
  search/recall/list, plus effective lock contention injection.
- Made custom shared roots consistent across configure/setup/status and added
  source-hash freshness checks for final release evidence.
- Made the live Node-to-Python Mem0 payload ASCII-safe via UTF-8 base64 transport
  so Unicode project paths and memory text survive Windows process boundaries.
- Removed mojibake from Mem0 agent-facing setup output.
- Added semantic JSON validation to release/evaluation checks and made full or
  release mode require a current memory battle report.
- Added evaluation latency and routing context-economy fields for measured,
  claim-safe release evidence.
- Made `flow` and the system updater treat semantic JSON failures as failures,
  including a `doctor` process that exits zero with `status: broken`.
- Added post-update SHA-256 parity, explicit obsolete-system-file cleanup,
  final post-check preservation proof for protected curated files, and
  machine-readable backup disposition.
- Added confirmation-gated pruning for verified backups; unverified backups are
  retained and legacy project-root backup/QA/baseline directories are excluded
  from ingest and sync.
- Added deterministic update bootstrap for installed artifacts that have not
  completed project initialization, while initialized projects continue to use
  the direct release refresh path.
- Made routing generation tolerant of legacy external-memory provider maps and
  made free-core graph diagnostics depend on structural invariants rather than
  fixture size.
- Required the current release note in packaged artifacts and rejected release
  notes newer than the artifact version.
- Normalized runtime-generated report schemas to the installed system version
  and added a focused schema/dependency hygiene self-test.
- Decoupled the public benchmark runner from maintainer-only packaging tools.
- Made release-impact classification include committed, staged, unstaged, and
  untracked changes; an unavailable git baseline now requires the conservative
  full/conformance path instead of allowing a quick release decision.
- Made the team-mode doctor flow regenerate isolated workspace health reports
  and check the canonical shared append-only event store; added regression
  assertions for semantic health and required runtime artifacts.

## 3.2.10 Mem0 storage diagnostics patch

- Made Mem0 provider status follow the actual configured Qdrant path when
  `config.meta.json` has stale shared/project-local scope metadata.
- Added explicit stale-scope fields so agents can see
  `metadata_scope_mismatch`, the metadata scope, and the path-inferred scope.
- Classified Qdrant lock/permission failures as storage availability problems
  instead of missing Mem0/Python runtime installs.
- Preserved cached Mem0 runtime/package availability when Qdrant storage is
  locked or not writable.
- Updated Mem0 recipes so agents do not silently move shared provider storage
  into a project-local path as a lock workaround.
- Polished the Inspector updater: one visible `Update` action, explicit
  `Auto-check: On/Off` launch-check mode, no automatic apply, and clearer
  in-session refresh/shutdown feedback.
- Removed stale mojibake text from the generated Inspector UI.
- Excluded maintainer-only release self-tests from the public runtime artifact
  when they depend on internal packaging or validation tools.
- Full release gate was not run for this patch preparation.

## 3.2.9 Inspector update polish and Local FastEmbed hardening

- Simplified the live Inspector update panel to a launch-checked status and a
  single Update action.
- Refreshed the live Inspector update status in the current session after an
  applied system update.
- Clarified Mem0 status semantics across offline status, live runtime health,
  and operational list/add/search/recall checks.
- Added `fastembed_onnx_external_data_path_error` for Local FastEmbed ONNX
  model-cache failures and preserved cached Mem0 runtime availability for that
  diagnostic.
- Added `fastembed_model_download_timeout` for first-run Local FastEmbed model
  warmup/download timeouts, with long-timeout retry guidance that does not
  confuse HuggingFace download messages with OpenAI quota.
- Improved Local FastEmbed Python runtime selection so configuration can prefer
  a supported discovered runtime, and live commands can reuse a cached
  `selected_python` from Mem0 config/status metadata.
- Preferred the configured Python runtime from `config.meta.json` over stale
  runtime-status cache entries for live Mem0 commands.
- Reported Mem0 as configured when `config.json` exists, even without an
  install approval receipt.
- Required explicit live Mem0 provider config before operational storage
  startup so unconfigured commands cannot fall back to default `/tmp/qdrant`.
- Added a shared Mem0 provider storage adoption recipe using explicit
  `--provider-scope shared` for existing non-shared configs.
- Full local release gate and Docker/Linux release gate passed during release
  preparation. Native macOS/iOS runtime testing was not run.

## 3.2.8 Mem0 shared provider onboarding

- Changed Mem0 setup policy so `setup mem0-oss --live --json` must stop and
  ask for an explicit embedding backend choice when no Mem0 config exists.
- Kept OpenAI API and Local FastEmbed as normal guided choices, but removed the
  silent OpenAI-by-default config creation from setup/recipe generation.
- Added shared per-user Mem0 provider storage as the default, with
  project-keyed Qdrant/history/runtime directories so multiple projects can
  discover the same provider location without mixing project memory.
- Added explicit project-local provider storage via `--provider-scope project`
  and documented it as a rare opt-in recipe.
- Extended Mem0 status/config metadata to report provider scope, shared provider
  root, project storage key, Qdrant path, and history DB path.

## 3.2.7 Mem0 embedding backend choice and Inspector file links

- Added `memory-provider.js configure-embeddings mem0-oss --json` so Mem0
  embedding backend selection is a separate agent-guided step from setup.
- Promoted Local FastEmbed from quota fallback to a normal onboarding choice,
  with pinned `fastembed==0.5.1`, programmatic dimension detection, and
  Qdrant collection names tied to provider/model/dimensions.
- Documented OpenAI API vs Local FastEmbed in
  `docs/cookbook/10-mem0-embedding-backends.md`, including the LLM provider,
  embedding provider, vector store, and history store split.
- Blocked reuse of a previous Qdrant collection when the requested embedding
  provider, model, or dimensions differ.
- Fixed Visual Inspector Trust Graph next-action file links by routing them
  through the live Inspector file-open endpoint instead of inert copied paths.
- Added a FastEmbed runtime guard so unsupported Python runtimes stop before
  pinned `fastembed==0.5.1` install/smoke, with Python 3.12 guidance.
- Added deterministic Inspector next-action smoke coverage for live
  `/api/files/open` behavior.
- Removed `docs/release-gates.md` from the public release source and blocked it
  from future public artifacts.
- Added source-only maintainer release policy, packaging, validation, release
  gate, post-release asset, conformance, impact, SBOM, notices, and source
  deliverable tooling.
- Excluded maintainer-only release/QA/CI tooling from installed user
  `.knowledge` artifacts and added artifact-forbidden rules so future leaks
  fail validation.
- Hardened source-only release tooling so post-release checks block wrong
  GitHub author/uploader identity, unsafe download directory cleanup, stale
  candidate artifact evidence, artifact/package version mismatch, unsafe ZIP
  inflation, Unicode entry spoofing, and central directory size drift.
- Added release policy required-entry profiles for public runtime, source
  release, and maintainer-only surfaces.
- Hardened release artifact validation for unsafe ZIP paths, duplicate/NFC
  entries, unsupported compression methods, CRC mismatch, local/central name
  mismatch, size/ratio caps, and lightweight token leakage patterns.
- Replaced Mem0 cookbook `OPENAI_API_KEY` examples with safe placeholders that
  do not look like committed secrets.

## 3.2.6 Mem0 guided setup and recipe gate

- Added `memory-provider.js setup mem0-oss --live --json` as the recommended
  one-command Mem0 onboarding flow.
- Added deterministic `write-recipe` and `validate-recipe` commands for
  `docs/cookbook/09-mem0-live-memory.md`.
- Added machine-readable Mem0 CLI `help --json` metadata so recipe validation
  checks generated commands against the actual dispatch surface.
- Added repo-local Mem0 config and runtime status cache under
  `.knowledge/external_memory/mem0`.
- Split Mem0 status fields into `receipt_present`, `runtime_available`, and
  `package_installed` so receipts do not masquerade as package installs.
- Updated live Mem0 diagnostics, network-call labels, telemetry defaults,
  Qdrant serialization, and Mem0 2.0.4 filter-based search/list calls.
- Classified live add/search/recall embedding provider connection failures with
  explicit diagnostics and filtered safe Qdrant/spaCy shutdown noise from stderr.
- Preserved cached Mem0 runtime availability and last live health timestamp when
  later live add/search/recall fails at the embedding-provider boundary.
- Raised live Mem0 operation defaults to tolerate slow first local Qdrant
  startup on Windows while keeping discovery probes short.
- Enforced the pinned Mem0 runtime version during live setup so a mismatched or
  unreported `mem0ai` version returns one exact pinned install command instead of
  reporting connected.
- Exposed cached Mem0 runtime version and pin-match fields in offline status and
  the Inspector onboarding card.
- Added Inspector Mem0 onboarding actions and a release gate for Mem0 recipe
  quality.
- Added a dedicated Mem0 install page and covered it in the recipe quality
  self-test so setup, runtime status, repo-local paths, and advisory boundary
  stay documented.

## 3.2.5 Inspector first-run, updater, graph shelf, and shutdown

- Added a live Inspector `Turn off` control that closes the local server and
  releases the active port.
- Moved the Free Core Trust Graph directly under Knowledge Trust metrics and
  made it collapsible with in-page node drilldown.
- Made Inspector update actions real: check, validate release zip, dry-run,
  apply with confirmation, verify upgrade, and preserve project knowledge.
- Added deterministic update e2e coverage that simulates a future release.
- Normalized Inspector launcher roots so passing a project root no longer
  creates a stray root-level `maintenance/` folder.
- Updated install/import follow-up copy to state that `.knowledge` already works
  and Inspector is open for First-run setup.

## 3.2.4 install source and integration selection hotfix

- Changed update asset selection to accept only the exact `knowledge-v<tag>.zip`
  asset attached to the latest GitHub release.
- Added a focused update-selection self-test so generic or old ZIP assets cannot
  be silently selected.
- Changed first-run integration behavior so `--all` requires
  `--all --confirm-all` and no-runtime runs create no agent bridge files.
- Added docs for connecting another agent later without reinstalling the system
  or creating every vendor integration folder.
- Updated README install copy to point agents at `/releases/latest` instead of a
  fixed release tag.

## 3.2.3 install source-checkout hotfix

- Added `INSTALL.md` and `install-policy.json` so agents have a clear release-asset install contract.
- Added `install-check` detection for `knowledge-src/` and other `.knowledge` source checkouts left in the target root.
- Added pre-import protection by running `install-check` at the start of `flow import`.
- Updated ingest/sync to ignore detected `.knowledge` source checkouts instead of treating them as project modules.
- Added release self-tests for the `knowledge-src/` failure mode.

## 3.2.2 release cleanup

- Added explicit OpenClaw and Hermes integration commands without creating unconfirmed vendor folders.
- Removed stale debug/pro export and marketing-pack commands from the public release line.
- Clarified that Graphiti and Zep are not bundled in the free/core install asset.
- Updated release artifact examples to `3.2.2`.

## 3.2.1 release hardening

- Added release artifact validation for local path leaks, source metadata, runtime provider state, and generated Inspector output.
- Added Mem0 OSS runtime/test-adapter commands that stay honest about `runtime_not_installed` unless a real runtime is verified.
- Added shared `knowledge.memory_adapter.v1` contract and Pinecone adapter CLI with dry-run by default and explicit live calls only.
- Upgraded the free Visual Inspector to a static tabbed UI with Command Center, Team Mode, Memory Providers, and release checks tabs.
- Updated `serve-inspector.js` to serve the generated Inspector instead of a separate minimal page.

## 3.2.1

- Added generic Memory Provider Interface and CLI.
- Added Mem0 OSS as recommended optional free/core provider.
- Kept Pinecone as optional vector/cloud retrieval provider.
- Removed Claude MEM as a first-class provider and added safe legacy migration notes.
- Added external memory status report and metrics schema.
- Added Memory Providers cards to the local Inspector.
- Documented that Graphiti and Zep provider files are excluded from the free/core artifact.
