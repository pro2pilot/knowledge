# Changelog

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
