# Memory Provider Migration Inventory

Generated for the 3.2.0 Mem0 OSS migration.

## Claude MEM References Found

- `tools/external-memory-status.js` previously detected `claude-auto-memory` as a first-class provider.
- `tools/build-routing-bundle.js` previously summarized Pinecone or Claude memory as external memory status.
- `tools/build-visual-inspector.js` previously rendered a generic External Memory table.
- `tools/render-graph-execution.js` previously showed Claude memory in the external-memory bridge graph.
- `tools/self-test-team-mode.js` used `CLAUDE_MEMORY_PATH` to simulate shared external memory warnings.
- `docs/team-mode.md`, `docs/product/free-project-logic.md`, `docs/product/graphs-ui-stack-layers.md`, `docs/product/paid-inspector-features.md`, and implementation notes referenced Claude MEM as a planned bridge.
- `docs/external-memory/claude-mem-bridge.md` documented the old bridge path.

## Existing Commands

- `node .knowledge/tools/external-memory-status.js --json`
- `node .knowledge/tools/external/pinecone-search.js "query" --dry-run`
- `node .knowledge/tools/external/pinecone-upsert.js --dry-run`

## New Commands

- `node .knowledge/tools/memory-provider.js list --json`
- `node .knowledge/tools/memory-provider.js preview mem0-oss --json`
- `node .knowledge/tools/memory-provider.js install mem0-oss --version mem0ai==2.0.4 --yes-i-reviewed-license --json`
- `node .knowledge/tools/memory-provider.js update mem0-oss --to mem0ai==2.0.4 --yes-i-reviewed-license --json`
- `node .knowledge/tools/memory-provider.js uninstall mem0-oss --json`
- `node .knowledge/tools/memory-provider.js status-all --json`
- `node .knowledge/tools/memory-provider.js migrate-legacy --json`

## Removed As First-Class Provider

Claude MEM is no longer represented as an installable/updateable provider. It is only detected as legacy advisory data.

## Migrated

- Free/core provider manifests now live under `memory-providers/mem0/` and `memory-providers/pinecone/`.
- External memory status is generated from `tools/lib/memory-providers.js`.
- Inspector now renders Memory Providers cards.
- Doctor checks Mem0 manifest/license/pin, Pinecone status, advisory-only policy, staged runtime state, and legacy Claude MEM warnings.
- Reports are written to `maintenance/external_memory_status.json` and `metrics/external_memory.json`.

## Legacy Notes

If legacy Claude MEM artifacts are found under `<stateRoot>/external_memory/claude_mem/`, `migrate-legacy` writes `DEPRECATED.md`. It does not delete user data by default.
