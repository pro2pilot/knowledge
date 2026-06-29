# Changelog

## 3.2.1 release hardening

- Added release artifact validation for local path leaks, source metadata, runtime provider state, and generated Inspector output.
- Added Mem0 OSS runtime/test-adapter commands that stay honest about `runtime_not_installed` unless a real runtime is verified.
- Added shared `knowledge.memory_adapter.v1` contract and Pinecone adapter CLI with dry-run by default and explicit live calls only.
- Upgraded the free Visual Inspector to a static tabbed UI with Command Center, Team Mode, Memory Providers, Export / Debug, and Pro Preview tabs.
- Updated `serve-inspector.js` to serve the generated Inspector instead of a separate minimal page.
- Added `export-pro-snapshot.js` and `export-debug-bundle.js` with redacted provider metadata.
- Added runnable Pro Inspector app shell and demo data contracts in the separate paid workspace.

## 3.2.1

- Added generic Memory Provider Interface and CLI.
- Added Mem0 OSS as recommended optional free/core provider.
- Kept Pinecone as optional vector/cloud retrieval provider.
- Removed Claude MEM as a first-class provider and added safe legacy migration notes.
- Added external memory status report and metrics schema.
- Added Memory Providers cards to the local Inspector.
- Added Graphiti and Zep provider contracts in the separate paid Inspector workspace.
- Added release gates that block Graphiti/Zep provider files from the free/core artifact.
