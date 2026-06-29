# Memory Providers

`.knowledge` is the repo-local source-of-truth, trust, freshness and repair layer. Memory providers are optional advisory context only.

Provider split:

```txt
Mem0 OSS = recommended optional universal local memory backend
Pinecone = optional vector/cloud retrieval bridge
Graphiti = not included in free/core
Zep = not included in free/core
External memory = advisory only
```

External memory can help search, retrieval, reports, repair hints and team-mode status. It cannot raise trust, overwrite curated `.knowledge` artifacts, become a required core dependency, enable itself silently, make hidden network calls, or outrank current code/tests/evidence.

## Adapter contract

All memory adapters use the same free/core safety contract:

- every result is `source_of_truth: false` and `trust_effect: advisory_only`;
- status/report commands are offline and make no provider network calls;
- live writes/searches require an explicit live command and user-controlled environment;
- adapter output redacts secrets and does not include memory text unless explicitly requested in local test mode;
- retrieved memories must be verified against current code, tests, evidence, or decisions before they influence implementation;
- memory providers can suggest repair/search context, but they cannot change `.knowledge` trust, curated artifacts, or agent routing by themselves.

## CLI

```bash
node .knowledge/tools/memory-provider.js list --json
node .knowledge/tools/memory-provider.js preview mem0-oss --json
node .knowledge/tools/memory-provider.js install mem0-oss --version mem0ai==2.0.4 --yes-i-reviewed-license --json
node .knowledge/tools/memory-provider.js update mem0-oss --to mem0ai==2.0.4 --yes-i-reviewed-license --json
node .knowledge/tools/memory-provider.js uninstall mem0-oss --json
node .knowledge/tools/memory-provider.js status mem0-oss --json
node .knowledge/tools/memory-provider.js status-all --json
node .knowledge/tools/memory-provider.js migrate-legacy --json
node .knowledge/tools/memory-mem0.js health --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
node .knowledge/tools/memory-mem0.js add --text "..." --scope repo --json
node .knowledge/tools/memory-mem0.js search "query" --json
node .knowledge/tools/memory-mem0.js list --json
node .knowledge/tools/memory-mem0.js delete --id <id> --json
node .knowledge/tools/memory-mem0.js sync-report --json
node .knowledge/tools/memory-mem0.js export-redacted --json
node .knowledge/tools/memory-pinecone.js health --json
node .knowledge/tools/memory-pinecone.js add --text "..." --json
node .knowledge/tools/memory-pinecone.js search "query" --json
node .knowledge/tools/memory-pinecone.js sync-sources --json
node .knowledge/tools/memory-pinecone.js export-redacted --json
```

`preview`, `list`, `status`, `status-all`, `doctor`, and `build-visual-inspector` are offline/report commands. They do not install packages and do not call external providers. Real Mem0 probing is only done by explicit adapter commands such as `memory-mem0.js health --adapter live --json`.

`install` and `update` require `--yes-i-reviewed-license` and a pinned version. In free core they record approval receipts only; they do not run `pip`, `npm`, Docker, or any hidden network call.

## Mem0 OSS

Mem0 OSS is the recommended optional memory backend for free/core.

Official references checked on 2026-06-06:

- Docs: https://docs.mem0.ai/open-source/overview
- Python quickstart: https://docs.mem0.ai/open-source/python-quickstart
- Package: https://pypi.org/project/mem0ai/
- License: https://github.com/mem0ai/mem0/blob/main/LICENSE

Pinned package in the provider manifest:

```bash
pip install mem0ai==2.0.4
```

Do not claim Mem0 is installed unless the package install was actually run in the user's environment. The `.knowledge` receipt only records approval and provenance.

`memory-mem0.js` exposes an explicit adapter command surface. By default it runs in dry-run mode and reports `status: runtime_not_installed`; with `--adapter test` it can store local advisory JSONL records for QA without pretending a production Mem0 runtime is installed.

`--adapter live` uses bounded Python discovery before importing Mem0. Discovery checks, in order: explicit `--python`, `KNOWLEDGE_MEM0_PYTHON`/`MEM0_PYTHON`, `VIRTUAL_ENV`/`CONDA_PREFIX`, PATH commands, Windows `py`/`pymanager` runtime listings, and standard Python install directories. It does not scan the whole disk. Only `health --adapter live` uses a 30000 ms default timeout for the live Mem0 import/health path, because the first `import mem0` on Windows can be noticeably slower than warm checks; short Python discovery/probe checks stay short. If that wait is exceeded, JSON reports `diagnostic_code: python_timeout`, and `--timeout-ms <ms>` can override the live health wait. Python probe/import timeout overrides accept `--python-timeout-ms <ms>` and the compatibility alias `--pythonTimeMs <ms>`. If Python is found but `mem0` is not importable, the JSON output reports `diagnostic_code: mem0_package_missing` and includes the exact pinned install command for that interpreter. If live writes/searches hit a qdrant lock or storage permission failure, JSON reports `diagnostic_code: mem0_storage_permission_error` and suggests configuring writable persistent storage. Live writes/searches still require explicit live consent such as `--yes-live-memory`.

## Pinecone

Pinecone remains supported as an optional vector/cloud retrieval bridge. It is useful for teams already using Pinecone or needing managed vector search.

Status/report mode reads environment and local registry only. Retrieval tools are explicit separate actions and remain advisory-only.

Adapter examples:

```bash
node .knowledge/tools/memory-pinecone.js health --json
node .knowledge/tools/memory-pinecone.js sync-sources --json
node .knowledge/tools/memory-pinecone.js search "routing bundle" --json
```

Those commands dry-run by default. Pass `--live` only when `PINECONE_MODE`, `PINECONE_HOST`, and any required API key are intentionally configured.

## Graphiti and Zep

Graphiti and Zep are not bundled in the free/core install asset:

- Graphiti-style temporal graph memory is out of scope for this free/core release.
- Zep-style managed or BYOC memory is out of scope for this free/core release.

Free core may mention these future provider categories, but it does not ship their adapters, manifests, runtime code, or provider-specific rules. They are excluded from `dist/knowledge-v3.2.2.zip`.

## Migrating from Claude MEM

Claude MEM is no longer a first-class provider. Existing artifacts are legacy advisory data.

Run:

```bash
node .knowledge/tools/memory-provider.js migrate-legacy --json
```

If a legacy state directory exists under `stateRoot`, the command writes `DEPRECATED.md`. It never deletes user memory by default and never uses legacy memory to raise trust.
