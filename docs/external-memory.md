# External Memory

External memory is optional advisory context for `.knowledge`. It helps with retrieval and reporting, but it is not truth.

Source-of-truth order stays:

```txt
current code > current tests > evidence > modules > decisions > wiki > sessions > external memory
```

Free/core provider positioning:

- Mem0 OSS: recommended optional universal local memory backend.
- Pinecone: optional vector/cloud retrieval bridge.
- Legacy Claude MEM: migration-only advisory artifacts, not a first-class provider.

Optional provider positioning:

- Graphiti: future temporal graph/provenance category, not included in free/core.
- Zep: future managed/BYOC memory category, not included in free/core.

Run:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
node .knowledge/tools/memory-provider.js status-all --json
node .knowledge/tools/external-memory-status.js --json
```

Both commands produce `<stateRoot>/maintenance/external_memory_status.json` and `<stateRoot>/metrics/external_memory.json`.

Mem0 runtime/test-adapter commands are explicit:

```bash
node .knowledge/tools/memory-mem0.js health --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json
node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json
node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json
node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json
node .knowledge/tools/memory-mem0.js export-redacted --json
```

Without a user-installed Mem0 runtime these commands report `runtime_not_installed` or dry-run/test-adapter status. Live operations use bounded Python discovery from explicit settings, active environments, PATH, Windows `py`/`pymanager`, and standard install directories; they do not scan the whole computer and never install packages automatically. Live Mem0 operations use a 30000 ms default timeout for import, health, and local Qdrant startup, because the first `import mem0` or local store initialization on Windows can be noticeably slower than warm checks; short Python discovery/probe checks stay short. They report whether Python was missing, Python was unusable, `diagnostic_code: live_operation_timeout` was hit, `mem0ai==2.0.4` is missing, or the importable Mem0 runtime has the wrong or unreported version.

The setup command writes repo-local Mem0 config under `.knowledge/external_memory/mem0`, creates or reuses the receipt, refreshes the cookbook recipe, and updates runtime status cache after explicit live health. Receipt is an approval/config marker, not proof that pip install already ran. Status stays offline-safe and distinguishes `receipt_present`, `runtime_available`, and `package_installed`.

Install-specific Mem0 guidance lives in [`mem0-install.md`](mem0-install.md).

When live health has run, offline status also exposes cached Mem0 `runtime_version`, `expected_runtime_version`, and `runtime_version_matches_pin`.

Live add is an external-memory write. Live add, search, and recall may call the configured embedding provider. If that provider is unavailable, the adapter returns an explicit embedding-provider diagnostic instead of a raw stack trace; safe Qdrant shutdown and optional spaCy warnings are filtered as noise. Retrieved memory stays advisory-only and must be verified against code/tests/evidence before use.

Pinecone adapter commands are also explicit:

```bash
node .knowledge/tools/memory-pinecone.js health --json
node .knowledge/tools/memory-pinecone.js sync-sources --json
node .knowledge/tools/memory-pinecone.js search "query" --json
```

They dry-run by default and do not call Pinecone unless `--live` is passed with a configured Pinecone environment. Pinecone results stay advisory-only and must be verified against code/tests/evidence before use.
