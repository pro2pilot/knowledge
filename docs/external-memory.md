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

Paid Inspector provider positioning:

- Graphiti: self-host temporal graph/provenance memory.
- Zep: managed or BYOC enterprise memory.

Run:

```bash
node .knowledge/tools/memory-provider.js status-all --json
node .knowledge/tools/external-memory-status.js --json
```

Both commands produce `<stateRoot>/maintenance/external_memory_status.json` and `<stateRoot>/metrics/external_memory.json`.

Mem0 runtime/test-adapter commands are explicit:

```bash
node .knowledge/tools/memory-mem0.js health --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
node .knowledge/tools/memory-mem0.js add --text "..." --scope repo --json
node .knowledge/tools/memory-mem0.js search "query" --json
node .knowledge/tools/memory-mem0.js export-redacted --json
```

Without a user-installed Mem0 runtime these commands report `runtime_not_installed` or dry-run/test-adapter status. Live health uses bounded Python discovery from explicit settings, active environments, PATH, Windows `py`/`pymanager`, and standard install directories; it does not scan the whole computer and never installs packages automatically. Only `health --adapter live` uses a 30000 ms default timeout for the live Mem0 import/health path, because the first `import mem0` on Windows can be noticeably slower than warm checks; short Python discovery/probe checks stay short. It reports whether Python was not found, Python was unusable, `diagnostic_code: python_timeout` was hit, or `mem0ai==2.0.4` needs to be installed in the selected interpreter.

Pinecone adapter commands are also explicit:

```bash
node .knowledge/tools/memory-pinecone.js health --json
node .knowledge/tools/memory-pinecone.js sync-sources --json
node .knowledge/tools/memory-pinecone.js search "query" --json
```

They dry-run by default and do not call Pinecone unless `--live` is passed with a configured Pinecone environment. Pinecone results stay advisory-only and must be verified against code/tests/evidence before use.
