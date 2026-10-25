# Cookbook: External Memory

Use external memory only as advisory context.

Recommended free/core path:

```bash
node .knowledge/tools/memory-provider.js preview mem0-oss --json
node .knowledge/tools/memory-provider.js status-all --json
```

Pinecone remains available for optional vector/cloud retrieval:

```bash
node .knowledge/tools/external/pinecone-upsert.js --dry-run
node .knowledge/tools/external/pinecone-search.js "query" --dry-run
```

Rules:

- current code/tests/evidence outrank memory;
- no provider is enabled by default;
- no hidden network calls in status/report commands;
- provider secrets stay in environment or user-managed provider config, never committed files;
- legacy Claude MEM artifacts are migration-only advisory data.
