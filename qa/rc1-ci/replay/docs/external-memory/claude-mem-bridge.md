# Migrating from Claude MEM Bridge to Mem0 OSS

Claude MEM first-class bridge has been removed.

Use Mem0 OSS as the recommended universal optional memory provider. Existing Claude MEM artifacts are treated as legacy advisory context only and are never used to raise trust.

What changed:

- Claude MEM install/status/update buttons are removed from the free Inspector surface.
- Claude MEM is detected only as legacy state.
- Doctor warns when legacy Claude MEM artifacts are found.
- Mem0 OSS is the recommended optional local/core provider.
- Pinecone remains an optional vector/cloud retrieval bridge.
- Graphiti and Zep are not bundled in the free/core install asset.

Safe migration:

```bash
node .knowledge/tools/memory-provider.js migrate-legacy --json
node .knowledge/tools/memory-provider.js preview mem0-oss --json
```

The migration command writes a `DEPRECATED.md` note only when legacy artifacts are inside `stateRoot`. It does not move or delete user data by default.

Manual deletion is intentionally manual: inspect the reported legacy path, back up anything needed, then remove it yourself outside `.knowledge` automation.
