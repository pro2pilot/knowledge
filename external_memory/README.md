# External Memory

External memory is optional advisory context. It is disabled by default and is never source of truth.

Supported free/core providers:

```txt
Mem0 OSS   -> recommended optional universal local memory backend
Pinecone   -> optional vector/cloud retrieval bridge
```

Graphiti and Zep are not bundled in the free/core install asset. Legacy Claude MEM artifacts are detected as advisory-only migration data and are no longer a first-class provider.

Use local `.knowledge` search and source code checks first. External memory cannot raise trust or overwrite curated artifacts.
