# Pinecone Provider Setup

Pinecone remains supported as an optional vector/cloud retrieval bridge.

Local/dev mode:

```bash
PINECONE_MODE=local
PINECONE_HOST=http://localhost:<port>
```

Cloud mode:

```bash
PINECONE_MODE=cloud
PINECONE_HOST=<index-host>
PINECONE_API_KEY=<redacted>
```

Status/report commands do not call the Pinecone API. Retrieval/upsert commands are explicit separate actions and remain advisory-only.
