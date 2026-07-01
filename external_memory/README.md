# External Memory

External memory is an optional bridge for large static archives. It is disabled by default and is never source of truth.

Supported Pinecone bridge modes:

```txt
Pinecone Local  → local emulator / CI / experiments, no API key required
Pinecone Cloud  → managed external archive, API key required
```

Use local `.knowledge` search and source code checks first.
