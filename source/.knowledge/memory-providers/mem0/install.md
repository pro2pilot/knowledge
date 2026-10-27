# Mem0 OSS Install Preview

Mem0 OSS is the recommended optional universal memory backend for `.knowledge` free/core.

Official install command verified on 2026-06-06:

```bash
pip install mem0ai==2.0.4
```

The `.knowledge` CLI does not run this command automatically. Use:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
```

That is the recommended guided flow. It records or reuses the receipt, refreshes the cookbook recipe, and stops for an explicit embedding backend choice when config is missing. It must not silently choose OpenAI API or Local FastEmbed.

Embedding backend configuration is a required guided step. The agent asks whether to use OpenAI API embeddings or Local FastEmbed, then runs one deterministic command:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json
```

The config keeps LLM provider, embedding provider, Qdrant vector store, and SQLite history store distinct. Shared provider storage is the default so multiple projects can discover the same provider location. Local FastEmbed is a normal install-time choice and must use a new Qdrant collection when dimensions differ from the old OpenAI `1536` collection.

Project-local provider storage is a rare, explicit choice:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope project --json
```

For Local FastEmbed on Windows, use a Python version with wheels for the pinned
runtime packages. This flow has been battle-tested with Python 3.12; Python 3.14
can force source builds for `mmh3` or `Pillow` when installing
`fastembed==0.5.1`.

Low-level receipt commands are still available:

```bash
node .knowledge/tools/memory-provider.js preview mem0-oss --json
node .knowledge/tools/memory-provider.js install mem0-oss --version mem0ai==2.0.4 --yes-i-reviewed-license --json
```

The second command records an approval receipt only. It does not install packages, create a network connection, or enable telemetry.

External memory remains advisory only. It cannot raise trust, overwrite curated `.knowledge` artifacts, or outrank current code/tests/evidence.
