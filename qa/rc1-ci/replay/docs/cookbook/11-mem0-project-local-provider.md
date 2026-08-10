# Mem0 Project-Local Provider Storage

Use this recipe only when the user explicitly wants this repository to keep its own Mem0 provider data under `.knowledge/external_memory/mem0`.

This is not the default. The default Mem0 provider storage is shared per OS user so multiple `.knowledge` projects can discover and reuse the same provider location while keeping project-keyed Qdrant/history storage separate.

## When To Choose This

Choose project-local storage when the repository must be self-contained for a controlled workspace, when shared user storage is not allowed by policy, or when the user wants to move/delete the project together with its Mem0 provider data.

Do not choose this just because setup is running inside a project directory.

## Command

Ask the normal embedding backend question first. If the user chooses Local FastEmbed and also explicitly asks for project-local storage, run:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope project --json
```

For OpenAI API embeddings with project-local Qdrant/history storage:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --provider-scope project --json
```

Then run:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
```

## Expected Paths

Project-local storage writes Qdrant/history/runtime data under:

```txt
.knowledge/external_memory/mem0/qdrant
.knowledge/external_memory/mem0/history.db
.knowledge/external_memory/mem0/runtime
```

These are runtime/user state. They must not be included in public release artifacts.

## Trust Boundary

Mem0 remains advisory-only external memory:

```txt
source_of_truth: false
trust_role: advisory_only
trust_effect: advisory_only
```
