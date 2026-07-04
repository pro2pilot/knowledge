# Mem0 Embedding Backends

Use this guided recipe when installing or changing Mem0 embeddings for `.knowledge`.

Mem0 remains advisory-only external memory:

```txt
source_of_truth: false
trust_role: advisory_only
trust_effect: advisory_only
```

This is an agent-guided chat recipe. The agent must ask the question, record the answer, then run deterministic commands. Do not turn this into an interactive shell script, and do not silently choose a default embedding backend.

## Layers

Keep these layers separate in prompts, config, and validation:

- LLM provider: the model Mem0 uses for memory reasoning and extraction.
- Embedding provider: OpenAI API or Local FastEmbed.
- Vector store: Qdrant under the shared provider root by default.
- History store: SQLite under the shared provider root by default.

Default provider storage is shared per OS user so multiple projects can discover
and reuse the same Mem0 provider location. Each project still gets its own
project-keyed storage directory under that shared root. Use project-local
storage only when the user explicitly asks for it.

Local FastEmbed changes the embedding provider only. It does not make the LLM provider local or API-free.

The shared provider root is data storage, not the Python runtime. Do not look
for `python.exe` or installed Python packages inside the shared provider root.
Python is selected from the current shell, an active venv, bounded discovery, or
an explicit `--python` flag.

## Question

Ask:

```txt
Which backend should Mem0 use for embeddings?

1. OpenAI API
   - simpler;
   - good quality;
   - requires OPENAI_API_KEY;
   - paid by API usage;
   - can fail with 429 insufficient_quota.

2. Local FastEmbed
   - free by API usage;
   - runs locally on CPU;
   - does not require GPU;
   - downloads a local model;
   - requires selecting a model and creating a separate Qdrant collection.
```

## OpenAI API

Configure OpenAI embeddings explicitly:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json
```

Never ask the user to paste `OPENAI_API_KEY` into a repository file, and never commit it. Ask them to set it in their local terminal:

macOS/Linux:

```bash
export OPENAI_API_KEY="sk-..."
```

Windows PowerShell:

```powershell
$env:OPENAI_API_KEY="sk-..."
```

Then validate:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
```

## Local FastEmbed

Install the pinned runtime packages:

```bash
python -m pip install mem0ai==2.0.4
python -m pip install fastembed==0.5.1
```

Use a Python version with prebuilt wheels for the pinned packages. On Windows,
this recipe has been battle-tested with Python 3.12. If the default `python` is
Python 3.14 and `fastembed==0.5.1` starts building dependencies such as `mmh3`
or `Pillow` from source, create a Python 3.12 venv and run the same pinned
commands inside that venv.

When no explicit `--python` or `KNOWLEDGE_MEM0_PYTHON` override is present,
`configure-embeddings` scans available Python candidates and prefers a
supported runtime for Local FastEmbed. The selected runtime is recorded in
`config.meta.json` so later live commands can reuse it instead of falling back
to an unsupported default `python` from PATH.

Health and operational smoke check different layers. `health --adapter live`
only proves that the selected Python can import the pinned Mem0 runtime.
`list`, `add`, `search`, and `recall` also initialize storage and the configured
embedding path. If a live command returns
`diagnostic_code: fastembed_onnx_external_data_path_error`, the shared provider
path is not the thing to move; repair the Python/FastEmbed/ONNX model-cache
layer, preferably under Python 3.12, and rerun the live smoke command.
If a live command returns `diagnostic_code: fastembed_model_download_timeout`,
the first local model download did not finish in time. This is not OpenAI quota;
retry the same live command with a longer timeout such as `--timeout-ms 300000`
after confirming local network/cache access.

Ask which model to use:

| Option | Model | Dimensions | Size | When to choose |
|---|---:|---:|---:|---|
| **small-en-fast** | `BAAI/bge-small-en-v1.5` | 384 | ~0.067 GB | fast default for English/code |
| **mini-en-fast** | `sentence-transformers/all-MiniLM-L6-v2` | 384 | ~0.090 GB | very light option, simple tasks |
| **base-en-balanced** | `BAAI/bge-base-en-v1.5` | 768 | ~0.210 GB | better quality, but heavier |
| **multilingual-small** | `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` | 384 | ~0.220 GB | RU/EN notes, light multilingual |
| **multilingual-large** | `intfloat/multilingual-e5-large` | 1024 | ~2.240 GB | better multilingual quality, noticeably heavier |

Configure the selected model. The command reads FastEmbed model dimensions programmatically and writes a new Qdrant collection name:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json
```

This uses shared provider storage by default. For the rare case where the user
explicitly wants provider data inside the repository, use:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope project --json
```

The generated config must show:

```txt
embedding_provider.provider: fastembed
embedding_provider.dimensions: 384
vector_store.provider: qdrant
history_store.provider: sqlite
```

Do not reuse an old OpenAI `1536`-dimension collection for FastEmbed. If collection reuse is requested and the previous provider, model, or dimensions differ, `configure-embeddings` must return `diagnostic_code: collection_reuse_blocked`.

Warm and smoke-test with explicit live consent:

```bash
node .knowledge/tools/memory-mem0.js health --adapter live --json
node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 embedding backend smoke test" --scope repo --json
node .knowledge/tools/memory-mem0.js search "embedding backend smoke test" --adapter live --yes-live-memory --json
node .knowledge/tools/memory-mem0.js recall "embedding backend smoke test" --adapter live --yes-live-memory --json
```

Search and recall output is advisory context only. Check current code, tests, and evidence before using it for implementation decisions.
