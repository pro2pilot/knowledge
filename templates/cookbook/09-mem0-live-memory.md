# Mem0 Live Memory

Use this recipe when an agent needs the recommended Mem0 OSS onboarding path for `.knowledge` external memory.

External memory is advisory-only:

```txt
source_of_truth: false
trust_role: advisory_only
trust_effect: advisory_only
```

Current code, tests, and `.knowledge/evidence` outrank retrieved memory. Search/recall returns advisory context that must be checked before it influences implementation.

## Recommended Flow

Run setup first:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
```

The setup flow records or reuses the install receipt and refreshes this recipe from the template. If no embedding backend has been configured yet, setup must stop with `setup_status: needs_embedding_provider_choice` and return the required chat question for the agent to ask. It must not silently choose OpenAI API or Local FastEmbed.

After the user chooses the embedding backend and the agent runs `configure-embeddings`, rerun the same setup command to check explicit live health and update the runtime status cache.

Receipt path:

```txt
{{RECEIPT_PATH}}
```

Repo-local config:

```txt
{{CONFIG_PATH}}
```

Runtime status cache:

```txt
{{RUNTIME_STATUS_PATH}}
```

Repo-local receipt/config/status path:

```txt
{{DATA_PATH}}
```

If setup reports that `mem0ai` is missing, run the single recommended install command from setup output. The pinned package is:

```bash
python -m pip install {{VERSION_PIN}}
```

The receipt is an approval and config marker. It is not proof that `pip install` already ran.

## Offline Status

Status commands are offline-safe. They do not import Python packages and do not make live or network calls.

```bash
node .knowledge/tools/memory-provider.js status mem0-oss --json
node .knowledge/tools/memory-provider.js status-all --json
```

The fields `receipt_present`, `runtime_available`, and `package_installed` are separate on purpose. A receipt alone must not be treated as a package install.

Read diagnostics in three layers:

- `status` and `status-all`: offline detection and cached status only.
- `health --adapter live`: proves that the selected Python can import the pinned Mem0 runtime.
- `list`, `add`, `search`, and `recall` with `--adapter live`: exercise the configured storage and embedding path.

`diagnostic_code: mem0_available` from health does not prove that a Local
FastEmbed model can load. If a later live command reports
`diagnostic_code: fastembed_onnx_external_data_path_error`, treat it as a
Python/FastEmbed/ONNX model-cache issue. Do not change the shared provider root
for that symptom.

If a Local FastEmbed live command reports
`diagnostic_code: fastembed_model_download_timeout`, Mem0 imported and model
warmup started, but the first HuggingFace/FastEmbed model download did not
finish before the timeout. This is not an OpenAI quota signal. Keep the same
storage and rerun the explicit live command with a longer timeout such as
`--timeout-ms 300000`.

## Explicit Live Operations

Live health checks runtime availability. It does not write memory.

```bash
node .knowledge/tools/memory-mem0.js health --adapter live --json
```

Live list opens local Qdrant and is serialized by the adapter. With Local
FastEmbed, first use can also download or warm the local model; the JSON
network label may be
`not_run_local_qdrant_may_download_local_fastembed_model`.

```bash
node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json
```

Live add is an external-memory write. It may call the embedding provider configured for Mem0.

```bash
node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json
```

Live search may call the embedding provider configured for Mem0.

```bash
node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json
```

Live recall is the same retrieval path as search and returns advisory context.

```bash
node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json
```

## Storage Policy

The default provider storage is shared per OS user so multiple `.knowledge` projects can find and reuse the same Mem0 provider location without creating a new provider install for every repository.

Default shared provider root:

```txt
{{SHARED_PROVIDER_ROOT}}
```

Within that shared root, each project gets its own project-keyed storage directory for Qdrant, history, and runtime files. This avoids mixing project memories while still keeping provider storage discoverable across repositories.

The shared provider root is data storage, not a Python virtualenv. Agents should
not look for `python.exe` inside it. Python is selected from the current shell,
an active venv, bounded runtime discovery, or an explicit `--python` flag.
After a successful Local FastEmbed configuration or live health check, the
selected Python can be reused from `config.meta.json` or `runtime_status.json`
unless the user passes an explicit Python override.

The repo-local `.knowledge/external_memory/mem0` directory remains the receipt/config/status control plane:

```txt
{{CONFIG_PATH}}
{{RUNTIME_STATUS_PATH}}
```

Project-local provider storage is not the default. Use it only when the user explicitly wants this repository to carry its own provider data:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope project --json
```

Project-local Qdrant and history paths are:

```txt
{{QDRANT_PATH}}
{{HISTORY_DB_PATH}}
```

Do not use `/tmp/qdrant`. If embedding dimensions change, create a new Qdrant collection name instead of reusing an existing collection.

## Embedding Backend Choice

Embedding backend selection is a required install-time chat choice and can be changed separately with `configure-embeddings`. The agent must ask the user which backend to use before it configures or live-tests Mem0.

Keep these layers distinct:

- LLM provider: the model Mem0 uses for memory reasoning and extraction.
- Embedding provider: the model/API that turns text into vectors.
- Vector store: Qdrant under the shared provider root by default.
- History store: SQLite under the shared provider root by default.

OpenAI API embedding config:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json
```

Do not paste `OPENAI_API_KEY` into repository files. Set it only in the local terminal:

```bash
export OPENAI_API_KEY="sk-..."
$env:OPENAI_API_KEY="sk-..."
```

Local FastEmbed is a regular choice, not an emergency fallback. Exact install command:

```bash
python -m pip install fastembed==0.5.1
```

Use Python 3.12 on Windows when the default `python` is too new for the pinned
FastEmbed dependency wheels. Python 3.14 can force source builds for `mmh3` or
`Pillow`; a Python 3.12 venv avoids that install failure.
When no explicit Python override is provided, the FastEmbed configuration step
checks available Python candidates and prefers a supported runtime instead of
stopping at the first unsupported `python` from PATH.
On Windows, discovery checks active venv/conda first, then `py -3.12`/`py -3.11`
launcher candidates, then PATH commands.

Example FastEmbed config for light RU/EN notes:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json
```

After changing embedding provider, model, or dimensions, use a new Qdrant collection name. Never reuse an OpenAI `1536`-dimension collection for a FastEmbed `384`, `768`, or `1024`-dimension model.

## Validate This Recipe

The validator checks this generated recipe against the machine-readable CLI help/dispatch metadata exposed by the Mem0 tools. Do not replace these commands with invented variants.

```bash
node .knowledge/tools/memory-provider.js write-recipe mem0-oss --json
node .knowledge/tools/memory-provider.js validate-recipe mem0-oss --json
```
