# Mem0 Shared Provider Storage

Use this recipe when a project should use the default per-user Mem0 provider
storage so multiple `.knowledge` projects can discover the same provider
location.

This is the default for new Mem0 embedding config. Use this recipe for existing
projects when the current config is project-local or custom and the user wants
the shared default.

## Boundary

Shared provider storage is data storage, not the Python runtime.

```txt
shared_provider_root = Qdrant/history/runtime data root
Python runtime = current shell, active venv, bounded discovery, or --python
```

Do not look for `python.exe` inside the shared provider root. Do not move the
shared provider root to fix a Python/FastEmbed/ONNX model-cache diagnostic.

## Inspect Current State

```bash
node .knowledge/tools/memory-provider.js status mem0-oss --json
node .knowledge/tools/memory-provider.js status-all --json
```

Read these fields:

- `provider_scope`
- `shared_provider_root`
- `project_storage_key`
- `qdrant_path`
- `history_db_path`
- `diagnostic_code`

Offline status does not import Python or prove that a model can load.

## Configure Shared Storage

Ask the normal embedding backend question first.

For OpenAI API embeddings:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --provider-scope shared --json
```

For Local FastEmbed:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope shared --json
```

Use `--provider-scope shared` when switching an existing non-shared config.
Without an explicit scope, `configure-embeddings` preserves existing configured
paths to avoid moving user memory unexpectedly.

## Validate

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json
```

For Local FastEmbed, also run an explicit write/search/recall smoke when the
user agrees to live memory writes:

```bash
node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 embedding backend smoke test" --scope repo --json
node .knowledge/tools/memory-mem0.js search "embedding backend smoke test" --adapter live --yes-live-memory --json
node .knowledge/tools/memory-mem0.js recall "embedding backend smoke test" --adapter live --yes-live-memory --json
```

If health reports `diagnostic_code: mem0_available` but list/search/recall later
reports `diagnostic_code: fastembed_onnx_external_data_path_error`, the Mem0
runtime was importable and the failure is in the Local FastEmbed/ONNX model
runtime layer. Prefer a supported Python runtime such as Python 3.12 and rerun
the pinned installs before changing storage paths.

If list/search/recall reports `diagnostic_code: fastembed_model_download_timeout`,
the first Local FastEmbed model download or warmup timed out. Keep the same
shared provider root and collection, then rerun the same explicit live command
with a longer timeout such as `--timeout-ms 300000`.

If list/search/recall reports `diagnostic_code: qdrant_lock_busy` or
`diagnostic_code: qdrant_path_permission_denied`, treat it as a storage
availability issue, not as a missing Python/Mem0 install. Do not silently move
the project from shared storage to project-local storage. Close the process
holding the Qdrant path or repair file permissions, then rerun the same live
command. Use `--provider-scope project` only after the user explicitly chooses
project-local storage.

## Existing Local Data

This recipe does not automatically copy old Qdrant/history files. If preserving
existing project-local memory is required, stop and ask the user before moving
data. Do not blindly merge old collections into a new shared project-keyed
directory.

Mem0 remains advisory-only external memory:

```txt
source_of_truth: false
trust_role: advisory_only
trust_effect: advisory_only
```
