# Mem0 Install

Use this page when an agent or user needs to connect Mem0 OSS to `.knowledge` without inventing commands.

## Recommended Flow

Run one guided setup command:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
```

The setup command:

- creates or reuses `.knowledge/external_memory/mem0/install_receipt.json`;
- regenerates `.knowledge/docs/cookbook/09-mem0-live-memory.md` from the bundled template;
- requires an explicit embedding backend choice if `.knowledge/external_memory/mem0/config.json` does not exist yet;
- after `configure-embeddings`, checks explicit live health through `memory-mem0.js`;
- updates `.knowledge/external_memory/mem0/runtime_status.json`;
- returns agent-facing text with exact next commands.

## Runtime Install

The receipt is an approval and config marker. It is not proof that `pip install` already ran.

If setup reports that Mem0 is missing, use the single pinned install command returned in JSON. The current manifest pin is:

```bash
python -m pip install mem0ai==2.0.4
```

Do not offer multiple install variants in onboarding. Keep the setup route above as the recommended path.

## Status Semantics

Offline status commands must not import Python packages or call network:

```bash
node .knowledge/tools/memory-provider.js status mem0-oss --json
node .knowledge/tools/memory-provider.js status-all --json
```

Status separates:

- `receipt_present`: approval/config receipt exists;
- `runtime_available`: explicit live health found an importable Mem0 runtime;
- `package_installed`: runtime availability was proven by live health or an executed install record;
- `runtime_health`: cached runtime health from the explicit adapter check.

Read diagnostics in three layers:

- `status` and `status-all`: offline detection and cached status only.
- `health --adapter live`: selected Python can import the pinned Mem0 runtime.
- `list`, `add`, `search`, and `recall` with `--adapter live`: configured storage plus embedding path can actually operate.

`diagnostic_code: mem0_available` from health means the Mem0 runtime imported.
It does not prove that a Local FastEmbed ONNX model can load. If a later live
command reports `diagnostic_code: fastembed_onnx_external_data_path_error`,
keep the shared provider root as-is and repair the Python/FastEmbed/model cache
layer instead.

If a Local FastEmbed command reports
`diagnostic_code: fastembed_model_download_timeout`, the runtime imported Mem0
and started model warmup, but the HuggingFace/FastEmbed model download did not
finish before the live command timeout. This is not an OpenAI quota diagnostic.
Keep the same collection/storage and rerun the explicit live command with a
longer timeout, for example `--timeout-ms 300000`.

## Live Commands

Live health checks runtime availability:

```bash
node .knowledge/tools/memory-mem0.js health --adapter live --json
```

Live add writes external memory and may call the embedding provider:

```bash
node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json
```

Live search and recall return advisory context and may call the embedding provider:

```bash
node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json
node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json
```

Live list reads local Qdrant state. With Local FastEmbed, first use can also
download or warm the local model, so JSON may report
`network_calls: not_run_local_qdrant_may_download_local_fastembed_model`:

```bash
node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json
```

## Provider Storage

Repo-local `.knowledge/external_memory/mem0` stores receipt, config, and runtime status:

```txt
.knowledge/external_memory/mem0
.knowledge/external_memory/mem0/config.json
.knowledge/external_memory/mem0/config.meta.json
.knowledge/external_memory/mem0/runtime_status.json
```

Default provider storage is shared per OS user:

```txt
Windows: %LOCALAPPDATA%\pro2pilot\knowledge\memory-providers\mem0
macOS: ~/Library/Application Support/pro2pilot/knowledge/memory-providers/mem0
Linux: ${XDG_DATA_HOME:-~/.local/share}/pro2pilot/knowledge/memory-providers/mem0
```

Each project gets a project-keyed subdirectory under that shared root for Qdrant, history, and Mem0 runtime files. This lets agents detect an existing default provider location across repositories without mixing project collections.

The shared provider root is data storage, not a Python virtualenv. It should not
contain `python.exe`, and agents should not expect Python packages to be inside
that directory. Python comes from the current shell, an active venv, bounded
runtime discovery, or an explicit `--python` flag.

When Local FastEmbed has been configured successfully, `.knowledge` records the
selected Python runtime in `config.meta.json`. Later live Mem0 commands prefer
that cached runtime unless the user passes `--python`, `KNOWLEDGE_MEM0_PYTHON`,
or `MEM0_PYTHON`.

Project-local provider storage is not the default. Use it only when the user explicitly asks for a repository-owned provider:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope project --json
```

Do not use project-local storage as an automatic repair for
`qdrant_lock_busy` or `qdrant_path_permission_denied`. Those diagnostics mean
the configured Qdrant path is locked or not writable. Keep shared storage by
default, repair the process/permissions problem, and switch to
`--provider-scope project` only after the user explicitly chooses a
repository-owned provider.

For existing projects that need to return to the shared per-user default, use
[`cookbook/12-mem0-shared-provider-storage.md`](cookbook/12-mem0-shared-provider-storage.md).

Do not use `/tmp/qdrant`.

Adapter subprocesses set:

```txt
MEM0_TELEMETRY=False
MEM0_TELEMETRY_SAMPLE_RATE=0
```

They do not change the user's global environment.

## Embedding Backend Choice

The main onboarding flow must ask the user which embedding backend to use. Embedding backend configuration is separate and agent-friendly through flags plus JSON. `setup mem0-oss --live --json` must not silently choose an embedding backend.

The guided recipe lives at [`cookbook/10-mem0-embedding-backends.md`](cookbook/10-mem0-embedding-backends.md). The agent asks which embedding backend to use, then runs deterministic commands.

Keep these layers distinct:

- LLM provider: separate from embeddings; default config uses OpenAI unless changed.
- Embedding provider: OpenAI API or Local FastEmbed.
- Vector store: Qdrant under shared provider storage by default.
- History store: SQLite under shared provider storage by default.

OpenAI API embeddings:

```bash
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json
```

Do not ask the user to paste `OPENAI_API_KEY` into repository files or commits. Ask them to set it in their local terminal:

```bash
export OPENAI_API_KEY="sk-..."
$env:OPENAI_API_KEY="sk-..."
```

Local FastEmbed is a normal install-time choice, not an emergency fallback:

```bash
python -m pip install mem0ai==2.0.4
python -m pip install fastembed==0.5.1
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json
```

Use a Python version with prebuilt wheels for the pinned packages. On Windows,
this flow has been battle-tested with Python 3.12. If the default `python` is
Python 3.14 and `fastembed==0.5.1` tries to build `mmh3` or `Pillow` from
source, create a Python 3.12 venv and run the same pinned commands there.
The FastEmbed metadata step scans available Python candidates and prefers a
supported runtime instead of stopping at an unsupported default `python`.
On Windows, discovery checks active venv/conda first, then `py -3.12`/`py -3.11`
launcher candidates, then PATH commands.

`configure-embeddings` reads FastEmbed dimensions programmatically and writes a collection name that includes provider, model, and dimensions. Changing embedding provider, model, or dimensions requires a new Qdrant collection name. Never reuse an OpenAI `1536`-dimension collection for FastEmbed.

## Trust Boundary

Mem0 is advisory-only external memory:

```txt
source_of_truth: false
trust_role: advisory_only
trust_effect: advisory_only
```

Current code, current tests, and `.knowledge/evidence` outrank retrieved memory.
