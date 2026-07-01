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

Run one setup command:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
```

The setup flow records or reuses the install receipt, writes repo-local Mem0 config, refreshes this recipe from the template, runs explicit live health, and updates the runtime status cache.

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

Repo-local data path:

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

## Explicit Live Operations

Live health checks runtime availability. It does not write memory.

```bash
node .knowledge/tools/memory-mem0.js health --adapter live --json
```

Live list opens local Qdrant and is serialized by the adapter.

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

## Local Paths

The default Qdrant path is repo-local:

```txt
{{QDRANT_PATH}}
```

The default history DB is repo-local:

```txt
{{HISTORY_DB_PATH}}
```

Adapter runtime files are repo-local under `.knowledge/external_memory/mem0/runtime`, while the canonical `config.json` stays reproducible. Do not use `/tmp/qdrant` or a user home directory as the default for this repo. If embedding dimensions change, create a new Qdrant collection name instead of reusing an existing collection.

## Optional Local Embedder

The main setup flow stays the one command above. If OpenAI embedding quota blocks add/search, a user may choose a separate local embedder path.

Exact optional install command:

```bash
python -m pip install fastembed==0.5.1
```

After changing embedding dimensions, use a new Qdrant collection name. Do not present this optional local embedder as an equal alternative to the recommended setup flow.

## Validate This Recipe

The validator checks this generated recipe against the machine-readable CLI help/dispatch metadata exposed by the Mem0 tools. Do not replace these commands with invented variants.

```bash
node .knowledge/tools/memory-provider.js write-recipe mem0-oss --json
node .knowledge/tools/memory-provider.js validate-recipe mem0-oss --json
```
