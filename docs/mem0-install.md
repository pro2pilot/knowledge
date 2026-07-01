# Mem0 Install

Use this page when an agent or user needs to connect Mem0 OSS to `.knowledge` without inventing commands.

## Recommended Flow

Run one guided setup command:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
```

The setup command:

- creates or reuses `.knowledge/external_memory/mem0/install_receipt.json`;
- writes repo-local config at `.knowledge/external_memory/mem0/config.json`;
- regenerates `.knowledge/docs/cookbook/09-mem0-live-memory.md` from the bundled template;
- checks explicit live health through `memory-mem0.js`;
- updates `.knowledge/external_memory/mem0/runtime_status.json`;
- returns agent-facing text with exact add, search, and recall commands.

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

Live list reads local Qdrant state:

```bash
node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json
```

## Local Data

Default Mem0 state is repo-local:

```txt
.knowledge/external_memory/mem0
.knowledge/external_memory/mem0/qdrant
.knowledge/external_memory/mem0/history.db
.knowledge/external_memory/mem0/runtime
```

Do not use `/tmp/qdrant` or the user's home directory as the default path on Windows. Adapter subprocesses set `MEM0_DIR` to `.knowledge/external_memory/mem0/runtime` when it is not already set, so Mem0 runtime files stay repo-local without mutating the canonical `config.json`.

Adapter subprocesses set:

```txt
MEM0_TELEMETRY=False
MEM0_TELEMETRY_SAMPLE_RATE=0
```

They do not change the user's global environment.

## Optional Local Embeddings

The main onboarding flow stays the single setup command. If the configured embedding provider blocks add/search because of credentials, quota, or network, a user may choose a separate local embedder path:

```bash
python -m pip install fastembed==0.5.1
```

Changing embedding dimensions requires a new Qdrant collection name. Do not present local embeddings as an equal alternative to the recommended setup flow.

## Trust Boundary

Mem0 is advisory-only external memory:

```txt
source_of_truth: false
trust_role: advisory_only
trust_effect: advisory_only
```

Current code, current tests, and `.knowledge/evidence` outrank retrieved memory.
