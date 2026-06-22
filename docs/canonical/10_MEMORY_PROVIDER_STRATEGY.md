# 10 — Memory provider strategy

## Core rule

```txt
External memory is advisory only.
It can suggest context.
It cannot raise trust automatically.
```

## Provider roles

| Provider | Layer | Role |
|---|---|---|
| `.knowledge` files | Core | Source-of-truth contract. |
| Mem0 OSS | Free optional | Recommended universal memory backend. |
| Pinecone | Free optional | Vector/cloud retrieval bridge. |
| Graphiti | Pro/Enterprise | Temporal graph/provenance provider. |
| Zep | Pro/Enterprise | Managed/BYOC enterprise memory. |
| Claude MEM / Claude memory | Legacy/runtime-specific | Read-only/advisory if detected. |

## Free UI

Memory Providers card shows:

```txt
.knowledge Source of Truth
Mem0 OSS
Pinecone
Legacy Claude memory if detected
Graphiti/Zep as Pro Preview
```

## Required status fields

```json
{
  "provider_id": "mem0-oss",
  "status": "not_configured|available|installed|enabled|disabled|runtime_not_installed|error|legacy",
  "source_of_truth": false,
  "can_raise_trust": false,
  "license_spdx": "Apache-2.0",
  "version": "...",
  "data_path": "...",
  "records_count": 0,
  "warnings": []
}
```

## Mem0

Recommended optional universal backend.

Live runtime probing is explicit:

```bash
node .knowledge/tools/memory-mem0.js health --adapter live --json
```

The live health command uses bounded Python discovery: explicit `--python`, Mem0/Python env vars, active virtual environments, PATH commands, Windows `py`/`pymanager`, and standard install directories. It must not scan the whole disk or install packages automatically.

If Python or Mem0 is not available, report:

```txt
runtime_not_installed
```

Include a diagnostic code such as `python_not_found`, `python_permission_error`, or `mem0_package_missing`. Do not fake live memory.

## Pinecone

Optional vector/cloud provider.

Must show:

```txt
cloud/API key warning
status without leaking API key
source_of_truth=false
```

## Graphiti/Zep

Pro/Enterprise only in V1. Do not include as free-core dependency.

## Legacy Claude memory

Detect if present, but do not recommend.

```txt
legacy
read-only
advisory
cannot raise trust
```

## Override protection

Every trust report must enforce:

```txt
external_memory_override_count = 0
```

If memory conflicts with code/evidence:

```txt
memory item → advisory/conflict
trust cannot increase
repair item may be created
```
