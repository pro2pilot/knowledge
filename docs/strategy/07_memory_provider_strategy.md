# 07 — Memory provider strategy after competitive analysis

## Decision

Memory must be provider-neutral and subordinate to `.knowledge` trust rules.

Final provider matrix:

| Provider | Layer | Status | Purpose |
|---|---|---|---|
| `.knowledge` | core | source of truth | repo-local trust/freshness/repair |
| Mem0 OSS | core optional | recommended | universal local memory backend |
| Pinecone | core optional | supported | vector/cloud retrieval provider |
| Graphiti | Pro/Enterprise | planned/paid | temporal graph/provenance |
| Zep | Pro/Enterprise | planned/paid | managed/BYOC enterprise memory |
| Claude MEM | legacy only | deprecated | no first-class bridge |

## Why Mem0 OSS is recommended for core

Mem0 OSS is the best optional core provider because it is:

- agent-neutral;
- useful for add/search memory workflows;
- local/self-hostable;
- broadly useful beyond Claude;
- a memory layer, not a PR/review platform;
- compatible with the idea of advisory retrieved context.

But Mem0 must not become required core.

## Why Pinecone remains

Pinecone remains useful for:

- users already using Pinecone;
- managed vector search;
- semantic retrieval at scale;
- cloud vector provider compatibility.

But it should be positioned as:

```txt
optional vector/cloud retrieval provider
```

Not:

```txt
primary memory system
```

## Why Graphiti belongs in Pro/Enterprise

Graphiti is valuable where the buyer needs:

- temporal knowledge graph;
- validity windows;
- provenance;
- fact invalidation;
- graph traversal;
- self-hosted advanced memory.

This is heavier than free core. It belongs in Pro/Enterprise memory governance.

## Why Zep belongs in Pro/Enterprise

Zep is valuable where the buyer needs:

- managed/BYOC provider;
- enterprise memory;
- governance/audit/SLA;
- provider support beyond local tooling.

It belongs in Pro/Enterprise, not in Apache-2.0 local core.

## Claude MEM deprecation

Claude MEM first-class bridge should be removed.

Allowed:

- legacy detection;
- deprecation note;
- read-only compatibility status;
- migration docs to Mem0.

Not allowed:

- install button;
- recommended provider card;
- runtime bridge;
- docs that call it primary path.

## Trust policy

```txt
External memory is advisory.
External memory cannot raise trust.
External memory cannot overwrite curated knowledge.
External memory cannot become source of truth.
```

Source-of-truth order:

```txt
1. current source code
2. current tests
3. evidence JSON
4. module records
5. decisions
6. wiki
7. sessions
8. external memory retrieval
```

## Provider interface commands

```bash
node .knowledge/tools/memory-provider.js list --json
node .knowledge/tools/memory-provider.js preview mem0-oss --json
node .knowledge/tools/memory-provider.js install mem0-oss --version <pinned> --yes-i-reviewed-license --json
node .knowledge/tools/memory-provider.js update mem0-oss --to <version> --yes-i-reviewed-license --json
node .knowledge/tools/memory-provider.js uninstall mem0-oss --json
node .knowledge/tools/memory-provider.js status mem0-oss --json
node .knowledge/tools/memory-provider.js status pinecone --json
node .knowledge/tools/memory-provider.js status-all --json
```

## Mem0 runtime commands

Default health remains dry-run/offline. Use live health when the user explicitly wants to probe a local Python/Mem0 runtime:

```bash
node .knowledge/tools/memory-mem0.js health --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
node .knowledge/tools/memory-mem0.js add --text "..." --scope repo --json
node .knowledge/tools/memory-mem0.js search "query" --json
node .knowledge/tools/memory-mem0.js list --json
node .knowledge/tools/memory-mem0.js delete --id <id> --json
node .knowledge/tools/memory-mem0.js sync-report --json
node .knowledge/tools/memory-mem0.js export-redacted --json
```

Live health uses bounded Python discovery: explicit `--python`, Mem0/Python env vars, active virtual environments, PATH commands, Windows `py`/`pymanager`, and standard install directories. It does not scan the whole disk and does not install packages.

If not installed, report honestly:

```json
{
  "status": "runtime_not_installed",
  "diagnostic_code": "python_not_found|python_permission_error|mem0_package_missing",
  "provider": "mem0-oss",
  "source_of_truth": false,
  "trust_effect": "advisory_only"
}
```

## Required reports

```txt
maintenance/external_memory_status.json
metrics/external_memory.json
SBOM.memory.json
THIRD_PARTY_NOTICES.md
```

## Required tests

- install refuses without license confirmation;
- update refuses without explicit version;
- status works offline;
- secrets redacted;
- legacy Claude MEM detected;
- external memory override blocked;
- trust cannot be raised from memory;
- team-mode stateRoot supported;
- Pro provider manifests validate.

## UI requirements

Free Memory Providers tab:

- `.knowledge Source of Truth` card;
- Mem0 recommended card;
- Pinecone optional card;
- Graphiti/Zep Pro cards;
- legacy Claude card only if detected;
- source-of-truth warning.

Pro Memory Governance:

- fleet status;
- version drift;
- provider license/SBOM;
- provider events;
- policy violations;
- Graphiti/Zep setup statuses;
- Mem0/Pinecone status across repos.
