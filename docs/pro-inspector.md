# Pro Inspector

Pro Inspector is the separate paid workspace for team and multi-repo governance. It is not bundled into free/core `.knowledge` and free core must not import paid app components.

The adjacent paid directory contains a runnable app shell that renders from demo data and exported `.knowledge` snapshots. It covers:

- Dashboard
- Repos / Workspaces
- Team Mode
- PR Impact
- Repair Board
- Policy Packs
- Memory Governance
- Provider Fleet Status
- Audit / History
- Settings / License

Free/core may include contracts, a Pro Preview tab, disabled paid capability cards, and:

```bash
node .knowledge/tools/export-pro-snapshot.js --json
```

The snapshot is sanitized, excludes secrets and memory content, and preserves the source-of-truth policy:

```txt
External memory is advisory only.
Code > tests > evidence > modules > decisions/wiki > sessions > external memory.
```

Provider split:

- Mem0 OSS: free optional local backend plus Pro fleet status.
- Pinecone: optional vector/cloud bridge plus Pro fleet status.
- Graphiti: Pro/Enterprise temporal graph/provenance provider.
- Zep: Pro/Enterprise managed/BYOC memory provider.

The current runnable paid shell is dependency-light so restricted release QA can run `npm install`, `npm run lint`, `npm run test`, and `npm run build` without network package downloads.
