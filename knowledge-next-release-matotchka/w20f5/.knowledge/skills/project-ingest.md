# project-ingest

Safe initial setup for an existing repository:

```bash
node .knowledge/tools/ingest-existing-project.js --merge
node .knowledge/tools/sync-tracked.js --scan
node .knowledge/tools/install-git-hooks.js
```

The ingest is shallow and heuristic. It creates routing maps and module cards, not authoritative summaries.

After ingest, replace heuristic module cards with code-backed facts as work proceeds.

Use `node .knowledge/tools/sync-tracked.js --scan --discover` only after ingest if you intentionally want to find additional important files that were not added to the curated module scope.
