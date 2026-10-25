# knowledge-maintenance

Use after code changes or before handing work to another agent.

Commands:

```bash
node .knowledge/tools/sync-tracked.js
node .knowledge/tools/sync-tracked.js --scan
node .knowledge/tools/sync-tracked.js --scan --discover
```

Rules:

- Set `KNOWLEDGE_AGENT_ID` for every agent.
- Use the provided tools so writes pass through `.knowledge/.lock` and atomic JSON writes.
- Update module cards/evidence only when facts were checked against code/tests.
- Add repair items rather than guessing.
- Do not run force bootstrap/ingest during concurrent work.
- Use `--scan` for the current curated scope.
- Use `--scan --discover` only when intentionally looking for new important files.
