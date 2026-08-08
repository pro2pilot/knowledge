# Trust, Evidence, Routing And Repair

Routing tells agents where to look. Evidence explains why knowledge is trusted. Trust tells whether the knowledge is usable now. Freshness tells whether it is stale. Repair tells how to restore trust.

Restore Trust is a safe action:

```bash
node .knowledge/tools/restore-trust.js --safe --json
```

It refreshes generated knowledge reports, routing/search, trust/freshness and repair state. It must not change source code, merge branches, raise trust without evidence or overwrite curated evidence without approval.

Repair-on-touch is the narrower task-time path:

```bash
node .knowledge/tools/repair-on-touch.js plan --request=<task-scope.json>
```

Each Doctor observation becomes a granular lifecycle finding with one module,
primary artifact, full affected-artifact set, required checks, and resolution
predicate. Detector disappearance does not close it. Closure requires:

1. a real no-shell local verification execution;
2. current hashes for every affected artifact;
3. a content-addressed receipt bound to the exact task, session, lifecycle,
   command, execution, and predicate;
4. an atomic recertification transaction.

Only trust reasons matched by verified artifacts may be cleared. Contradictions,
security findings, policy violations, critical-path findings without explicit
confirmation, unrelated modules, and any remaining trust reason block
elevation. See `repair-on-touch.md`.
