# Trust, Evidence, Routing And Repair

Routing tells agents where to look. Evidence explains why knowledge is trusted. Trust tells whether the knowledge is usable now. Freshness tells whether it is stale. Repair tells how to restore trust.

Restore Trust is a safe action:

```bash
node .knowledge/tools/restore-trust.js --safe --json
```

It refreshes generated knowledge reports, routing/search, trust/freshness and repair state. It must not change source code, merge branches, raise trust without evidence or overwrite curated evidence without approval.
