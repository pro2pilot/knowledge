# Routing context estimate reporting

After meaningful work, run:

```bash
node .knowledge/tools/flow.js release
```

Use the generated PR summary as the canonical human-readable result:

```txt
.knowledge/maintenance/pr_summary.md
```

Report exactly one routing-context state when it is available:

1. **Workspace-to-task narrowing** — report the estimated local first-read reduction and percentage.
2. **Estimated overhead** — report the estimated local first-read overhead and percentage.
3. **Neutral** — report that there is no material estimated local first-read difference.
4. **Unavailable / not comparable** — report the reason and do not invent a percentage.

Always state that this is a deterministic local context estimate, not provider-reported model-token usage. Do not describe it as actual token savings, model speed, accuracy, or error reduction. If the metrics were not regenerated in the current run or the task route is stale, say so explicitly.
