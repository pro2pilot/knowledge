# Routing and task-result reporting

For meaningful scoped work, use the committed result from:

```bash
node .knowledge/tools/agent-task.js finish --workflow-id=<ATW-id> --request=<finish.json> --json
```

Treat that result as the canonical task report. Keep separate:

- primary verification outcome;
- task-route snapshot and exact first-read acknowledgement;
- one routing-context state: workspace-to-task narrowing, estimated overhead,
  neutral, or unavailable / not comparable;
- Global Doctor before/after;
- Task Readiness before/after;
- native KVE/KVR IDs and sustained repair status;
- deferred unrelated debt;
- provider usage only when an actual provider receipt was supplied.

Use `node .knowledge/tools/flow.js release` only when the task or repository
policy requires the broader release workflow. A structured optional release
failure must remain visible as `completed_with_warnings`; it must not replace or
hide a verified primary task result.

Always state that a routing percentage is a deterministic local first-read
context estimate, not provider-reported model-token usage. Do not describe it as
actual token savings, model speed, general model accuracy, error reduction, or
API cost savings.
