# Integrated agent task workflow

`agent-task` turns task routing, physical verification and bounded
Repair-on-touch into one explicit workflow. It is the recommended entrypoint
for meaningful scoped work.

## Begin

```bash
node .knowledge/tools/agent-task.js begin \
  --task="Update the orders route and its shared mapping" \
  --scope-module=orders_app \
  --scope-path=apps/orders/ \
  --json
```

The response creates a canonical task snapshot and returns the exact current
`first-read.md` body, relative path, SHA-256 and byte count. Read that body
before broad exploration. A public percentage is shown only when the canonical
workspace comparison remains complete, current and claim-eligible.

The local estimate compares the canonical workspace-wide first read with the
task-scoped first read. It is not provider-reported token usage, cost, model
accuracy or speed.

## Finish

Prepare a JSON request:

```json
{
  "schema_version": "knowledge-agent-task-finish-request.v1",
  "route_first_read_sha256": "<from begin>",
  "changed_files": ["src/orders.js"],
  "source_files": ["src/orders.js", "tests/orders.test.js"],
  "tests_to_run": [
    {
      "argv": ["node", "tests/orders.test.js"],
      "cwd": ".",
      "timeout_ms": 120000
    }
  ],
  "run_release_flow": true
}
```

```bash
node .knowledge/tools/agent-task.js finish \
  --workflow-id=<ATW-id> \
  --request=finish.json \
  --json
```

The request file must be a regular file inside the repository. Use
`--request=-` to supply the same JSON through stdin. Every test `cwd` is
repository-relative and must resolve to a real directory inside the target
root; symlink/junction escapes are rejected.

Finish binds the request and executes each phase through a durable journal.
Primary verification runs once and creates native KVE records. If the refreshed
scoped plan contains exactly one safe `verify_on_touch` finding and every
affected artifact is in the explicit verified source set, the same KVE IDs are
reused to create a native KVR and apply that exact lifecycle finding.

The workflow does not auto-close protected, generated, security, policy,
incident, architecture-conflict, manual-review, ambiguous or incompletely
verified findings. An unsustained recertification remains open.

## Recovery and idempotency

An identical finish request is idempotent. A different request is rejected.
Completed phases are reused. If a process dies after a side-effecting phase
starts but before its result is persisted, retry returns
`agent_task_finish_reconciliation_required`; it does not guess or repeat the
unknown side effect.

## Result

A successful finish also writes a content-addressed
`knowledge-agent-task-first-read-acknowledgement.v1` receipt. It proves that
the finish request was bound to the exact begin-time first-read SHA. It is an
acknowledgement receipt, not a claim that the model was physically prevented
from reading other files.

The result keeps separate:

- primary engineering verification;
- task routing and exact first-read acknowledgement;
- Global Doctor before/after;
- Task Readiness before/after;
- KVE/KVR and exact repair status;
- deferred unrelated debt;
- optional release-flow evidence;
- provider usage, only when an actual provider receipt was supplied.

When `run_release_flow` is requested, the release flow runs before repair
planning. This refreshes generated state before the workflow decides whether a
single exact scoped finding is safe to close. If release discovers additional
overlapping debt for the same artifact, automatic repair remains ineligible or
an attempted closure is reopened; the workflow never reports an unsustained
repair as applied.

If primary verification succeeds but the release flow returns a structured
non-zero outcome, the task result is preserved as `completed_with_warnings`,
the release failure remains visible in `release_flow`, and automatic repair is
skipped. The workflow never rewrites a verified engineering success into a
fabricated clean release.
