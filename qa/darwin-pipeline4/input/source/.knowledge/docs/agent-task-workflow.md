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

## Verification time budget

Native verification separates the work budget, the absence of meaningful stage
progress and cleanup. `timeout_ms` retains its role as the batch work budget;
`verification_policy` selects a profile or overrides the three limits. Cleanup
has a separate window and API return can follow the work deadline. A command
without trusted checkpoints uses its test/work budget; silence and heartbeat
messages do not establish a hang or extend a budget. An accepted cancellation
or timeout cannot produce a late ACK.

See [timing profiles, cancellation and recovery](verification-execution-contract.md)
for defaults, examples and limits. Unconfirmed cleanup retains a durable claim;
status and Doctor remain available while conflicting verification is refused.
The old millisecond-return criterion is superseded, not reported as fixed.

Windows requires the bundled PowerShell Job Object helper to establish process
containment before tests start. Failure output retains acknowledged partial KVE
IDs and reports cleanup status. See [RC5 details and limits](audit-3.4.4-rc5.md).

Linux verification uses the PID-namespace backend when its native prerequisites
pass. macOS production verification remains unavailable. Its
`verification_containment_unavailable` refusal creates no KVE and prevents
`finish` from completing the verification phase. Existing routing and Doctor
are outside that native batch and may already have run. Do not mark the workflow
completed or invent verification receipts for this refusal. See
[the current execution contract](verification-execution-contract.md).

The development `native_execution` field is preserved in the normalized finish
request and replay hash. Its `nativeExecution` alias is accepted only when the
snake alias is absent; supplying both refuses. Explicit enabled Darwin settings
currently refuse before a finish claim or native work is created, including on
Windows/Linux. They cannot silently select another host backend or reinterpret
previous acceptance. Absent settings retain the existing host selection. See
[the Darwin development contract](native-darwin-broker.md).

## Optional factual currency maintenance

Factual currency is an opt-in overlay. The finish request may set
`currency_updates` to one canonical relative path containing an exact-input
v1 batch request; the full child request, review and every computed source pin
must be included in `source_files`. Finish adds the native `check-batch`
command to the verification batch and, after verification passes, reuses the
native KVE IDs for batch issuance. This performs one verification batch and
does not require the user to manually pass KVE IDs to the finish workflow.
See [Factual currency overlays](factual-currency.md) for the request, review
and batch structures and the direct `issue-batch` command.

Currency issuance writes immutable receipts, an index and a batch operation
record. It does not alter raw lifecycle ledgers, close findings, or certify
application risks. Currency facts and application assurance remain separate
projections. The legacy Doctor joint quality score is not redefined by this
overlay, and its operational unknown-history remains in that score.

Finish also returns `knowledge_maintenance` separately from the primary
verification result. When `knowledge_maintenance.chat_notice` is present,
relay it to the user immediately in the user's preferred language and include
the specific maintenance status and `next_action` in the final report. Do not
assume an arbitrary agent runner has a chat hook; displaying the field in its
own output does not guarantee delivery. `report_only` is supported. An explicit
`currency_defer` must name exact eligible lifecycle IDs and a nonempty reason;
protected application risks and globally blocked currency state cannot be
deferred.

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

## Recording blockers and chat notices

An agent must not silently skip task accounting when a meaningful task or
required `.knowledge` write is blocked. Use the blocker registry when
available:

```bash
node .knowledge/tools/recording-blockers.js list
node .knowledge/tools/recording-blockers.js resolve --id=<id> --scope=once --reason=<reason> --confirmed=true
node .knowledge/tools/recording-blockers.js resolve --id=<id> --scope=project --reason=<reason> --confirmed=true
node .knowledge/tools/recording-blockers.js revoke
```

For `list`, relay the returned `chat_notice` in the user's preferred language.
State the specific task or record that is blocked and the reason. If a secret
caused the block, identify its type or setting and show only a safe mask such
as `********`; never disclose the value. Do not treat a notice as confirmation
to resolve a blocker. A generic `blocked_by_user_scope` blocker is not
automatically resolvable.

If the user explicitly confines writes to a directory that excludes
`.knowledge/`, obey the scope. Do not write blocker state elsewhere or bypass
the restriction. Keep `blocked_by_user_scope` visible in the chat and final
result, and offer: вЂњР•СЃР»Рё СЌС‚Рѕ РЅРµ СЃРµРєСЂРµС‚, СЃРѕРѕР±С‰РёС‚Рµ РІ С‡Р°С‚Рµ РёР»Рё РІС‹Р±РµСЂРёС‚Рµ РґРµР№СЃС‚РІРёРµ
РІ InspectorвЂќ. The registry instructions are not a mechanical guarantee for
arbitrary agent runners; when it cannot be used, report the blocker visibly
instead of omitting it.

Relay a `knowledge_maintenance.chat_notice` from `agent-task finish` with the
same urgency and language requirement, even when primary verification passed.
This maintenance notice is separate from the recording-blocker registry and
must not be treated as proof of a delivered message by an external runner.

## RC5 current verification evidence

KVE v2 command records require their exact signed `verification_acceptances`
for new task PASS, repair, recertification or currency issuance. Preserve the
`maintenance/verification_finalizations/` store and the complete native verify
JSON. Reused KVE IDs without acceptance, and legacy KVE v1, do not authorize
new certification. `agent-task finish` propagates acceptance automatically.
See [the native and Team finalization contract](audit-3.4.4-rc5-audit1.md).

## Current-task footer after source drift

The incomplete-trust footer uses effective task evidence before suppressing a
message. A previously healthy global report cannot hide a proven change in
bound task inputs. Missing or ambiguous task binding is unknown; incomplete
snapshot evidence is unavailable. The full footer labels the saved global
report separately. Estimator/comparison limitations alone do not mark unchanged
sources stale. Explicit footer mode `off` still disables the footer.
