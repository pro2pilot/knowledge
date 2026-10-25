Use `.knowledge/` as the repository-local trust and task-routing layer.

## Default meaningful-task entrypoint

Before broad repository exploration, start a scoped task:

```text
node .knowledge/tools/agent-task.js begin \
  --task="<exact engineering task>" \
  --scope-module=<module-id> \
  --scope-path=<path> \
  --json
```

Read the returned `route.first_read.content` immediately. Preserve the returned
`workflow_id` and `route.first_read.sha256`. The task snapshot, canonical
workspace comparison and first-read body are immutable evidence for this run.
Do not substitute the global routing bootstrap for this task-specific first
read.

Then inspect only the selected source/tests and any required continuation or
direct dependency. Re-read current code for behavior claims and critical edits.

## Source-of-truth order

1. Current code
2. Current tests
3. `.knowledge/evidence/*.json`
4. `.knowledge/modules/*.json`
5. `.knowledge/decisions.json`
6. `.knowledge/wiki/*.md`
7. `.knowledge/sessions/*`

Code beats summaries. Tests beat prose. Wiki is advisory unless backed by
evidence and current code/tests.

## Trust rules

- `trusted`: usable for routing and limited planning; re-read code before critical behavior edits.
- `near_trusted`: usable after targeted code checks.
- `routing_trusted`: use only to choose files, modules, and boundaries.
- `advisory_only`: context only; never source of truth.
- `suspect`, `needs_recheck`, `low_confidence`: re-read source code before behavior claims or edits.

## Finish the task with native evidence

After the primary change and relevant local tests are ready, create a finish
request inside the repository containing the exact first-read SHA,
changed/source files and physical test argv. Test `cwd` values are relative to
the repository root. Then run:

```text
node .knowledge/tools/agent-task.js finish \
  --workflow-id=<ATW-id> \
  --request=<finish-request.json> \
  --json
```

The workflow executes primary verification once. If exactly one safe,
task-relevant `verify_on_touch` finding is selected and every affected artifact
is explicitly in the verified source set, it reuses the native KVE execution
IDs to create one native KVR and applies only that exact lifecycle finding.
Ambiguity, protected findings, missing artifacts, failed tests and unsustained
recertification fail closed. Unrelated debt stays visible.

## Blocked recording and user notice

Do not silently omit a meaningful task or a required knowledge-state update
because recording is blocked. Tell the user in their preferred language what
specific task or record could not be written and why. If the reason involves a
secret, identify its type and relevant setting or location, but never reveal
the value; show only a safe mask such as `********` (or a short, policy-approved
prefix/suffix for a long value).

Use the local blocker registry when it is available:

```text
node .knowledge/tools/recording-blockers.js list
```

Read the returned `chat_notice` and communicate it in the chat. A user may
resolve an eligible blocker only with an explicit confirmation and reason:

```text
node .knowledge/tools/recording-blockers.js resolve --id=<id> --scope=once --reason=<reason> --confirmed=true
node .knowledge/tools/recording-blockers.js resolve --id=<id> --scope=project --reason=<reason> --confirmed=true
```

The registry also supports `node .knowledge/tools/recording-blockers.js revoke`.
Do not invent flags or treat a listed notice as user confirmation. A generic
`blocked_by_user_scope` item cannot be auto-resolved. If the user explicitly
limits writes to a directory that excludes `.knowledge/`, obey that boundary:
do not write elsewhere, use another state root, or ask a tool to bypass it.
Leave the item visibly blocked as `blocked_by_user_scope` and explain this in
the chat. Include the offered next step in the user's preferred language: “Если
это не секрет, сообщите в чате или выберите действие в Inspector”.

These instructions describe agent behavior; they do not mechanically guarantee
that every runner records every task or displays a notice. If this runner cannot
use the registry, still report the blocker visibly in the chat and final result.

The final result keeps the engineering outcome separate from routing evidence,
Doctor, Task Readiness, repair receipts and deferred debt. It also writes a
content-addressed first-read acknowledgement receipt bound to the finish
request. This is proof of exact snapshot acknowledgement, not proof that the
agent was technically unable to inspect other files.

## Context estimate rule

A task-routing percentage is a deterministic local first-read estimate. It is
not provider-reported model-token usage, cost, accuracy or speed.
