# Repair-on-touch

Repair-on-touch preserves verification that an agent already performs while
completing a real task. It is bounded knowledge maintenance, not a background
attempt to make Doctor reach 100.

## Default and modes

The built-in default is `scoped`, with these budgets:

- at most 2 findings per task;
- at most 5 additional minutes;
- at most 10 percent additional context.

The modes are:

- `off`: no opportunistic maintenance;
- `safe-only`: generated routing, index, graph, and report artifacts only;
- `scoped`: exact findings that overlap the current task;
- `dedicated`: maintenance requested as its own task;
- `aggressive` (`extended` is a migration alias): task-adjacent dependencies,
  still subject to every safety rule and budget.

Effective policy is resolved in this order:

1. team or security maximum-mode cap;
2. explicit per-run override;
3. operator/workspace setting;
4. repository setting;
5. built-in `scoped` default.

`edit_source_for_health` is always false and is not configurable.

## Runtime workflow

Start with the exact primary task:

```text
node .knowledge/tools/repair-on-touch.js plan \
  --task-id=TASK-123 \
  --session-id=SESSION-123 \
  --task="Fix authentication behavior" \
  --changed-file=src/auth.js \
  --module=auth
```

The authoritative plan is task/session scoped:
`maintenance/repair_sessions/<sha256(task_id,session_id)>.json`. The command
also refreshes `maintenance/repair_opportunities.json` as a convenience view
of the latest plan. That global file is advisory and must never be used as
authority for another task or session.

The scoped plan separates:

- selected task-relevant findings;
- deferred findings and their reasons;
- global Doctor health;
- current-task readiness;
- the effective mode, source, cap, and budgets.

Repeatable CLI selectors such as `--module`, `--changed-file`,
`--dependency-module`, `--dependency-file`, `--essential-dependency-module`,
`--critical-path`, and `--plan-step` may be supplied more than once. Routing
inventory records are normalized through their explicit `module_id`; malformed
object records never become synthetic module names or widen the task scope.

Read status only with the same explicit identity:

```text
node .knowledge/tools/repair-on-touch.js status \
  --task-id=TASK-123 \
  --session-id=SESSION-123 \
  --json
```

Complete the primary task before optional curated repair. A selected finding may
close only when every affected artifact is verified, every required check is
actually executed, the resolution predicate passes, and a verification receipt
exists.

### Record real test execution

The `verify` and `receipt` commands execute an argv array without a shell. They
store only command metadata, exit status, duration, output hashes and byte
counts, and a source-hash snapshot. Test stdout and stderr content are not
stored.

Example verification request:

```json
{
  "task_id": "TASK-123",
  "session_id": "SESSION-123",
  "source_files": [
    "src/auth.js",
    ".knowledge/modules/auth.json"
  ],
  "tests_to_run": [
    {
      "argv": [
        "node",
        "tests/auth.test.js"
      ],
      "cwd": ".",
      "timeout_ms": 120000
    }
  ]
}
```

Run it with:

```text
node .knowledge/tools/repair-on-touch.js verify --request=verify.json
```

The execution record is content-addressed under
`maintenance/verification_executions/`. A caller-authored string such as
`"status": "pass"` is not accepted as test evidence.

Generated-artifact rebuilds are a smaller allowlist: only the bundled routing,
search-index, and wiki-graph producers may run, with their exact canonical
Node argv (optionally `--quiet`). Script aliases, hardlinks, symlinks,
junctions, context-root overrides, and producer input/output escapes fail
before trust can change. Ordinary verification commands do not gain this
generated-producer authority.

Current generated KVEs bind the producer code/dependency closure and trusted
project/state roots, but not a complete root-aware manifest of every mutable
data input, missing-path fallback, directory listing, or metadata value read
by that producer. A concurrent input change can therefore make the generated
output stale after execution. This is a documented residual P2, not a trust or
marketing claim. A future closure contract must persist those observations,
guard them through phase 2, and reject input/write-set intersections unless it
rebuilds against the projected post-transition state.

### Create and apply an exact receipt

The receipt command can reuse execution IDs from `verify`, or execute
`tests_to_run` itself:

```json
{
  "finding_id": "LC-0123456789abcdef",
  "source_files": [
    "src/auth.js",
    ".knowledge/modules/auth.json"
  ],
  "test_execution_ids": [
    "KVE-<64-lowercase-hex>"
  ],
  "claims_checked": [
    {
      "claim_id": "auth-current-behavior",
      "claim": "The current auth implementation matches the focused test.",
      "result": "confirmed",
      "evidence": [
        "src/auth.js",
        "tests/auth.test.js"
      ]
    }
  ],
  "required_checks_completed": [
    "read_current_source",
    "run_relevant_tests",
    "verify_resolution_predicate"
  ],
  "predicate_result": "pass",
  "additional_work": {
    "wall_time_ms": 1200,
    "context_tokens": 80,
    "context_percent": 2,
    "input_tokens": null,
    "output_tokens": null
  }
}
```

```text
node .knowledge/tools/repair-on-touch.js receipt --request=receipt.json
node .knowledge/tools/repair-on-touch.js apply --receipt=KVR-<64-lowercase-hex>
```

Use actual runtime token values when the runtime can separate maintenance from
the primary task. Otherwise keep `input_tokens` and `output_tokens` null. Never
substitute a bytes-to-token estimate. `wall_time_ms` cannot be below the sum of
the physical KVE durations. `context_percent` and any caller-supplied token
fields remain operational telemetry, not independently measured billing data.

The evidence chain uses:

- `KVE-*`: the physical no-shell verification execution and source snapshot;
- `KVR-*`: the exact finding receipt binding KVE IDs, task, session, module,
  lifecycle occurrence, claims, source hashes, predicate, policy, and budget;
- `KDVR-*`: a separate dedicated-review receipt required for protected or
  manual-review closures.

Receipts and execution records are immutable and content-addressed. `apply`
accepts only a regular KVR inside
`maintenance/verification_receipts/`. Current source hashes, task scope,
finding ID, module, artifact set, predicate, required checks, execution
snapshot, policy, and budgets are checked again before the transaction.

Recertification is two phase. Phase 1 closes only the exact lifecycle
occurrence and freezes a trust-elevation authority that binds the KVR identity,
task/session/module/finding, canonical card path, target trust level, and
post-phase-1 card hash. Phase 2 reloads the physical KVR/KVE/KDVR evidence and
must match that frozen authority before trust elevation. The transaction
read-set rejects drift at the commit boundary for the bound authority and
evidence files. It does not yet provide the complete generated-producer data
read-set described above.

These hashes prove local content integrity and replay identity; they are not
digital signatures and do not authenticate a human or model. `checked_by`,
`reviewed_by`, verifier IDs, and approved-tool manifests are local assertions.
KDVR enforces distinct declared reviewer IDs, not cryptographic proof of
organizational independence.

## Storage, upgrade, and export boundary

Task-scoped plans, telemetry, KVE/KVR/KDVR stores, and in-flight transactions
are repo-local runtime state. The updater preserves them across a system-file
upgrade. Clean release packages and system exports exclude those directories,
so one repository's repair history is not shipped as another repository's
trusted evidence.

## Findings that stay open

Normal Repair-on-touch cannot close:

- open contradictions;
- security findings;
- policy violations;
- incidents;
- unresolved architecture conflicts;
- manual-review findings;
- another artifact's finding;
- an unrelated finding in the same module.

Critical paths and security-sensitive work require confirmation. Detector
silence does not close debt. A later source-hash change reopens the same stable
lifecycle ID.

## Doctor and task readiness

Global Doctor and current-task readiness are independent:

- Global Doctor represents repository-wide `.knowledge` health.
- Task readiness uses only findings relevant to the current task.

Closing one exact finding can make task readiness reach 100 while unrelated
repository debt remains open. Doctor score changes only by deterministic
finding score costs after the exact lifecycle transaction and a Doctor rerun.

## Settings

First-run setup and Inspector use the existing repo-local operator profile.
CLI examples:

```text
node .knowledge/tools/repair-on-touch.js settings show
node .knowledge/tools/repair-on-touch.js settings set --mode=scoped
node .knowledge/tools/repair-on-touch.js settings reset
```

Extended mode requires explicit confirmation. Team/security policy can lower
the effective mode but cannot raise it past the configured safety cap.

## Final task summary

Keep the main result and optional maintenance visibly separate:

```text
node .knowledge/tools/repair-on-touch.js summary --request=summary.json
```

The summary reports:

- primary task and primary tests;
- exact maintenance performed and receipt IDs;
- Global Doctor before and after;
- task readiness before and after;
- deferred findings and human-readable reasons.
