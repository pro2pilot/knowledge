# Native verification: work, progress and cleanup

This contract supersedes the earlier millisecond caller-return criterion for
3.4.4 RC5. Historical measurements remain in their original audit evidence.
`timeout_ms` is a work budget, not a promise that an API returns at that exact
millisecond. Cancellation and work-budget expiry start stopping and cleanup.
A completed response can therefore arrive after the work deadline.

## Timing profiles

Defaults are in `verification-policy.json`. A verification request may select
a profile and override its limits with `verification_policy`; the JavaScript
runner uses the equivalent `verificationPolicy` property.

| Profile | Work | No meaningful progress | Cleanup | Basis and use |
| --- | ---: | ---: | ---: | --- |
| `local` | 120 s | 60 s | 30 s | Short local checks. Initial Windows setup and a trivial command took about 1.3 s before cleanup. A silent three-second CPU task took about 4.5 s including setup, or 8.5 s with the test tree restricted to two CPUs competing with two load workers; cleanup took about 1.2 s in that constrained run. These are reference observations, not universal slow-host certification. |
| `suite` | 1,800 s | 180 s | 60 s | Larger sequential suites. A historical installed-policy suite took about 396 s; the work default leaves substantial room for slower runs. |
| `external` | 600 s | 120 s | 60 s | Commands involving external dependencies. This conservative initial profile has not been calibrated against every provider. Configure it for the actual operation. |

The work budget covers admission, controller preparation, command execution,
source checks and command receipt creation. Successful work is followed by
process teardown, batch receipt readback, signing and the final result commit
within one separate cleanup window. A failure or explicit cancellation starts
that window immediately. Neither nested cleanup nor a later controller starts
a second window. There is no automatic work-budget extension.

The no-progress limit applies only where the controller can verify stage
transitions or distinct command receipts. Command stdout and heartbeat messages
are never proof of meaningful progress. During a command without a trusted
checkpoint channel, this limit is suspended and the work/test budget applies.
A silent command is not described as hung. A stopped command reports the
budget that expired; a missing stage checkpoint is reported separately.

Without `verification_policy`, existing callers retain their explicit
`timeout_ms` or the sum of their test budgets. Individual tests default to
120,000 ms and accept integers from 1 to 600,000 ms. Profile work budgets can
cover a longer batch. `no_progress_ms: 0` disables inactivity detection.
Small artificial timeouts are useful for fault tests and are unsuitable as
normal operating defaults.

Example fragment in an `agent-task finish` or `repair-on-touch verify` request:

```json
{
  "verification_policy": {
    "profile": "suite",
    "work_budget_ms": 1800000,
    "no_progress_ms": 180000,
    "cleanup_budget_ms": 60000
  }
}
```

These limits apply to native verification. They do not time Doctor, routing or
the entire task workflow. Operating-system scheduling and synchronous caller
I/O prevent a hard real-time API-return guarantee.

## Status and cancellation

In a normally installed project:

```text
node .knowledge/tools/verification-control.js status --json
node .knowledge/tools/verification-control.js cancel --attempt=<VAT-id> --generation=<generation> --json
node .knowledge/tools/verification-control.js recover --attempt=<VAT-id> --generation=<generation> --json
```

Read the attempt ID and generation from `status`. Explicit context flags are
available for a separate state root. Status is read-only and reports the saved
stage, elapsed-time observation, last meaningful progress, waiting reason and
known process identities. A saved snapshot is not a new OS liveness check.
Doctor exposes this operational block separately from its content trust score.
Cancellation accepted before the final commit prevents that attempt from
returning an ACK, even if a valid result arrives later. Cancellation after the
commit returns `already_terminal`.

Use the cancellation command for an orderly stop. Terminating a caller or
controller externally is a crash path; it can require recovery.

## Cleanup and recovery

Successful verification requires validated command results, empty Windows Job
Objects and observed keeper termination. A completed job termination request,
a dead worker PID, or a later process poll alone is insufficient.

If cleanup cannot be confirmed within its budget, the attempt remains claimed
with `cleanup_unconfirmed`. A new verification against the same state root is
refused. Currency issuance, repair application and recertification also acquire
the same resource guard before their mutations, including calls using an older
valid ACK. Status and diagnostics remain available. Historical KVE/KVF and ACK
files are retained; no late result changes the stopped attempt into PASS.

Recovery is deliberately narrow. The CLI can finish an attempt with no process
spawn intents, or when the only
process was its watchdog, the parent durably observed that exact process handle
exit, and no authority or keeper spawn intent exists. This never issues an ACK.
Other cases return `requires_native_recovery` until a trusted native recovery
adapter can establish the owner and resource state. Do not delete the claim
because a PID disappeared or start another state root to bypass it.

## Evidence and platform limits

New batches use finalization and acceptance schema v2, binding work duration
and cleanup budget separately. Historical v1 records keep their original
total-budget rules and exact eight- or ten-file implementation lists. New
records use the current implementation list. Currency checks decide whether
historical evidence covers the current source; history is not rewritten.

Native verification currently uses Windows Job Objects. Linux/macOS still
return `verification_containment_unavailable` before probes. POSIX ownership
and teardown remain separate unfinished work. The historical creator of the
second ownerless lock remains unknown.

This is an unpublished audit candidate. Focused test results and their exact
source hashes belong in its handoff. They are not a full release-gate result.
