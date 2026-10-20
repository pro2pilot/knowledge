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

Successful verification requires validated command results, an empty native
container and observed keeper termination. Windows uses a Job Object. Linux
uses a private user/PID namespace whose trusted PID 1 owns the descendant
lifecycle; the ordinary completion path waits for that init to be reaped.
A termination request, a dead worker PID, or a process-group sweep alone is
insufficient. Detached sessions and reparented children remain in the container.

If cleanup cannot be confirmed within its budget, the attempt remains claimed
with `cleanup_unconfirmed`. A new verification against the same state root is
refused. Currency issuance, repair application and recertification also acquire
the same resource guard before their mutations, including calls using an older
valid ACK. Status and diagnostics remain available. Historical KVE/KVF and ACK
files are retained; no late result changes the stopped attempt into PASS.

Recovery first persists an irreversible stop fence and an exclusive recovery
reservation under the control mutex. The former owner cannot start work,
publish progress or commit an ACK after that fence, including when the native
adapter throws or times out. A late, independently validated owner cleanup receipt
may still be appended after the fence: it only records additional evidence and
cannot permit work or an ACK. Recovery reservations compare immutable container
identity, so this append does not invalidate an in-flight reservation. Native
waits run outside the mutex, so status and cancellation remain available. A competing recovery cannot perform native
actions while the first recoverer is still active. Takeover requires an exact
native observation of the previous recoverer's exit; age alone is insufficient.

The CLI still handles the narrow no-process and fully observed controller-only
cases. It also invokes the platform recovery adapter for an attempt with a
durable native descriptor. The descriptor binds the attempt to the original
container and process births before work is permitted. Linux recovery checks
boot, observer namespace, procfs and process birth identities, using pidfds for
live processes. A recorded init already absent or replaced is handled only by
the separately labelled, context-checked kernel inference; it is not reported
as a newly observed waitpid event. No unrelated replacement PID is signalled.

Windows recovery reopens the recorded named Job and checks actual emptiness,
or uses a previously persisted, descriptor-bound cleanup receipt and verifies
the remaining outside controller. A missing Job name without that receipt is
not sufficient proof. A legacy attempt without a durable container descriptor,
or an unresolved pre-descriptor spawn, remains quarantined. Recovery never
issues an ACK. Do not delete a claim because a PID disappeared or use a new
state root to bypass the resource guard.

## Durable native cleanup transcript

New contained attempts use control schema v3. On confirmed terminal cleanup,
`cleanup.native_transcript` preserves the exact native adapter return separately
from the proof bound to the attempt, generation, descriptor and recovery ID.
`payload_sha256` covers the JSON payload; `evidence_sha256` covers the bound
proof without its own digest field. Both use UTF-8 `JSON.stringify` bytes in
stored property order. This is local evidence integrity, not a signed OS
attestation or proof that a privileged writer could not change local state.

The transcript is limited to 64 KiB and the control record to 256 KiB. It is
written and read back with terminal state before the claim is released; the
next attempt archives the complete previous record. Missing native returns,
digest mismatch, oversized data and forbidden capability/private-key fields
fail closed. No proof is silently truncated or redacted. Historical v1/v2
control records remain readable with an explicitly absent optional transcript;
reading history does not manufacture evidence or certify current code.

Windows normal and recovery paths retain their actual native returns. A ready
candidate and trusted work-completion notice travel on separate channels;
both are required before acceptance, regardless of arrival order. Waiting for
the latter remains bounded by work/cancellation and cleanup policies.

## Evidence and platform limits

New batches use finalization and acceptance schema v3. They retain separate
work and cleanup budgets and bind the current implementation, native backend
and container descriptor. Historical v2 Windows records retain their exact
sixteen-file list and work/cleanup rules. Historical v1 records retain their
original total-budget rules and exact eight- or ten-file lists. A historical
format cannot substitute a new backend or a different pin list. Currency
checks determine whether historical evidence covers the current source;
history is not rewritten and an old acceptance does not make changed code fresh.

Linux requires user and PID namespaces, pidfds, readable native identity
metadata and a system C compiler for the bundled helper. The helper is built
locally from the pinned source; no binary is downloaded and no host mount,
cgroup or kernel policy is changed. The cache binds source, compiler and binary
digests. The outer trusted authority retains only the child-user-namespace
capability needed to establish the inner namespace; command workers have no
permitted, effective or ambient capabilities and use no-new-privileges.
Unavailable prerequisites stop setup without admitting a command. A runtime
setup failure after a reserved spawn can still require explicit recovery.

This backend controls descendant lifetime; it does not isolate the filesystem,
network, or work delegated to an independent external service. The current
environment uses inherited procfs; readable process metadata is not a claim of
private procfs isolation. Runtime capability is checked through actual native
setup, not inferred solely from an operating-system name.

macOS has no equivalent backend in this candidate and remains explicitly
unsupported for native verification. Physical Windows recovery results are
recorded in the current handoff; installed and release-gate acceptance remain
separate checks. Linux results do not certify macOS or Windows. The historical creator of the second ownerless lock remains unknown.

Kernel basis: [Linux PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html),
[pidfd lifecycle](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), and
[Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

This is an unpublished audit candidate. Focused test results and their exact
source hashes belong in its handoff. They are not a full release-gate result.
