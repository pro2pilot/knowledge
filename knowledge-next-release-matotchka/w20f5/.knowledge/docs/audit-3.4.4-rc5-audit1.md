> Historical audit.1 continuation documentation. The current derivative is
> `independent-audit.20261019.windows.1.followup.1`; see [current audit](audit-3.4.4-rc5-windows-followup.md).
> Hashes and host results below identify their original artifacts and do not
> certify the current source or runtime.

# 3.4.4 RC5 independent audit.1

This is an unpublished derivative of the supplied RC5, for continued agent
work. Package, configuration and install-manifest versions remain `3.4.4`;
`knowledge_release.candidate_label` remains `RC5`. The additional
`audit_revision` is `independent-audit.1`. This is not a stable release or RC6.
The complete release gate has not been run.

**Native verification is unavailable on Linux and macOS in this revision.**
Those platforms now refuse before launching a verification supervisor, worker
or probe. They do not return a successful batch or create execution receipts.
Windows uses the Job Object backend and must establish containment before
starting probes. The updated handoff records new Windows tests against exact
source/runtime hashes. Original RC5 and incoming audit results are historical
evidence, with their own byte identities; they are never inherited as PASS.

## Identity and installation for audit

The input runtime ZIP has SHA-256
`c0b5ce127d346b0eb4b16f23f6df05d020e4152bb58990bfaadae716c5dc8d01`.
The source of this derivative is the full RC5 source supplied in that
candidate's handoff. It is not a 3.4.3 checkout. The separate audit handoff
contains the patch, frozen source, exact new runtime ZIP, test outputs and
the new ZIP's SHA-256.

Use that audit.1 handoff's `candidate/knowledge-v3.4.4.zip` for an isolated
audit installation. Verify its new SHA and `audit_revision` before testing.
Version-only checks cannot distinguish the input RC5 and this derivative;
automatic upgrade detection for this audit revision is not promised. The
canonical runtime name remains `knowledge-v3.4.4.zip` for the RC5 release
contract. The containing handoff archive is explicitly named `RC5_AUDIT1`.
Its manifest, audit revision and runtime SHA distinguish these bytes. Do not
substitute a similarly named older ZIP.

## Lock layout diagnostics

Named, all-lock and context inspection now use one read-only physical layout
check for `locks`, `locks/v1`, `locks/v1/.stale` and `locks/v1/.release`.
An absent directory is allowed and is not created. A regular file, symlink,
dangling symlink or directory reparse point at any of these positions is
reported as `unsafe_lock_parent`. Inspection stops at an absent or unsafe
ancestor and does not inspect through it.

Acquisition already rejected these obstructions. Doctor and Team Status now
show the same observed obstruction instead of a misleading healthy result.
Doctor's `operational_readiness` becomes `blocked`; the content score for an
unrelated task remains separate. This remains a `snapshot_only` observation,
not a guarantee against changes before the next acquisition.

No ownerless lock is deleted by this diagnostic change. Publication grace,
recovery policy, owner/directory cleanup authority and the existing bounded
Windows rename retry remain in force.

## Native verification boundaries

The previous POSIX process-group cleanup could miss a child that created a
new session. A real detached child continued writing after the original RC5
returned both a successful KVE and `teardown.status: completed`. The timeout
path could also report completed teardown while that child remained alive.

This revision prevents the false result by refusing unsupported containment.
The error code is `verification_containment_unavailable`, with execution
`not_started`, teardown `not_required`, and no completed execution IDs.
The guard applies to the public runner, transport, direct supervisor and
worker core. A custom worker test entry does not enable a weaker POSIX backend.
`agent-task finish` cannot complete its native verification phase on these
platforms. Existing native execution scenarios are not counted as passing
because the feature is unavailable.

This closes the false containment claim; it does not restore POSIX native
execution. A future backend must contain detached descendants, handle loss of
the controller/helper, and confirm complete teardown. Process ancestry scans
or a subreaper alone do not supply all of those guarantees. A Linux kernel
containment backend also needs an explicit capability check and real host
tests. macOS requires its own supported design and tests.

Public native request objects are copied through the existing bounded inert
data validator before property reads or serialization. Accessors, proxies,
serialization functions, excessive depth and over-limit data are rejected
with `verification_input_invalid` without invoking caller code. Numeric
timeout validation preserves `verification_timeout_invalid` for invalid
timeout values. Earlier inert admission can reject an oversized request
before it reaches the transport's byte limit.

For supported execution, the existing monotonic deadline and Windows Job
Object contract still apply. The batch deadline includes setup, sequential
probes, source hashing, receipt publication and cleanup. The deadline does
not cover the entire `agent-task finish` workflow and is not a hard real-time
guarantee that an error can always be returned by an exact millisecond.
See [the RC5 budget contract](audit-3.4.4-rc5.md#native-verification-budget).

## Accepted native batches

KVE v1 remains readable as `legacy_unattested` command evidence. It cannot
issue new currency or close/recertify a finding through the current authority
readers. Existing history is preserved; renewed certification needs a new
supported native run. This migration can leave old closures visibly unverified.

New KVE v2 binds a unique batch, command ordinal, request SHA and an ephemeral
parent public key. It remains command-only evidence until the entire batch
finishes. After Windows confirms zero active job processes and the helper
exits, the supervisor writes a content-addressed KVF receipt. It binds ordered
KVE files, task/session, runtime and implementation identities, observed budget
and teardown. No worker writes an accepted batch.

After receipt readback and transport, the public parent signs
`verification_acceptances` with an ephemeral Ed25519 private key held only in
its memory. It checks the total deadline again after signing. The private key
is never sent to the worker, persisted, or returned. Missing/lost acceptance,
partial batches, unconfirmed teardown and expiry cannot authorize a new repair,
currency issuance, or task PASS. Readers verify the signature against the key
already fixed in each KVE, exact membership/order, file hashes and budget.

Public keys and signatures use fixed-length lowercase hexadecimal encoding.
Readers reject other encodings before decoding. This prevents random Base64
signature text from resembling a private filesystem path without relaxing
the privacy checks applied to evidence.

This signature prevents promotion of existing partial KVE IDs by constructing
an ACK from the persisted KVF. It is not a third-party attestation or protection
against an attacker replacing an entire locally authored evidence corpus.
`accepted_elapsed_ms` is the observation used in the signed payload; the public
runner separately checks time after signing. No exact wall-clock return bound
is promised for an OS/kernel stall or emergency cleanup after a missed deadline.

Keep the complete JSON returned by `repair-on-touch.js verify`. When reusing
its `test_execution_ids`, copy its exact `verification_acceptances` array into
the receipt request. `agent-task finish` propagates and revalidates this field
automatically, including resumption. For manual batch currency issuance use:

```bash
node .knowledge/tools/knowledge-currency.js issue-batch --request=reviewed-batch.json --execution=KVE-<id> --verification-result=native-verify-result.json
```

The result file must contain the unmodified native verify JSON. Supplying KVE
IDs alone is insufficient. Preserve `maintenance/verification_finalizations/`
with the execution and receipt stores when upgrading or transferring state.

## Team completion and retry

Every Team CLI flow starts a unique `TFR-` attempt. Immutable start and final
records live in the registered workspace's `flow-runs/` directory. The final
record is written after lock release and binds the start, checks log bytes,
checks outcome, release outcome and optional `retry_of`. The existing flow log
and `flow_end` event retain their before-release meaning; `flow_end` explicitly
has `terminal: false`. They do not alone certify full completion.

Team Status and Inspector derive final status from the bound attempt. Missing
finalization is `incomplete`, invalid/drifted evidence is `unknown`, and legacy
workspaces are `legacy_unattested`. A release-event failure after physical
release preserves both observations and stays failed after reopening. An older
attempt cannot overwrite the current attempt's final status. The raw workspace
registry keeps `last_status: incomplete`; consumers must use Team Status rather
than interpreting this cached field as terminal success.

An intentional retry uses a new run ID and explicit lineage:

```bash
node .knowledge/tools/flow.js doctor --exclusive --retry-of=TFR-<id> --json
```

Retry requires an exactly bound, finalized failed attempt of the same flow and
a currently safe lock. Incomplete/unknown attempts require investigation first.
Retry reruns the flow; it is not transaction rollback or a promise that arbitrary
side effects are idempotent. Inspect the earlier log before requesting a retry.

## Regression entrypoints

```bash
node tools/self-test-lock-layout-safety.js
node tools/self-test-native-verification-boundaries.js
node tools/self-test-verification-finalization.js
node tools/self-test-team-finalization.js
```

The lock test retains its own fixtures and validates Doctor and Team Status,
denied acquisition, nonmutation, and normal lock behavior. The native boundary
unit test intercepts process creation to prove admission happens first; it
does not constitute a native execution or containment success test. The
separate handoff also records unmodified runtime reproductions and actual
CLI checks. Existing full-source suites and their raw failures are retained.

## Continuing investigations

The creator of the historical second ownerless lock and the historical Field
Report timeout cause remain unknown. A successful controlled regression does
not identify a past writer. Keep the original evidence and avoid adopting or
deleting locks with unproven ownership.
Batch finalization does not grant a privacy exception. Its default reader
checks every member with the strict policy, even when the caller selects only
one KVE. The task workflow and writer-facing reader separately check every
member against current exact path approvals for the recorded session. A
revoked approval is rejected on new authority reads; completed task output
remains an immutable historical result. The strict legacy reader is unchanged.

