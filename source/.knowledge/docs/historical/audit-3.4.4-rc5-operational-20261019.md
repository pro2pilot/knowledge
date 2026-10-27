> Historical RC5 operational audit for the earlier 2026-10-19 source snapshot.
> Its platform and timeout statements are preserved as historical evidence and do
> not describe `independent-audit.20261027.reliability.4`. See the
> [current RC5 audit](../audit-3.4.4-rc5.md).
# 3.4.4 RC5 operational changes

Historical record for unpublished revision `independent-audit.20261019`.
The timeout contract below has been superseded by the
[work/progress/cleanup contract](../verification-execution-contract.md) in
`independent-audit.20261020.windows.4`. Historical results remain unchanged.
Full release gate not run. This page preserves the earlier RC5 operational and timeout
contract; the [mechanism audit](../audit-3.4.4-rc5-mechanisms.md) describes subsequent
fixes and evidence limits. Supplied Windows results are historical input evidence,
not a Windows verification of this derivative. Native verification on Linux and
macOS remains unavailable.
RC5 derives from 3.4.4 RC4. The older 3.4.3 audit supplied defect scenarios, not
certification of this candidate. Existing RC4 fixes remain part of this tree.

## Doctor and locks

Doctor adds `lock_safety` and `operational_readiness` for the selected state and
project knowledge roots. An unsafe lock creates a protected manual-review
finding and a failed check. Scoped content readiness remains visible separately
from the operational block. The legacy global joint score can also fall when
this critical finding is present. The workflow retains these diagnostic fields.

Audit.1 also checks the physical `locks`, `locks/v1`, `.stale` and `.release`
layout parents. Dangling links and reserved paths occupied by ordinary files
are unsafe, matching acquisition's existing refusal. Missing directories are
not created by inspection.

This is a point-in-time observation. It does not inspect shared team-registry,
repository-flow or system roots and cannot promise that a later lock acquisition
will succeed. Team status separately inspects the existing registry lock without
initializing a missing registry. Neither command silently removes ownerless or
unverifiable locks. A known live Doctor lock held by the current call is expected.

The lock manager binds cleanup authority to its own created directory identity
and canonical owner bytes. A replacement directory or changed owner cannot be
adopted during cleanup. Failed publication keeps its original error and reports
cleanup failure separately. Empty-directory cleanup is nonrecursive, so content
arriving after the empty check is retained. RC4's bounded Windows rename retry
is preserved. These checks do not provide a general hostile-filesystem atomicity
guarantee between every OS operation.

## Team flow finalization

Flow emits its terminal result after releasing its team lock. A release failure
keeps earlier step results and their flow-log binding, marks finalization failed
and suppresses onboarding. If the primary operation already failed, its failure
code remains primary. Acquisition/event errors likewise retain secondary release
or event failures. Optional Inspector launch happens only after successful
finalization; a process spawn acknowledgement is not proof that a window opened.
The persisted `flow_end` event and raw workspace `last_status` precede final
lock release and can remain `ok` if finalization subsequently fails. Current
Team readers use the selected attempt's validated finalization record. TFR v2
binds its selected state root, context and semantic log contents; use that
reader result rather than treating the event or raw registry status as proof.
See [Team mode](../team-mode.md) for v1 compatibility and explicit retry.

## Native verification budget

The optional top-level `timeout_ms` in a native verify or `agent-task finish`
request bounds the verification batch. It does not bound routing, Doctor, repair
or the entire finish workflow. Without it, the total is the sum of the declared
test budgets. Each test defaults to 120000 ms. Explicit values are integer
numbers from 1 to 600000 ms; they are not silently clamped.

The monotonic budget starts before bounded inert request admission and
serialization. Active getters, proxies and serialization hooks are rejected
without invocation. On a supported platform, a separate supervisor
covers setup, sequential probes, source hashing, receipt publication and owned
process cleanup. Ten percent of the total, capped at 5000 ms, is reserved inside
the budget for cleanup. Per-test deadlines can stop work earlier. A late result
or unconfirmed teardown fails closed. OS scheduling may delay returning a
failure; the deadline is not a hard real-time promise. Emergency transport
termination never extends the budget for a successful result.

On Windows, the bundled PowerShell helper assigns the idle worker to an unnamed
Job Object before any probe starts. Descendants inherit membership, including
children whose immediate parent has exited. Normal close queries zero active
processes; helper termination or loss of its control pipe closes the job. The
host must permit Windows PowerShell, local `Add-Type` compilation and job
assignment. Failure to establish containment prevents probe execution.

Audit.1 disables native execution on macOS and Linux because the previous
process-group backend could miss descendants that created a new session.
These platforms return `verification_containment_unavailable` before worker
or probe creation, with no KVE and teardown `not_required`. This removes the
false containment PASS; it does not restore POSIX native execution support.

Successful KVE receipts acknowledged before interruption remain listed as partial
evidence. A receipt interrupted around publication may exist without an
acknowledgement; it is not silently counted as completion or automatically
retried. A failed command cannot publish a passing KVE. Inspect `verification_budget`,
`completed_executions` and `teardown` in the failure report before recovery.

## Remaining historical uncertainty

The original second ownerless-lock creator and the cause of the historical
Field Report timeout are not established. Controlled crash/race tests reproduce
possible mechanisms; they do not identify the historical writer. Prior FAIL
records and unknown causes are retained in the audit handoff.
