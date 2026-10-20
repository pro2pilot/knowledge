> Historical artifact scope. For the current candidate, see [Windows watchdog continuation](audit-3.4.4-rc5-windows-watchdog.md).

# 3.4.4 RC5 — follow-up to the Windows reaudit

Audit revision: `independent-audit.20261019.windows.1.followup.1`.
This is an unpublished candidate for continued agent work. Package, config and
install-manifest versions remain `3.4.4`; the label remains `RC5`. Identify the
candidate by its revision and runtime SHA-256 in the handoff.

## Exact input and scope

The immediate input is `KNOWLEDGE_3.4.4_RC5_WINDOWS_REAUDIT_HANDOFF.zip`,
SHA-256 `e81b7ce07bc7582a6e57259ddfda185022a9c6c60c9629dbc681b55405cf22bc`.
Its 448-file source has audit revision `independent-audit.20261019.windows.1`.
Its 399-file runtime SHA-256 is
`43887eb65f9c3fb596368a7dc0d7a1eb923723c7592664afd10f8f7e571fcf4e`.
The input source and runtime were checked by physical hashes. The canonical
runtime rebuild was byte-identical to the supplied Windows archive. The exact
byte patch also reproduced all 448 files from the preceding 445-file handoff.

Supplied Git ancestry receipts are retained. Without their Git objects or a
bundle, this audit independently proves byte derivation, not that commit
ancestry. The reported Windows head is
`265f6a6da0da5e14e151649e867251804204781d`. Use a narrow reviewed patch when
continuing an agent branch; preserve later work and resolve changed preimages
explicitly. An older 3.4.3 installation is only an upgrade fixture in historical
evidence; it is not this source base.

## Worktree Status correction

Workspace registration honors `KNOWLEDGE_DISABLE_GIT_DISCOVERY=1`. Worktree
Status must derive the same disabled Git context before selecting the
repository/workspace composite key. Previously, it rediscovered the real Git
repository and could report a registered workspace as missing. The correction
reuses the existing context helper. Explicit `--repo-id` selection, diagnostic
warnings and isolation between repositories are preserved. Actual Git fixtures
exercise both enabled and disabled discovery and the explicit selector.

## Evidence and platform boundaries

The follow-up handoff records fresh Linux executions separately from supplied
Windows results. The parent Windows full run belongs to F1: 88 suites with
86 PASS, 1 FAIL and 1 PARTIAL. F2 changed only one document from CRLF to LF;
two affected suites were replayed successfully. The resulting 87 PASS and
1 PARTIAL is a scoped projection, not a second full F2 run. The NUL-filename
scenario remains unsupported by the Windows host. The original 126-scenario
mechanism matrix retains its original source and host scope.

The evidence collector is separate handoff tooling, not installed runtime.
Its follow-up must verify retained raw output by deterministic fixture and
command ordinal, keep integrity failures visible across Team retries, and
derive overlays from matching suite identities rather than fixed arithmetic.
Collector regression fixtures do not count as fresh Windows product runs.

## Open native timeout requirement

`timeout_ms` prevents a late native result from becoming accepted authority.
It does not currently enforce the stronger caller wall-return requirement.
The supplied controlled Windows readback stall reported 4672.7395 ms as
`verification_budget.total_elapsed_ms` for a 3500 ms budget, with no
acceptance. The outer test-case duration was 4778.1772 ms; it includes harness
work and is not an isolated stopwatch around the public API. Synchronous receipt I/O can block
the supervisor event loop; the caller also permits transport/cleanup grace
and performs synchronous admission and signing. A timer around that work
cannot preempt it. Describing this limit does not close the original defect.

A future implementation must account from one monotonic entry deadline,
move potentially blocking work outside the caller's event loop, use an
independent watchdog, retain Windows Job ownership, and distinguish expired
work from confirmed teardown. Late or unconfirmed work must never grant an
ACK. Fresh physical Windows tests are required for preparation/signing stalls,
readback stalls, detached descendants, helper/supervisor interruption, Job
assignment denial and deadline-boundary races. Practical return tolerance
must be measured explicitly; a general-purpose OS is not a hard real-time
guarantee. The native backend is not rewritten by this follow-up.

## Remaining continuation work

Native verification on Linux/macOS still refuses before worker/probe creation
with `verification_containment_unavailable`. Windows Job assignment denial
and the complete native currency crash/resume path remain open scenarios.
The historical second ownerless lock creator remains unknown: no physical
process-creation chain proves its origin. Preserve ownership evidence and do
not delete ownerless locks automatically. A Doctor reopen after a new source
revision is distinct from identifying that historical lock creator.

Actual shortcut click/VBS entry, a full browser action/authentication matrix,
and live Mem0/Pinecone/Python-provider behavior are not certified here. Mock
transport and supplied browser smoke results keep their stated scope. The
full release gate, publication and cross-platform release certification have
not been run. The agent handoff lists exact commands, raw evidence, remaining
acceptance criteria and the patch preimage hashes.
