# Upgrade to 3.4.4 RC5 for testing

This is an unpublished `RC5` audit candidate with no release certification. Identify
the exact ZIP and scoped test results by SHA-256 in its accompanying handoff. Use
`knowledge-v3.4.4.zip` only for candidate testing. For ordinary
installation, use the [latest published release](https://github.com/pro2pilot/knowledge/releases/latest).
Keep a backup and follow the system-file update procedure in
[INSTALL](../INSTALL.md). Preserve project modules, evidence, wiki, sessions,
curated settings, lifecycle records and content-addressed receipts. Reinstall
the active agent integration to update its managed instructions.

This tree uses audit revision `independent-audit.20261027.reliability.5`. The
675-file source snapshot at commit `5bed133f860d2d5e2ae395287d47c065c410f605`
(SOURCE SHA-256 `bea4ec0c914990e546d84883ee429eee97b7fd5d2148eaf58407b8b8ed849229`)
is a historical evidence baseline, not the current `.5` artifact. New source and
package pins must be recorded after the docs-integrated candidate is rebuilt.
The unchanged version/candidate label does not identify
the bytes and does not promise automatic update detection. Review
[the current audit](verification-execution-contract.md) before upgrading an audit
fixture.

The request contract supports macOS isolated-copy verification, but the product
installer does not install the privileged broker or provision its reserved private
UID range. Those are separate administrator tasks. A ready broker does not enable
verification: each request must explicitly set
`native_execution.darwin.enabled=true` and `mode="isolated_copy"`, with broker
paths and copy limits. Writable Flow/Team requires separate admin-provisioned
workspace access; it is distinct from isolated-copy verification. Verify exact
broker/runtime binaries in the assembled archive and installation procedure rather
than inferring their presence from this source guide. Fresh macOS qualification
remains incomplete. Legacy versioned acceptance pin lists remain unchanged; this
compatibility statement does not claim current Windows/Linux authority paths or
runtime bytes are unchanged. Stricter proof readers reject contradictory
inferred/observed cleanup claims.

This continuation adds `verification-watchdog.js` to the required installed
files and current currency authority pins. An older currency receipt may need
reverification after upgrade. Historical eight-pin signed native batches remain
readable; this does not make their factual currency current for new code.

Current native verification supports Windows Jobs and Linux when native namespace
prerequisites pass. Current common verification finalization uses KVFv4 and ACKv4; historical v1–v3
readers preserve their original pin/proof contracts. Linux
execution remains conditional on successful namespace setup. macOS verification
stays disabled unless a request explicitly enables `native_execution.darwin` in
`isolated_copy` mode and provides configured broker paths and copy limits. The
administrator-installed broker and UID provisioning are separate from installer
execution. Writable Flow/Team remains a separate admin-provisioned capability.
See the [native broker guide](native-darwin-broker.md). Historical source-pinned
macOS evidence does not complete fresh qualification of the `.5` artifact or the
release gate.

For restricted Linux hosts, a separate system broker with isolated-copy execution
is the accepted design direction; production implementation and qualification
are not complete. Hosted Ubuntu 24.04 ARM64 refused nested PID namespace setup
with `EPERM` without changing host policy. The preceding reliability.4 scoped
physical testing on Windows x64 / Node 22.17.1 passed 61 selected TAP cases plus 20
runtime-safety checks. Reducer correction reinterpreted saved TAP output without
rerunning those physical tests. Preceding reliability.4 Team evidence is 7/7 physical cases
and 8/8 shipping steps; Doctor is 86/100 `usable_with_warnings` with medium
`suspect_module` and `low_confidence_module` warnings. These scoped results do
not qualify the changed reliability.5 runtime, stock-SIP Macs or the final
installed ZIP. New audit5 matrix evidence has separate source pins; no final
passing outcome is asserted here. The historical second
ownerless-lock cause remains unknown.

Current KVEv2 command records are not a batch acceptance by themselves. Preserve
`maintenance/verification_finalizations/` alongside execution records and retain
the returned verification acceptance when recording new verified results. The
historical v1/v2 finalization readers remain available for existing records; those
records retain their original artifact and evidence scope. Old evidence is not
current factual currency for changed code and does not receive new acceptance by
upgrade. Re-run verification and keep the current acceptance in its JSON result;
the updater does not synthesize acceptance for old records. Team completion is
derived from each attempt's finalization after lock release. An interrupted attempt
stays incomplete or unknown until reviewed; `--retry-of=<run-id>` explicitly
starts a new attempt for a confirmed failed run.
New attempts use TFR v2. Completed valid v1 records remain readable as
`legacy_v1`; a pending v1 attempt must be reconciled before v2 finalization.
Do not delete or rewrite historical records to make them look current. A custom
Team state root must be a physical strict descendant of the selected team root.
See [Team mode](team-mode.md) for the current operational contract.

Read the [RC3 audit guide](audit-3.4.4-rc3.md) before comparing results with RC2.
Malformed or unproven readiness comparisons now report unavailable instead of
an invented numeric improvement. Stricter currency authority pins and native
record checks can invalidate earlier local evidence; review and reverify the
current scope. The updater does not rewrite or reissue that evidence.

System update preflight still requires the exact protected evidence set. Its
post-check phase can create new committed sync/Doctor queue journals; only the
independently validated two-output, guarded journal shape is accepted. Existing
file bytes, earlier successful-apply journal pins, factual currency and
recording history remain protected. The raw added-file count remains visible
even when those approved additions make preservation successful.

An old receipt that accidentally marked a protected context file clean is not
retroactively corrected or rewritten. Restore that file's pending freshness
from known current source/repair evidence, then verify it through the dedicated
workflow. Do not reapply the old ordinary receipt as a shortcut or force trust.
This patch prevents the faulty certification on new native apply transactions.

The supplied local hotfix for an existing 3.4.3 installation may retain its base
version and custom project repairs. Its patch manifest lists the exact changed
system files and backup; that overlay is not a certified 3.4.4 upgrade.

[Recording blockers](recording-blockers.md) describes chat notices and the
Inspector controls. A “Once” exception is bound to the blocked task's immutable
workflow ID; it is not available to the next task. A project exception is an
exact path classification, not a folder/prefix whitelist. Revoking it makes
subsequent validations of that path strict again, including retained evidence.

## Factual currency overlay

The candidate adds opt-in v3 factual currency receipts. Follow
[the factual currency guide](factual-currency.md) to prepare, independently
review, check and issue through an exact-input batch. Issuance adds immutable
receipts, a currency index and batch operation evidence. It does not edit or
close raw stale-item or repair-queue records and it does not certify or close
application risks. The currency projection and application assurance remain
separate from Doctor's legacy joint quality score.

Local v1/v2 prototype receipts are not accepted by the v3 evaluator. Automatic
migration, deletion or index reset for those prototype artifacts is not
implemented; do not treat them as v3 evidence or remove them as part of this
upgrade. This candidate does not promise that an arbitrary central CLI
installation can run the exact currency CLI check from another checkout.

RC5 adds bounded native verification and operational lock diagnostics. Review
[the RC5 changes](audit-3.4.4-rc5.md) before testing. Existing unknown-owner
locks are reported for review; upgrading does not authorize deleting them.

## Reliability audit 2026-10-25

Historical status for the 2026-10-25 source only. It is superseded for current
macOS capability and integration by the source snapshot and current audit linked
at the top of this guide.

This derivative is based on the exact prototype.3 audit.1 followup.1 runtime
`7a8c1fbb08725e610620545966997f7e93d46e6b3d9dc8ae31486544c22b191c`.
The separate prior-chat notes describe pipeline4, whose source was not supplied;
no pipeline4 implementation or acceptance is inherited here.

The audit hardens bounded physical reads of owner/control/evidence files and
Darwin native inputs, detects closed IPC and truncated authority output, confines
auxiliary report writes and Team workspace selection, checks cleanup retry
admission against a monotonic budget, and uses monotonic elapsed measurements
for ordinary Flow/evaluation. Production work/progress/cleanup budgets are unchanged.

In this historical revision, Darwin production capability was disabled. The changed native source then required
fresh whole-broker/stub compilation and service/load acceptance on Intel and ARM
macOS with the intended SIP configuration; portable C tests are not that evidence.
The synchronous Darwin durable writer can still delay stop. Common-lock recovery
on Windows/macOS and atomic first-owner publication remain unqualified. The
ordinary Flow/evaluation subprocess path still lacks an independently supervised
whole-process-tree cancellation contract. Full release gate is BLOCKED; this is
an unpublished development candidate. Prior Windows/macOS receipts bind prior
bytes and do not qualify this derivative.
