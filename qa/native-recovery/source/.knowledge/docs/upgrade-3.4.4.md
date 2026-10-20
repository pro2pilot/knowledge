# Upgrade to 3.4.4 RC5 for testing

This is the unpublished `RC5` candidate, with no full release gate. Use the
candidate `knowledge-v3.4.4.zip` only for candidate testing. For ordinary
installation, use the [latest published release](https://github.com/pro2pilot/knowledge/releases/latest).
Keep a backup and follow the system-file update procedure in
[INSTALL](../INSTALL.md). Preserve project modules, evidence, wiki, sessions,
curated settings, lifecycle records and content-addressed receipts. Reinstall
the active agent integration to update its managed instructions.

This tree is audit revision `independent-audit.20261020.windows.4`. Use this revision's
`candidate/knowledge-v3.4.4.zip` and SHA from its new handoff. The audit input was
the supplied Windows follow-up, not an older 3.4.3 checkout.
The unchanged version/candidate label does not identify the new bytes and
does not promise automatic update detection. Linux/macOS native verification
is unavailable and refuses before probes. Review [the current audit](verification-execution-contract.md)
before upgrading an audit fixture.

This continuation adds `verification-watchdog.js` to the required installed
files and current currency authority pins. An older currency receipt may need
reverification after upgrade. Historical eight-pin signed native batches remain
readable; this does not make their factual currency current for new code.

Native verification now emits v2 command records, a batch finalization record
and a signed acceptance returned after Windows Job Object teardown. Preserve
`maintenance/verification_finalizations/` alongside execution records. A saved
command record alone, including an older v1 KVE, cannot authorize new receipts
or currency issuance. Re-run verification and retain `verification_acceptances`
from its JSON result; the updater does not synthesize acceptance for old records.
Team completion is derived from each attempt's finalization record after lock
release. An interrupted attempt stays incomplete or unknown until reviewed;
`--retry-of=<run-id>` explicitly starts a new attempt for a confirmed failed run.
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
