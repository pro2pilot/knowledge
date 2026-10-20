> Historical Linux mechanism audit for `independent-audit.20261019`.
> The current follow-up is `independent-audit.20261020.windows.4`;
> see [its execution contract](verification-execution-contract.md). Results below keep their original
> artifact and host scope.

# 3.4.4 RC5 — current mechanism audit

Audit input revision: `independent-audit.20261019`.
Release status: unpublished candidate. The full release gate has not been run.

## Artifact identity and evidence

The input is `KNOWLEDGE_3.4.4_RC5_AUDIT1_CONTINUATION_HANDOFF.zip`, SHA-256
`655927beed83d1c70e8452b2b1ab566592bfff1af6a66912eb5bfbefc100f6e4`.
It contains 428 source files and a 396-file runtime. Its runtime archive hash is
`54def69e5f9dad123f5d68ef1edfbc6b980653baf3822c2c2525f60e1b8a0d33`.
The source declares version `3.4.4`, candidate `RC5`, audit `independent-audit.1`.
These are the actual inputs to this audit. The reported upstream commit is input
provenance, not a locally verified Git ancestry.

The older 3.4.3 work tree was not used for this audit. A previously described
audit2 artifact was unavailable and was not reconstructed or treated as tested
source. This derivative keeps version `3.4.4` and candidate `RC5`; its new audit
revision and exact SHA distinguish it. Do not identify artifacts by their ZIP
filename or semantic version alone.

The accompanying handoff contains immutable input pins, a baseline run, focused
before/after reproductions, the final source/runtime runs, a 63-mechanism catalog
with two critic scenarios per mechanism, observed scenario results and raw
commands. Its counts and host restrictions are authoritative for that exact
artifact. Source checks, installed runtime checks, integrity assertions and
Windows input evidence are separate categories.

## Verification evidence and transaction guards

The accepted batch reader authenticates all sibling KVE command records and
their KVF finalization. It now returns physical transaction guards for every
record it read. Issuance rejects a sibling change between admission and commit
with `transaction_guard_drift`, even when that sibling was not directly selected
by the currency child. Failed issuance leaves raw lifecycle ledgers untouched.

Accepted task/session IDs in a finalization use the same string representation
as their command records. Raw request bytes and their hash are preserved; this
is not a rewrite of signed requests or a broadening of admissible request data.
Synthetic signed-data regressions exercise the portable reader and transaction.
The corresponding native producer must still be verified on Windows.

The native `timeout_ms` contract remains described in
[RC5 operational changes](audit-3.4.4-rc5.md). Linux and macOS refuse native
execution with `verification_containment_unavailable` before worker/probe
creation. Passing portable admission, signature or refusal tests does not prove
successful POSIX execution, teardown after supervisor death, or a hard real-time
response bound. Historical Windows results do not certify these changed bytes.

## Team completion records

New Team attempts use TFR v2. Before any flow step, admission checks that the
selected state root is a physical strict descendant of the selected team root,
with safe existing parents and flow-log directory. A safe custom state root
inside that boundary is supported and recorded in the start record.

Finalization reads the persisted start as its authority. It binds run ID,
repository, workspace, agent, flow, target/project roots and the selected state
root to the final record and the actual flow log. The log's status and counters
must agree with the final outcome. Caller mutation of a returned start object
cannot change those persisted facts.

Team status, PR summary and Inspector use the latest attempt's validated record.
The Inspector shows the attempt ID, binding version and selected state root.
A missing final record is incomplete; a physically present malformed/null final
record is invalid/unknown. Neither case can inherit an earlier successful run.

Completed valid v1 records remain readable with `binding_version: legacy_v1`.
An incomplete v1 attempt cannot be finalized as v2 without reconciliation.
An explicitly retried, validated failed attempt gets a new run ID and
`--retry-of` lineage. Automatic retry is not implied. Primary, release and
finalization errors retain their identities. If writing succeeded but readback
failed, diagnostics say `write_completed_readback_failed`; reconcile the actual
record before creating another attempt. See [Team mode](team-mode.md).

## Contained local report writes

External-memory status reports and debug/pro snapshot exports now preflight
their destinations and use contained atomic single-file writes. A missing state
root is created through a verified physical ancestor. Existing symlink parents,
symlink/hardlink targets and replacements at tested write boundaries are refused.
Provider status with `write: false` remains non-writing, including on missing
state roots. Export preflight runs before dependent provider reports.

Each write is checked separately. This is not a multi-report transaction: if a
later destination is replaced, an earlier valid report can already exist. These
checks do not promise universal protection against all filesystem races or
change every provider read path into a containment-checked operation.

## Additional defensive fixes

The exported action entitlement boundary now accepts inert state with exact
string-array entitlements. It rejects substring lookalikes, malformed null/object
values and active accessors without invoking them. This closes a latent exported
API defect. There was no registered extension-locked action proving that the
normal CLI or Inspector had a reachable entitlement bypass.

`withTempFixture` captures its directory's physical identity before invoking the
callback, then checks it before evidence copying and cleanup attempts. A renamed
fixture replaced by a new directory at the same path is retained and reports
`TEMP_FIXTURE_IDENTITY_CHANGED`; cleanup cannot silently delete that successor.
Standalone cleanup without a previously captured identity cannot recognize a
replacement that happened before it was called. The check and OS removal remain
separate operations and are not a general atomic deletion primitive.

The standalone ZIP helper sets UTF-8 flags in both headers and preflights names,
portable collisions, file/directory conflicts and classic ZIP bounds. Invalid
inputs are rejected before touching the previous destination. This helper has
no current production caller and is separate from the canonical release packager.
An independent Python ZIP reader verifies its Unicode output. Filesystem errors
during its final write are not covered by an atomic replacement guarantee.

The currency test fixture now disables updates in the actual `config.yaml` used
by the loader. Writing an unrelated `config.json` did not configure that loader.
The default was already disabled; this fix does not establish a past network leak.

## Watcher attempt ownership

Watcher publication and shutdown now use a dedicated local state store. Each
attempt has a nonce and tracks the physical identity and digest of its state
file; subsequent heartbeat, event, child-completion and removal operations must
still match that ownership. The shared aggregate row carries the same attempt
identity. A successor at the former pathname or aggregate key is retained and
produces an ownership diagnostic instead of being overwritten or silently
removed. Startup checks physical containment before creating runtime directories.

The intermediate stopped-state write immediately followed by unlink was removed;
the guarded aggregate records the stop, and the private state is removed only
while it is still owned. The new store is a required installed runtime file.
The filesystem checks and OS writes are separate operations, not a general
atomic ownership primitive. Actual watcher tests use physical file events and
bounded synthetic sync children; they do not certify native verification.

The three runtime writers of `maintenance/automation_status.json`—watcher,
sync and Git hook installation—now share the short `watch-maintenance`
publication lock and rebuild their own fields from the latest record. Sync
appends trigger history to that latest value; its routing updates and hook
installation no longer republish a cached whole document. The lock order is
`sync` or `git-hooks` before `watch-maintenance`; the watcher releases
its publication lock before launching sync. This addresses both a reproduced
false watcher failure during legitimate sync progress and loss of newer watcher
rows when sync published its older snapshot.

An observed aggregate change from an uncoordinated writer permits at most three
fresh read/merge attempts, with physical scope and watcher-slot ownership
rechecked each time. Ownership, malformed-state and temporary-file cleanup
errors are not retried as normal progress. Continued contention reports a
bounded failure and preserves the last observed competing publication. Present
malformed records, including a null or array `active_watchers`, now fail strict
read preflight: sync refuses before its persisted output writes, and the hook
installer refuses before managed hook writes. Missing aggregate state remains
valid initialization. This deliberately tightens the former hook fallback.
These checks do not create an atomic filesystem compare-and-swap for unknown
writers. The extended suite also runs actual sync and hook CLIs; a separate
existing smoke runs the actual watcher-to-sync chain. Neither certifies native
verification or fresh Windows behavior.

## Footer and canonical ZIP validation

The current-task footer now checks the bound snapshot, pointer, live inputs,
required sources, continuations and readiness before deciding whether an
incomplete-trust warning may be hidden. A cached healthy global report cannot
suppress the footer after proven live source drift. An unbound task is unknown;
damaged completion evidence is unavailable. A limitation of the estimator or
comparison alone does not prove source drift. The full footer labels the saved
global report separately. Explicit footer mode `off` is preserved.

The canonical release ZIP validator now checks raw name encoding and portable
segments, including NFC, Windows reserved names, alternate-stream punctuation,
trailing dot/space, valid UTF-8 and its encoding flag. It also checks agreement
between local and central general-purpose flags and rejects unsupported flag
combinations. Supported stored/Deflate entries, valid data descriptors and
Deflate options remain accepted. This is separate from the standalone ZIP
helper. Mutations of the complete input runtime were validated without extracting
or executing their entries; fresh Windows extraction remains a separate host test.

Canonical staging and physical ZIP validation also require the union of public
release paths and `install-manifest.json`'s `required_system_files`, using exact
path spelling separately from portable collision checks. Missing runtime
dependencies now produce `required_system_entry_missing` before a package is
written and when an already built ZIP is validated. The generated installed
`.gitignore` mapping and source-only exclusions are preserved. This checks
required inventory; comparison with a particular frozen source's bytes remains
a separate integrity check, and `install-check` retains its completeness role.

## Current evidence in Inspector

The default Home and Trust outcomes now use live task evidence as well as the
saved global reports. Collection exposes snapshot completeness, pointer
consistency, live-input matching, required-source/continuation completeness and
readiness. Incomplete non-archived task evidence shows a recheck outcome and a
copyable task-list command; users can inspect and rebuild the affected snapshots.
A persisted pointer may still say `current` while live inputs have changed. A
limitation of the estimator alone does not mark valid evidence stale. The audit
exercised the actual collector, renderer and written HTML/JSON with local
fixtures, including escaping; it did not run a browser engine or live actions.

## Atomic JSON retries and Git hook paths

Contained JSON writes and NDJSON append now recheck the original root, parent
and temporary-file identities before every bounded rename attempt. Temporary
cleanup uses that same ownership guard. Replacing a parent during a retry can
no longer redirect a later attempt into the tested successor namespace, nor can
cleanup unlink its temporary entry. A displaced owned temporary file can remain
for diagnosis when the namespace no longer belongs to the original operation;
primary and cleanup errors are retained. These guards do not provide an atomic
filesystem transaction, a CAS contract for the destination's contents, or a
universal check-to-rename race guarantee.

Git hook changed-path collection now disables rename detection in its NUL-delimited
name-only diffs. This reports both old and new paths, including whitespace and
POSIX newline/tab characters, instead of losing the old rename path. The root
checkout branch is covered too. This fixes payload completeness; it does not
establish a past loss of tracked deletion history, because sync already scans
all tracked paths. Tests of the hook transport use a bounded capture-only sync
child; separate public tests exercise actual sync.

## Stable identities during ingest

Ingest allocates module IDs using exact source-path identity and a deterministic
collision loop. It reserves existing IDs and card names before allocating new
ones, preserves manual path-to-ID/card associations on reingest, and does not
adopt an unregistered existing card. Distinct source folders with the same
normalised basename remain separate modules. Ambiguous existing registry
identities are refused with `ingest_module_identity_invalid` before content
writes instead of being silently merged. The registry is checked again under
the ingest lock. The directory map uses the actual assigned IDs; a parent whose
children were promoted records `module_id: null` and its concrete `module_ids`.
This is not automatic migration of an already ambiguous registry.

## Pinecone command consent and metrics inventory

Pinecone's shared command entry point parses consent flags as boolean scalars.
Explicit false consent and an explicit dry run override ambient test-mode
permission. Without a positive dry-run veto, malformed consent values are
refused with `pinecone_live_flag_invalid`; the dry-run veto already prevents
dispatch. Setting `--dry-run=false` alone grants no live
permission. Provider mode, host and credentials remain separate admission
conditions. Tests execute remember, recall and source sync through an inert
transport spy: they establish local admission behavior, not remote service
availability. The legacy external CLI retains its separately documented dispatch
contract.

Metrics now counts unique regular-file paths. A regular-file alias inside its
own inventory root is deduplicated; directory, dangling and outside-root aliases
are excluded with explicit diagnostics. Cross-role aliases are excluded from the
referring root while the real files are counted in their selected root. The JSON
and Markdown reports disclose incomplete inventory. Existing root-overlap
accounting and the refusal to claim measured token savings remain intact.
Inventory walking is not an atomic snapshot of a changing filesystem and does
not promise hardlink deduplication. Generated execution graphs remain static
workflow descriptions rather than execution evidence.

## Doctor, ownerless locks and continuation limits

Doctor's selected-state/project lock diagnostics, operational readiness and
manual-review behavior were exercised with physical own-fixture layouts. Team
registry lock diagnostics are separately scoped. An ownerless lock is not
automatically safe to delete. Identity changes, uncertain ownership and failed
cleanup retain evidence and typed diagnostics.

The historical second lock creator and the separate historical Field Report
timeout remain unknown without the original event/process evidence. New
reproductions establish the behavior of these exact bytes; they do not identify
an old process or retroactively explain an unrelated timeout.

Further host validation must cover Windows Job Object execution/teardown,
numeric-ID native production, Windows paths/launchers and the final changed
runtime. Live Mem0/Pinecone/publication tests require their explicitly configured
services; local adapters and transport doubles are labelled as such in the
scenario results. No full release gate, external publication or CI deployment
was performed by this audit.
