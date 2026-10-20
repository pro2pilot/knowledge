> Historical artifact scope. For the current candidate, see [Windows watchdog continuation](audit-3.4.4-rc5-windows-watchdog.md).

> Historical Windows audit for `independent-audit.20261019.windows.1`.
> The current follow-up is `independent-audit.20261019.windows.1.followup.1`;
> see [its contract](audit-3.4.4-rc5-windows-followup.md). Results below retain the
> original F1/F2 source and Windows-host scope; they do not certify changed
> follow-up bytes on Windows.

# 3.4.4 RC5 — Windows reaudit candidate

Audit revision: `independent-audit.20261019.windows.1`.
Status: unpublished candidate for independent audit. The full release gate has
not been run. Version `3.4.4`, label `RC5` and archive `knowledge-v3.4.4.zip`
remain unchanged; identify this candidate by revision and the handoff SHA-256.

## Provenance and fixes

This source continues the preserved RC5 branch at
`e1d08d245925d2409ab3acee2fbe3c6506083281`. The October 19 input audit was
integrated with exact byte parity to its 445-file source before further edits.
Its 398-file runtime SHA-256 is
`c8069180849cd4abe40dfd1ceb4ed4379e4f4112650adf488528154d971857d7`.
The handoff records the new source manifest, patch, runtime and test controllers.

This continuation adds:

- Canonical release validation refuses a regular file that is also a parent
  directory of another entry, regardless of archive order or Windows case alias.
- The standalone ZIP helper rejects non-NFC names and additional reserved
  Windows device names before changing an existing destination.
- Worktree Status selects the repository/workspace composite key, including
  explicit `--repo-id`, when several repositories share a workspace ID.
- The Windows Inspector launcher quotes the complete script path. Spaces,
  Unicode and shell metacharacters remain part of one argument. `-NoDialog`
  reports launch errors on stderr with exit 1 for unattended checks; ordinary
  desktop use retains the error dialog. It does not select another project.
- A native Doctor repair regression reopens the same lifecycle finding after
  a new source change, increments its occurrence and preserves the old KVR
  without granting it authority over the new bytes.

The [mechanism audit](audit-3.4.4-rc5-mechanisms.md) describes the integrated
KVE/KVF physical read-set guards, TFR v2 bindings, watcher ownership and bounded
aggregate rebasing. Completed valid TFR v1 remains `legacy_v1`; incomplete or
invalid attempts do not inherit a prior success. The historical creator of the
second ownerless lock is still unknown. Do not delete or adopt an unowned lock
from the pathname alone.

## Evidence and supported boundaries

Source suites, installed-ZIP workflows, controlled fault probes and historical
Linux results are separate evidence sets. The accompanying audit report gives
exact argv, hashes, raw outcomes and any partial/deferred scenarios. Counts in
older documents certify only the original bytes; they are not this candidate's
Windows results. A transport spy is not a live provider call.

Windows native verification uses an assigned Job Object before admitting
commands. Accepted KVE v2 batches require confirmed zero active processes, KVF
readback and a signed public-parent acknowledgement within the total budget.
Preserve `verification_acceptances` alongside KVE/KVF IDs. A persisted KVF by
itself, including one written before parent interruption, cannot authorize
closure or currency issuance. Older KVE remains readable as legacy evidence.

`timeout_ms` bounds admission and acceptance of the complete native batch,
including preparation, commands, receipts and teardown. Expired work cannot
be accepted. Synchronous I/O or an unscheduled OS process can delay error return;
this is not a hard real-time wall-clock return guarantee. Controlled stalls are
reported with measured elapsed time and the absence of acceptance.

Native verification remains unavailable on Linux/macOS and refuses before
probes. This Windows continuation does not restore that backend or claim a new
POSIX host run. Live Mem0/Pinecone service availability, publication and the full
release gate are not certified by these local checks.

## Candidate installation

Use `candidate/knowledge-v3.4.4.zip` from this handoff and verify its checksum.
Extract exactly one `.knowledge/` root. Follow [INSTALL](../INSTALL.md) and
[Quick Start](../Quick-Start.md); preserve project state during updates. A shared
version number alone cannot detect a different audit revision.

The unattended Windows launcher command is:

```powershell
powershell.exe -NoProfile -NonInteractive -File .knowledge/tools/open-inspector.ps1 -KnowledgeRoot .knowledge -NoDialog
```

For Windows shortcut testing, pass an explicit `-ShortcutPath` inside the test
project to `tools/create-inspector-shortcut.ps1`. Do not use the default Desktop
destination in an automated fixture.
