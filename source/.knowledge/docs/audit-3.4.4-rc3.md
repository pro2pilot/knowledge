# Knowledge 3.4.4 RC3: audit corrections and limits

This page documents the corrections introduced in the RC3 audit baseline.
The current candidate is RC5; see [upgrade notes](upgrade-3.4.4.md) for its
identity and [release notes](../RELEASE_NOTES.md) for subsequent changes.
The historical RC3 archive was `knowledge-v3.4.4-step1-rc3.zip`. A local audit is not the maintainer
release gate or a cross-platform release matrix. Use the separately supplied
audit handoff for exact source/archive hashes, commands and final results.

## Doctor, ownership and readiness

Doctor and sync now use the same validated union of registry and curated module
card declarations. Generated freshness labels cannot replace the declared
source owner. Repository-relative shadow cards cannot replace a card from the
configured curated root. Missing direct dependency targets are diagnosed.
A typed file scope covers only that exact file; directory containment uses the
declared directory boundary.

Doctor publishes stale-items and repair-queue as a pair with exact read guards,
so a concurrent change is rejected instead of silently overwritten. Sync keeps
previously reported ignored-card cleanup debt visible while the preserved card
still physically exists. This queue transaction does not make every derived
sync output atomic.

Readiness uses only finite, non-negative remediation costs, with the existing
severity fallback for missing or invalid values. Malformed scope/cohort inputs
produce an unavailable comparison. An unproven raw `repaired` status does not
count as a verified closure. A before/after comparison remains bound to one
frozen cohort; new debt remains a separate result.

## Currency and native verification evidence

Local lifecycle drift in one factual unit no longer revokes independent valid
units. Failed final physical reads clear validity and coverage. Recovery checks
the expected finish binding before effects and independently derives all
receipt, index and operation bytes; agreement between attacker-controlled
payloads and their own hashes is insufficient. A valid interruption directly
after the initial manifest can be recovered through the same checked plan.
Cached committed results are reconstructed and checked against their native
receipt identity instead of trusting stored safety fields.

Currency, native execution and recording inputs share bounded inert-data
admission. It rejects accessors, cycles, unsupported prototypes and oversized
data before invoking writers. Native KVE reading rejects hardlinks and verifies
the opened file and parent identity around the bounded read. The pure admission
helper and native schema are included in currency authority pins.

These checks constrain evidence; they do not grant new coverage. Older local
receipts can become invalid when their authority pins no longer match. No
automatic receipt migration, deletion, reissuance or raw lifecycle closure is
performed. Factual currency still does not certify application security or
close application risks. See [Factual currency](factual-currency.md).

## Recording and child actions

Public recording lists and notices use an explicit masked field projection.
Unexpected stored fields and unmasked previews are not copied to public output.
Malformed currency JSON errors do not echo fragments of the supplied file.
Listing a registry does not rewrite its bytes or broaden an override's authority.

Inspector, Restore Trust, updater and agent-task workflow use the shared bounded
child JSON capture limit. Process success requires exit zero without a spawn
error or signal. JSON-required steps reject empty or malformed output. Restore
Trust also checks the semantics of its declared JSON steps; text steps remain
text. Native verification cannot issue successful execution authority from a
failed child transport. Doctor's Inspector action is correctly classified as a
local write because it creates reports and maintenance projections.

Inspector and Restore Trust validate contained, regular, singly linked evidence
destinations before starting child actions and check them again before writing.
Inspector serializes only the short daily journal append, preserving concurrent
entries without holding the lock throughout a child process. These are bounded
application checks, not a claim of arbitrary operating-system race immunity.

## System update preservation

Pre-apply preservation remains an exact set and byte check. Post-check tools
can legitimately create new sync/Doctor queue journals. The updater accepts
those additions only under `validated_queue_journal_append_only.v1`, with all
of the following verified:

- A new transaction directory, absent even as an empty directory in the backup.
- A canonical committed transaction, terminal markers, valid staged/backup
  hashes, exactly two queue outputs and exact guards for their preimages.
- The current trusted knowledge root and independently derived queue paths.
- The exact internal file set, without extra files or unrelated receipts.
- Unchanged bytes for every prior protected file and every appended file pinned
  by the earlier successful apply proof.

Approved additions still appear in the report: `hash_set_unchanged` is false
when files were added, while `history_unchanged` can remain true. Any old-file
change, removal, unapproved addition or changed prior appended pin fails.
Mandatory fallback protection includes factual currency and recording state,
even when optional manifest arrays are empty.

`verify-upgrade` validates later unpinned journals on each invocation; it does
not persist a new checkpoint for all of them. Do not infer detection of a
self-consistent rewrite of a later journal that has never been byte-pinned by
a successful apply proof. Legacy exact-set reconstruction remains strict.

## Regression and handoff boundaries

The source handoff includes negative and positive regression cases for these
changes. The runtime archive includes the supported public self-test programs;
private audit tests and maintainer packaging tools remain source-only. The audit
runner uses isolated repositories, offline fixture settings and raw execution
receipts. Explicit child transport fault tuples are labelled synthetic; actual
child execution controls are recorded separately.

The RC2 baseline also contained an intermittent team-mode negative-case failure
and a repeated-update failure with an ownerless `sync.lock` directory. A later
passing run alone does not establish their cause or closure. Retained evidence
and current triage status belong in the audit handoff. Six historical source
pins referenced by a supplied continuity record were absent from the input
handoff; their bytes were not reconstructed by inference.

Live external providers, arbitrary agent host behavior, Windows/macOS execution,
production upgrades, publication and the full maintainer release gate are
outside this local run. See [upgrade notes](upgrade-3.4.4.md) before testing an
existing installation.
