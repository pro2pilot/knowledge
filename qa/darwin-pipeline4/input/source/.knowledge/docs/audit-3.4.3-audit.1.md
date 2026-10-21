# Knowledge 3.4.3 audit background

This document records the audit corrections incorporated into Knowledge 3.4.3.
The audit began with an install artifact and its handoff, then the fixes were
integrated into the maintainer source before release certification. This is a
technical overview; release evidence is tied to the exact published artifact.

## Doctor and trust recovery

- A scan observes current bytes; it cannot certify a changed source. Repeating
  sync preserves unresolved source drift instead of restoring trusted status.
- File-fact coverage requires the current `evidence.source_sha256`. Legacy facts
  with no hash, or only a top-level `sha256`, do not silently certify current
  source. Refresh the fact register through a real, scoped verification.
- Doctor verifies physical tracked files, reports hash drift, preserves damaged
  queue evidence, and distinguishes curated project data from runtime state.
  A same-named file inside `.knowledge` cannot replace a missing project source.
- Successful execution requires stable declared source inputs across the run.
  Tests that edit those inputs or themselves do not create valid passing
  evidence for the resulting bytes. Only exact outputs of supported first-party
  generated rebuilds have a bounded exception; producer inputs remain pinned.
- Closure validation checks the committed transaction, lifecycle occurrence and
  curated module claims. Keeping a receipt reference while editing those claims
  does not preserve certification. Existing receipts that fail the stronger
  validation require a new verification, rather than metadata repair by hand.
- Sequential verification batches use the sum of their effective test budgets.
  Restore Trust and Inspector actions execute the selected system runtime while
  preserving the explicit target/project/state roots.

## Local tools and data preservation

The audit also adds regression coverage for updater path containment and
preservation of local configuration, extension authentication and entitlement
state, template file ownership, Unicode search and Git paths, concurrent session
and team registry updates, local memory record corruption, and Inspector/watch
runtime behavior. Consult the detailed handoff for each reproduced defect and
its exact regression; this document does not substitute for execution evidence.

Workspace/session identifiers must be safe single path segments. Traversal,
control characters, Windows device aliases and trailing dot/space aliases are
rejected instead of silently normalized. Ordinary Unicode identifiers remain
supported. When the same workspace ID exists in multiple repositories, specify
`--repo-id` when unregistering it; ambiguous selection fails without changing
workspace records.

Pinecone source collection uses the selected project context. Configured sources
must remain inside that project and must not use symbolic links or hardlinks.
Corrupt source configuration is reported instead of replaced with an empty
fallback. External memory remains advisory and does not establish source trust.

Secret scanning examines every occurrence of a pattern, so a placeholder cannot
hide later matches in the same file. Strict rejection still returns nonzero, but
releases its owned lock before exiting. Reports contain masked findings.

## Reproduce the local checks

The accompanying handoff includes a portable Python replay runner. It extracts
the exact candidate ZIP, discovers every shipped `self-test-*.js`, and runs them
in independent copies with recorded commands, exits, durations and raw output.
The install manifest's public self-test allowlist and package script aliases are
kept in sync with the shipped tests.

For a focused installed-runtime check, run for example:

```sh
node .knowledge/tools/install-check.js --json
node .knowledge/tools/self-test-doctor-audit.js
node .knowledge/tools/self-test-repair-audit.js
node .knowledge/tools/self-test-root-boundaries.js
node .knowledge/tools/self-test-team-registry-concurrency.js
node .knowledge/tools/self-test-scan-memory-boundaries.js
```

Use an existing writable temporary directory for `TMPDIR`/`TEMP`/`TMP` in a
restricted execution environment. In the audit environment, invoking Node by
its absolute executable path was necessary for physical runtime hash evidence.
That environment adjustment is recorded separately from product changes.

## Runtime health and release certification

Install artifacts intentionally omit the maintainer source checkout, release
policy implementation, canonical release gate, packaging validator and
conformance tooling. A runtime test pass, Doctor score, safe repair receipt or
`flow release` result does not replace maintainer release certification.

The release checks distinguish Windows verification from the Linux/macOS
runtime matrix. Live Mem0 evidence comes from Windows; the runtime matrix does
not claim live provider coverage on every platform. External memory remains
optional and advisory.

Do not copy fixture state, synthetic credentials, locks or audit runtime evidence
into an installed project's curated data. See the release notes and upgrade
guide for the changes that apply to existing installations.
