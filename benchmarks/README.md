# Maintainer benchmark surface

This directory is source-only. It is not included in the installed `.knowledge`
artifact. Benchmark evidence must use fixed tasks, an external oracle, separate
baseline/assisted runs, raw command traces, and claim-safe reporting. Local
context estimates are not provider-reported model-token usage.

`run-benchmarks.js` exposes the strict GATE-00 release-envelope adapter used by
source regression tests. Comparative study tooling and raw results belong in a
separate evidence workspace, not in installed project repositories.
