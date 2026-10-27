# 3.4.4 RC5 reliability audit status

This page describes the current unpublished candidate. Package version remains
`3.4.4`, candidate status remains `RC5`, and audit revision is
`independent-audit.20261027.reliability.4`. This candidate is not published, has
not passed the full release gate, and is not certified for general release.

## Historical evidence baseline

The previous reliability evidence baseline contained 675 product-source files
and is identified by SHA-256
`bea4ec0c914990e546d84883ee429eee97b7fd5d2148eaf58407b8b8ed849229`.
Its source commit was
[`5bed133f860d2d5e2ae395287d47c065c410f605`](https://github.com/pro2pilot/knowledge/commit/5bed133f860d2d5e2ae395287d47c065c410f605).
Scoped workflow evidence is available from [CI06](https://github.com/pro2pilot/knowledge/actions/runs/40463689764),
[QA07](https://github.com/pro2pilot/knowledge/actions/runs/40464641016), and
[QA08](https://github.com/pro2pilot/knowledge/actions/runs/40465272797). Each
result applies only to that pinned historical source and test cohort. These
receipts do not qualify the current `.4` source; historical failures remain
preserved and a later scoped pass does not erase them.

The prior diagnostic build was named
`NOT-QUALIFIED-knowledge-v3.4.4.zip` (SHA-256
`5ea2cd56e2bad85fc68b2b144af8c5264837bd5b02664fbeba398966738a5f7a`). It is a
baseline archive, not the current `.4` candidate or a release asset. Its digest
does not identify the new package. The exact `.4` source/package pins will be
recorded after the docs-integrated candidate is rebuilt and verified. Complete
post-ZIP runtime qualification has not run; `release_gate_qualified=false` and
`release_ready=false`.

## Platform state

- **Windows x64:** historical CI06 continuation passed on its pinned baseline.
  A fresh targeted current-source physical run on Windows x64 / Node 22.17.1
  passed 61 selected TAP cases plus 20 runtime-safety checks (81 selected checks
  across eight groups). The evidence correction only reinterpreted saved TAP; it
  did not rerun the physical tests. The original reducer marked the final holder
  group failed because it expected two skipped baseline tests; the saved TAP has
  the exact eight expected passes and no skips. This does not qualify ARM64 or
  the final installed ZIP.
- **Windows ARM64:** historical CI06 continuation passed on its pinned baseline.
  No fresh ARM64 qualification for `.4` is recorded here. Qualification of the
  final installed ZIP is still pending; historical workflow receipts above do
  not qualify `.4`.
  The Windows watcher smoke profile is setup 30 s, work 60 s, cleanup 15 s;
  startup allowance 60 s and caller-ready window 90 s. The default observation
  budget is `5 × setup + work + cleanup + debounce + 1 s` (227.5 s at the default
  1.5 s debounce). `KNOWLEDGE_SMOKE_WATCH_MS` remains an exact explicit override.
  This observation window does not assert a hard filesystem-I/O latency limit.
  Recorded measurements from one Windows run:

  | Measurement | Observed duration | Scope |
  |---|---:|---|
  | Watcher startup | 11.5–22.1 s | Startup observation only |
  | Sync after change | about 22.7 s | One sync cycle |
  | Full smoke | about 46.8 s | One complete smoke run |

  These measurements do not close installed-ZIP qualification and do not assert
  an I/O upper bound.
- **Linux x64:** historical pinned QA08 continuation passed on its named source
  snapshot; it is not current `.4` qualification.
- **Linux ARM64:** the hosted Ubuntu 24.04 runner denied the required nested PID
  namespace with `EPERM` under its active AppArmor policy. The policy was not
  weakened. A separate system broker with isolated-copy execution is the accepted
  design direction for restricted hosts, but its production implementation and
  qualification are not complete. Safe refusal is not a successful process-tree
  qualification; Linux ARM64 runtime qualification remains open.
- **macOS Intel and ARM64:** the production isolated-copy verification path is
  disabled by default. A request must explicitly set
  `native_execution.darwin.enabled=true` and `mode="isolated_copy"`, with broker
  paths and copy limits. Administrator installation of the broker and reserved
  private UID provisioning are separate tasks; broker availability alone does
  not opt a request in. Writable Flow/Team operations require separately
  provisioned workspace access and are not enabled by isolated-copy verification.
  Historical CI06/QA07/QA08 have distinct scoped basic, failure, physical,
  writable and sandbox results; they do not establish fresh full qualification
  for `.4` or all supported hosts. Physical runs were on GitHub-hosted machines.
  Stock-SIP behavior on a user's own Mac has not been verified.

## Team and historical uncertainty

The targeted macOS Team run passed seven physical cases and all eight shipping
steps. The Doctor result was 86/100 `usable_with_warnings`; two genuine medium
warnings were `suspect_module` and `low_confidence_module`. They do not promote
either module to trusted. The public projection and acceptance report are the
available evidence; the private Doctor raw report was not loaded in this review.
This scoped result is not stock-macOS/SIP qualification.

The historical second ownerless-lock cause remains **UNKNOWN**. Current replayed
or controlled mechanisms do not identify the original historical writer. Unknown
ownerless locks remain subject to evidence-based diagnosis; they are not
automatically deleted or adopted.

## Remaining gates

1. Complete fresh, source-bound qualification for the exact release candidate,
   including macOS platform requirements and a permitted Linux ARM64 host with the
   needed namespaces.
2. Preserve the current-source Windows core/native watcher PASS evidence, then
   complete qualification of the final installed ZIP without changing the
   documented budgets.
3. Rebuild the docs-integrated `.4` candidate and record its new source/package
   pins; the 675-file/5ea2 baseline pins above are historical inputs.
4. Check its exact archive name, `.knowledge/` root, versions and public
   documents, then run the full release gate and complete post-ZIP runtime
   qualification.

The earlier operational audit and its timeout/lock discussion are preserved in
[the historical 2026-10-19 audit](historical/audit-3.4.4-rc5-operational-20261019.md).
Its statements describe that source snapshot, not revision `.4`.

Do not transfer scoped PASS results to different bytes, label the candidate as
released, or infer a performance guarantee from a smoke observation budget.
