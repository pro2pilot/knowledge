# Marketing Proof Pack

Run: 2026-06-08T14-16-07-684Z-kb-13

Verdict: passed

This pack only promotes suites with `measured` or `measured-on-fixture` claim status. Preview, planned, diagnostic and failed suites are included only as limitations.

## Approved public claims

- KB-13 Pro Inspector Governance: pro_score=94. Evidence: `../pro2pilot-inspector/scripts/pro-inspector-qa-gate.js`.

## Not approved

- None.

## Reproduce

```sh
node .knowledge/benchmarks/run-benchmarks.js --suite KB-13 --runs 3 --json
node .knowledge/benchmarks/generate-marketing-pack.js --latest --json
```
