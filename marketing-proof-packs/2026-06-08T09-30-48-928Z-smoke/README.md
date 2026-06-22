# Marketing Proof Pack

Run: 2026-06-08T09-30-48-928Z-smoke

Verdict: passed

This pack only promotes suites with `measured` or `measured-on-fixture` claim status. Preview, planned, diagnostic and failed suites are included only as limitations.

## Approved public claims

- No public claims are approved from this run.

## Not approved

- SMOKE Harness smoke: diagnostic; needs more evidence.

## Reproduce

```sh
node .knowledge/benchmarks/run-benchmarks.js --suite smoke --runs 1 --json
node .knowledge/benchmarks/generate-marketing-pack.js --latest --json
```
