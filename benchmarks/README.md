# .knowledge Competitive Benchmark Harness

This harness runs local, reproducible benchmark suites for `.knowledge 3.2.4`.

It is intentionally claim-safe:

- no benchmark runs before the release/QA gate;
- failed or preview features are marked as `failed`, `diagnostic`, `preview`, or `planned`;
- only `measured` and `measured-on-fixture` claims are allowed in public copy;
- raw reports stay local by default.

## Commands

```bash
node .knowledge/benchmarks/run-benchmarks.js --suite smoke --json
node .knowledge/benchmarks/run-benchmarks.js --suite kb-02-routing --runs 5 --json
node .knowledge/benchmarks/run-benchmarks.js --suite kb-03-trust-freshness --runs 5 --json
node .knowledge/benchmarks/run-benchmarks.js --suite kb-04-repair-queue --runs 5 --json
node .knowledge/benchmarks/run-benchmarks.js --suite kb-09-pr-impact --runs 5 --json
node .knowledge/benchmarks/run-benchmarks.js --suite kb-11-memory-providers --runs 5 --json
node .knowledge/benchmarks/run-benchmarks.js --suite kb-12-team-mode --runs 10 --json
node .knowledge/benchmarks/run-benchmarks.js --suite kb-14-no-cloud --runs 5 --json
node .knowledge/benchmarks/run-benchmarks.js --suite all --fixture all --runs 5 --json
```

In source checkout, omit the `.knowledge/` prefix.
