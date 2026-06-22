# 12 — QA, benchmark and release gates

## Rule

No public claim without local evidence.

No `10/10` unless all relevant gates pass in source checkout and clean install.

## Core release gate

```bash
node tools/self-test-install-policy.js
node tools/self-test-memory-providers.js
node tools/self-test-external-memory.js
node tools/self-test-pr-impact.js
node tools/self-test-team-mode.js
node tools/self-test-team-inspector-json.js
node tools/build-visual-inspector.js
node tools/self-test-inspector-ui.js
node tools/flow.js release --no-color --json
node tools/doctor.js --json
node tools/package-release.js
node tools/validate-release-artifact.js dist/knowledge-v3.2.0.zip --json
```

## Clean install gate

```bash
git init
unzip dist/knowledge-v3.2.0.zip
node .knowledge/tools/install-check.js --json
node .knowledge/tools/flow.js import --no-color --json
node .knowledge/tools/doctor.js --json
node .knowledge/tools/build-visual-inspector.js
node .knowledge/tools/self-test-inspector-ui.js
node .knowledge/tools/self-test-team-mode.js
```

## Benchmark suites

| Suite | Purpose |
|---|---|
| QA-00 | Release gate before benchmarks. |
| KB-01 | Install health. |
| KB-02 | First-read routing vs raw repo/packers. |
| KB-03 | Trust/freshness calibration. |
| KB-04 | Repair queue actionability. |
| KB-05 | Stale/critical files. |
| KB-06 | Wiki graph. |
| KB-07 | Local search. |
| KB-08 | Inspector UX. |
| KB-09 | PR Impact. |
| KB-10 | Cross-agent handoff. |
| KB-11 | Memory provider governance. |
| KB-12 | Team Mode / multi-worktree. |
| KB-13 | Pro Inspector governance. |
| KB-14 | No-cloud/privacy. |
| KB-15 | Performance/scale. |
| KB-16 | Competitive proof matrix. |

## Claim statuses

```txt
measured
measured-on-fixture
preview
planned
blocked
```

Only `measured` and `measured-on-fixture` may be used as public proof.

## Report structure

Every run must write:

```txt
benchmark-runs/<run_id>/
  00_EXECUTIVE_SUMMARY.md
  01_CLAIM_EVIDENCE_MAP.md
  02_SCORECARD.md
  03_TECHNICAL_REPORT.md
  04_LIMITATIONS.md
  05_REPRODUCTION.md
  06_MARKETING_PACK.md
  raw/
  metrics/
  artifacts/
  screenshots/
  verification/
  marketing/
```

Top of report:

```txt
headline result
status
proof table
limitations
safe public wording
```

Details below:

```txt
setup
fixtures
commands
raw metrics
logs
reproduction
failures
```

## Forbidden claims

```txt
eliminates hallucinations
guarantees safe PRs
zero-risk agent work
always faster
enterprise-ready without enterprise evidence
replaces Cursor/Sourcegraph/Devin
```
