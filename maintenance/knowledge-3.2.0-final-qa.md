# .knowledge 3.2.0 Final QA

Generated: 2026-06-16T09:55:00.000Z

Status: pass for the free `.knowledge` 3.2.0 release package and private-preview License API scaffold.

Scope note: adjacent paid `pro2pilot-inspector` app QA is intentionally deferred because the user explicitly said not to touch or release the paid Pro Inspector. Only its boundary metadata was read: package `pro2pilot-inspector`, version `0.1.0`, `private: true`.

## 1. What Was Checked

- Free core: routing, evidence/trust/freshness, repair queue, PR Impact, PR summary, JSON CLI outputs, memory-provider advisory status, embedding/API contracts, debug bundle, Pro snapshot.
- Free Inspector: local server on `127.0.0.1`, session token, API auth, canonical tabs, allowlisted actions, action lifecycle, run fetch/stream fallback, logs, secret redaction, first-run settings.
- Agent workflows: start, heartbeat, report, finish, active sessions derived from registry, events, footer compact/full.
- Multi-agent workflows: Safe Queue, Manual Only merge default, locks, stale lock cleanup, parallel worktrees, dirty/staged generated runtime warnings, branch mismatch, workspace archive, team Inspector JSON.
- Restore Trust: safe mode, generated report refresh, stale/repair/routing/search refresh, source hash preservation, no branch merge, no trust raise without evidence.
- Free/Pro split: no pricing in free Inspector, Pro action gated, paid manifest valid, Pro schemas present, free artifact excludes paid app/runtime/secret material.
- License API scaffold: Worker routes, D1 schema, Stripe webhook mock, R2 manifest mock, admin endpoint mock, activation/deactivation/validation/offline grace/expired/revoked/error states.
- Edge cases: clean repo, dirty repo, corrupt JSON, missing/unavailable memory providers, invalid token, no browser/API-only Inspector run, Windows paths, paths with spaces/Cyrillic.

## 2. Simulated Scenarios

- Temporary clean git repo and dirty repo diff.
- Corrupt JSON runtime artifact.
- Secret-bearing fixture report to verify redaction.
- Unavailable/unconfigured Mem0/Pinecone providers.
- Invalid Inspector token and free-mode Pro action without entitlement.
- No-browser Inspector run through local API only.
- Multi-worktree team run with stale lock, duplicate agent warning, branch mismatch and staged generated runtime file.
- License API mock activation, deactivation, validation, offline grace, expired grace, expired license, revoked license, invalid Stripe signature and admin auth failure.

## 3. Commands Run

| Command | Result |
|---|---|
| `node .knowledge/tools/build-routing-bundle.js` at outer workspace | pass |
| `node .knowledge/tools/doctor.js` at outer workspace | degraded, historical root issues only |
| `node .knowledge/tools/evaluation-harness.js` at outer workspace | pass, score 100 |
| `node tools/self-test-canonical-e2e.js --json` | pass |
| `node tools/self-test-restore-trust.js --json` | pass |
| `node tools/self-test-inspector-actions.js --json` | pass |
| `node tools/self-test-inspector-ui.js --json` | pass |
| `node tools/self-test-team-mode.js` | pass |
| `node tools/release-gate.js --json` | pass, 20/20, clean install pass |
| `node benchmarks/run-benchmarks.js --suite smoke --json` | pass |
| `node tools/validate-release-artifact.js dist/knowledge-v3.2.0.zip --json` | pass, 0 violations |
| `node tools/self-test-pro-ready-gates.js --json` | pass |
| `node tools/validate-paid-manifest.js --json` | pass |
| `npm.cmd run lint` in `../pro2pilot-license-api` | pass |
| `npm.cmd run test` in `../pro2pilot-license-api` | pass |
| `npm.cmd run build` in `../pro2pilot-license-api` | pass |

## 4. Pass / Fail Results

- Free package release gate: passed, `gate_status: benchmark-ready`, 20 steps, 0 failures, clean install smoke passed.
- Package doctor after fixes: healthy, 100/100, 0 issues, secret scan clean.
- Release artifact: `dist/knowledge-v3.2.0.zip`, 318 entries, 0 violations.
- Benchmark smoke: passed, run `benchmark-runs/2026-06-16T09-53-06-914Z-smoke`.
- License API: lint/test/build passed.
- Outer workspace `.knowledge` doctor: degraded due historical missing `.knowledge-kit-3.0.zip`/tracked file and suspect old modules; not a blocker for `knowledge-3.2.0` package evidence.

## 5. Bugs And Regressions Found

- `doctor.safeJson()` swallowed corrupt JSON because it used `readJson(abs, null)`. Fixed by parsing JSON directly so `json_parse` fails on invalid JSON.
- Secret scan included `.qa-tmp` / `.self-test-tmp` QA output and reported stale temp copied test content. Fixed scanner skip dirs for QA runtime temp.
- License API tests only checked D1 table names. Fixed by adding Worker-level mock route tests.
- Restore Trust coverage was mostly static. Fixed by adding canonical E2E source-hash verification.

## 6. Security Issues

- Current package secret scan is clean: 0 findings.
- Inspector binds to `127.0.0.1`, uses per-session token and rejects invalid token.
- Action stdout/stderr logs redact secret-like tokens and local developer paths.
- Free Inspector generated UI has no external scripts/styles/images in UI self-test.
- License API admin route requires bearer token and production activation stays `preview_only` unless explicit mock env is enabled.

## 7. Free / Pro Boundary Issues

- No blocking issue found in free package boundary.
- Pro-only Inspector action is gated without entitlement.
- Free Inspector shows Pro Preview but no prices.
- Free artifact validation has 0 violations and excludes runtime/pro/secret material.
- Paid `pro2pilot-inspector` full app QA remains deferred by user instruction.

## 8. UX Issues

- Codex Browser plugin / `node_repl` failed in this desktop session before executing browser JS, so visual in-app browser switching was not available through the plugin. Workaround used local URL handler and API/DOM checks.
- `flow release` metrics currently reported negative token savings in one summary; not a gate failure, but the metric copy should be reviewed before marketing claims.
- Outer workspace root still has old degraded `.knowledge` trust state, which can confuse routing summaries outside the package.

## 9. Missing Tests Remaining

- Full paid `pro2pilot-inspector` app QA is intentionally not run.
- Full `benchmarks --suite all` is not run because KB-13 writes into the paid Pro Inspector area.
- No real Stripe signature cryptographic verification or real D1/R2 integration test; License API is private-preview mock/scaffold only.
- No real browser screenshot proof due Browser plugin failure; live Inspector API and DOM checks passed.

## 10. What Was Fixed

- Added `tools/self-test-canonical-e2e.js`.
- Added canonical E2E to `package.json`, release gate and release-gates docs.
- Fixed invalid JSON detection in `tools/doctor.js`.
- Fixed secret scanning of QA temp output in `tools/scan-secrets.js`.
- Expanded `pro2pilot-license-api/src/worker.js` preview mock routes.
- Expanded `pro2pilot-license-api/scripts/test.mjs` and `scripts/build.mjs`.
- Updated canonical compliance/gap docs to include canonical E2E evidence.

## 11. What Remains

- Decide separately when to QA/release paid `pro2pilot-inspector`.
- If marketing/public claims need “full benchmark suite”, run all non-paid suites or explicitly exclude KB-13 with rationale.
- Investigate the desktop Browser plugin runtime asset error outside this codebase if visual in-app verification is required.
- Clean or regenerate the outer workspace `.knowledge` layer if it should represent the new `knowledge-3.2.0` package.

## 12. Release-Ready Decision

Scoped decision: yes, the free `.knowledge` 3.2.0 package and private-preview License API scaffold are release-ready for the local/free release scope tested here.

Not release-ready: the adjacent paid `pro2pilot-inspector` app itself is not certified by this pass because QA was explicitly deferred.
