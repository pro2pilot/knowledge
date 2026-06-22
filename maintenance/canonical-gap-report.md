# Canonical Gap Report

Generated for the canonical free/pro implementation pass.

## Resolved In This Pass

- Added the one-file free launcher: `node .knowledge/inspector.js`.
- Replaced the old top-level `Command Center`/`Metrics` Inspector model with canonical navigation: `Home`, `Review`, `Knowledge Trust`, `Agents Activity`, `Reports`, `Settings`, `Pro Preview`.
- Added token-protected local action API and allowlisted action registry/runner.
- Added Agent Registry / Active Sessions tooling via `tools/agent-session.js`.
- Added Safe Queue / Manual Only defaults for repo mode and team mode.
- Added safe Restore Trust entrypoint via `tools/restore-trust.js`.
- Added Simple/Advanced settings and `tools/agent-footer.js`.
- Added live first-run Inspector onboarding wizard with token-protected settings save.
- Added Pro-ready schemas and free-mode feature gates without embedding closed Pro code.
- Added Cloudflare-first License API scaffold under `../pro2pilot-license-api`.
- Added canonical self-tests and release-gate coverage.

## Deferred By User Boundary

- `../pro2pilot-inspector` paid Inspector QA is intentionally not run in this pass. The user explicitly asked not to touch that paid version while preparing the free Inspector release.
- `KB-13 Pro Inspector Governance` full benchmark is therefore not run, because it invokes scripts inside `../pro2pilot-inspector` and writes Pro QA proof outputs.

Safe evidence still collected:

- `tools/self-test-pro-ready-gates.js` checks free core version `3.2.0`.
- The same self-test checks adjacent Pro Inspector version `0.1.0` when present.
- Free artifact validation excludes `pro2pilot-inspector` and closed Pro implementation code.

## QA Gate Devised From Canon

The free/core/license-api pass is not complete until these pass:

```bash
node tools/release-gate.js --json
node tools/self-test-inspector-launcher.js --json
node tools/self-test-inspector-actions.js --json
node tools/self-test-agent-activity.js --json
node tools/self-test-safe-queue.js --json
node tools/self-test-agent-footer.js --json
node tools/self-test-restore-trust.js --json
node tools/self-test-canonical-e2e.js --json
node tools/self-test-pro-ready-gates.js --json
node tools/self-test-memory-providers.js
node tools/self-test-external-memory.js
node tools/self-test-pr-impact.js
node tools/self-test-team-mode.js
node tools/self-test-team-inspector-json.js
node tools/self-test-inspector-ui.js --json
node tools/flow.js release --no-color --json
node tools/package-release.js
node tools/validate-release-artifact.js dist/knowledge-v3.2.0.zip --json
node benchmarks/run-benchmarks.js --suite smoke --json
```

Clean install smoke from `dist/knowledge-v3.2.0.zip` is covered by `node tools/release-gate.js --json`.

License API scaffold gate:

```bash
npm.cmd run lint
npm.cmd run test
npm.cmd run build
```
