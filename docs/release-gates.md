# Release Gates

No public claim is allowed without local evidence.

Canonical gate:

```bash
node tools/release-gate.js --json
node tools/self-test-inspector-launcher.js --json
node tools/self-test-inspector-actions.js --json
node tools/self-test-agent-activity.js --json
node tools/self-test-safe-queue.js --json
node tools/self-test-agent-footer.js --json
node tools/self-test-restore-trust.js --json
node tools/self-test-memory-providers.js
node tools/self-test-external-memory.js
node tools/self-test-free-core-graph.js
node tools/self-test-pr-impact.js
node tools/self-test-team-mode.js
node tools/self-test-team-inspector-json.js
node tools/self-test-inspector-ui.js
node tools/flow.js release --no-color --json
node tools/package-release.js
node tools/validate-release-artifact.js dist/knowledge-v3.2.2.zip --json
```

Clean install smoke from `dist/knowledge-v3.2.2.zip` must pass before marking the release available.
