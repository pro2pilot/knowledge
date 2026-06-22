# Release Gate Report

Generated: 2026-06-21T11:10:21.218Z

Status: passed

## Commands

| Command | Status | Duration ms |
|---|---|---:|
| node.exe tools/self-test-inspector-launcher.js --json | pass | 357 |
| node.exe tools/self-test-inspector-actions.js --json | pass | 358 |
| node.exe tools/self-test-agent-activity.js --json | pass | 344 |
| node.exe tools/self-test-safe-queue.js --json | pass | 318 |
| node.exe tools/self-test-agent-footer.js --json | pass | 1384 |
| node.exe tools/self-test-restore-trust.js --json | pass | 54 |
| node.exe tools/self-test-canonical-e2e.js --json | pass | 21877 |
| node.exe tools/self-test-pro-ready-gates.js --json | pass | 59 |
| node.exe tools/self-test-install-policy.js | pass | 140428 |
| node.exe tools/self-test-memory-providers.js | pass | 1839 |
| node.exe tools/self-test-external-memory.js | pass | 1310 |
| node.exe tools/self-test-pr-impact.js | pass | 4943 |
| node.exe tools/self-test-team-mode.js | pass | 30669 |
| node.exe tools/self-test-team-inspector-json.js | pass | 26268 |
| node.exe tools/build-visual-inspector.js | pass | 565 |
| node.exe tools/self-test-inspector-ui.js | pass | 7858 |
| node.exe tools/flow.js release --no-color --json | pass | 23895 |
| node.exe tools/doctor.js --json | pass | 1912 |
| node.exe tools/package-release.js | pass | 295 |
| node.exe tools/validate-release-artifact.js dist/knowledge-v3.2.0.zip --json | pass | 49 |

## Clean Install Smoke

Status: pass

| Step | Status | Duration ms |
|---|---|---:|
| git init | pass | 47 |
| git config email | pass | 41 |
| git config name | pass | 36 |
| git add fixture | pass | 616 |
| git commit fixture | pass | 291 |
| install-check | pass | 76 |
| flow import | pass | 10883 |
| doctor | pass | 1295 |
| build Inspector | pass | 558 |
| self-test Inspector UI | pass | 7539 |
| self-test Team Mode | pass | 28221 |
| memory status all | pass | 550 |
