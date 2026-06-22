# .knowledge 3.2.0 QA report

Generated: 2026-06-05

## Architecture summary

- Repo-local mode remains default.
- Team mode is explicit and uses `teamRoot`, `targetRoot`, `workspaceId`, and `agentId`.
- `systemRoot`, `targetRoot`, `projectKnowledgeRoot`, and `stateRoot` are resolved by `tools/lib/path-context.js`.
- Runtime state is separated into `stateRoot` in team mode.
- Team registry, workspaces, locks, and events live under `<teamRoot>/repos/<repoId>/`.
- Paid Inspector implementation is separate in `<paid-inspector-root>` and ignored by the free/core package.

## New env vars

- `KNOWLEDGE_MODE=repo|team`
- `KNOWLEDGE_SYSTEM_ROOT`
- `KNOWLEDGE_TEAM_ROOT`
- `KNOWLEDGE_TARGET_ROOT`
- `KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT`
- `KNOWLEDGE_STATE_ROOT`
- `KNOWLEDGE_WORKSPACE_ID`
- `KNOWLEDGE_AGENT_ID`

## New CLI flags

- `--team-root`
- `--target-root`
- `--workspace-id`
- `--agent-id`
- `--state-root`
- `--project-knowledge-root`
- `--exclusive`
- `--json`

## New commands

```bash
node .knowledge/tools/team-init.js --team-root <path> --target-root <path> --json
node .knowledge/tools/workspace-register.js --team-root <path> --target-root <path> --workspace-id <id> --agent-id <id> --json
node .knowledge/tools/team-status.js --team-root <path> --json
node .knowledge/tools/workspace-unregister.js --team-root <path> --workspace-id <id> --json
node .knowledge/tools/worktree-status.js --target-root <path> --json
node .knowledge/tools/team-pr-summary.js --team-root <path> --workspace-id <id> --json
node .knowledge/tools/self-test-team-mode.js
node .knowledge/tools/validate-paid-manifest.js
```

## Updated context-aware scripts

- `flow.js`
- `sync-tracked.js`
- `build-routing-bundle.js`
- `build-search-index.js`
- `build-visual-inspector.js`
- `build-wiki-graph.js`
- `lint-wiki.js`
- `doctor.js`
- `collect-metrics.js`
- `generate-pr-summary.js`
- `render-graph-execution.js`
- `evaluation-harness.js`
- `install-agent-integrations.js`
- `external-memory-status.js`
- `search-knowledge.js`
- `scan-secrets.js`

## Artifacts written in repo mode

- `.knowledge/maintenance/routing_bundle.json`
- `.knowledge/maintenance/trust_report.json`
- `.knowledge/maintenance/handoff_summary.json`
- `.knowledge/maintenance/pr_summary.md`
- `.knowledge/maintenance/graphs/*.mmd`
- `.knowledge/search/index.json`
- `.knowledge/metrics/baseline.json`
- `.knowledge/inspector/index.html`

## Artifacts written in team mode

- `<teamRoot>/registry.json`
- `<teamRoot>/repos/<repoId>/repo.json`
- `<teamRoot>/repos/<repoId>/events/YYYY-MM-DD.ndjson`
- `<teamRoot>/repos/<repoId>/locks/flow.lock`
- `<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/workspace.json`
- `<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/maintenance/*`
- `<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/search/index.json`
- `<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/inspector/index.html`

## Inspector UI changes

- Command Center with copy-only buttons.
- Routing Bundle View.
- Team Mode panel.
- Memory Providers panel with provider records.
- PR Summary Preview.
- Paid Inspector disabled extension points are rendered from `docs/product/paid-feature-manifest.json`.
- Contextual conversion signals are rendered from manifest conditions and local metrics.
- Billing boundaries, non-billable free behavior, and usage-billing policy are visible without prices.
- Static HTML does not execute commands silently.

## Memory provider / external memory behavior

- Providers are advisory only.
- Mem0 OSS and Pinecone provider status are reported.
- Team mode warns when legacy Claude MEM appears shared across worktrees.
- External memory cannot raise trust by itself.

## Free vs paid boundaries

- Free core remains repo-local, local-first, Apache-2.0, no telemetry, no required cloud.
- Paid surface is represented only by disabled preview labels, contextual conversion signals, and `docs/product/paid-feature-manifest.json`.
- Paid implementation lives outside the free package in `pro2pilot-inspector/`.
- `03_inspector_monetization_logic.md` is implemented as a configurable capability/commercial model, not as hard-coded prices or feature-to-plan bindings.
- `tools/validate-paid-manifest.js` fails if the free manifest contains concrete prices or capability plan bindings.
- `pro2pilot-inspector/versions/0.1.0/commercial-model.json` captures the paid commercial catalog separately from the free package.

## Tests run

```bash
node knowledge-3.2.0/tools/flow.js release --no-color --json
```

Result: pass, 14/14 steps, `overall_status: ok`, includes `paid-manifest`, doctor step `100/100 healthy`.

```bash
node knowledge-3.2.0/tools/doctor.js --json
```

Result: pass, `quality_score: 100`, `status: healthy`, `issues: []`.

```bash
node knowledge-3.2.0/tools/build-visual-inspector.js --json
```

Result: pass, features include `command_center`, `team_mode_panel`, `routing_bundle_view`, `pr_summary_preview`, `external_memory_status`, `paid_extension_points`, `config_driven_paid_manifest`, and `conversion_signal_preview`.

```bash
node knowledge-3.2.0/tools/validate-paid-manifest.js
```

Result: pass, `prices_in_free_core: false`, `feature_plan_bindings_in_free_core: false`, `capabilities: 10`, `conversion_signals: 6`.

```bash
node knowledge-3.2.0/tools/render-graph-execution.js --json
```

Result: pass, wrote 8 Mermaid diagrams.

```bash
node knowledge-3.2.0/tools/self-test-team-mode.js
```

Result: pass. Covered temp git repo with spaces and Cyrillic path, two worktrees, two workspace registrations, missing `teamRoot`, missing `workspaceId`, duplicate `workspaceId`, duplicate `agentId`, parallel doctor/release exclusive flows, stale lock cleanup, JSON corruption scan, lock release, team events (`doctor_result`, `external_memory_status_changed`, `worktree_warning`), separated state, team status, stale workspace reporting, branch/head detection, branch mismatch, missing targetRoot, dirty/staged runtime warnings, shared external memory warning, Inspector builds in repo and team modes, and workspace archive.

## Manual smoke results

- `team-init`, `workspace-register`, and `team-status` were also smoke-tested against the local workspace with the expected non-git target warning.
- `worktree-status` was run against `knowledge-3.2.0` and detected the local feature branch plus dirty working tree.

## Known limitations

- The outer workspace directory is not a git repository; the active free package repo is `<knowledge-source-root>`.
- The free package repo had pre-existing dirty/staged files before this implementation; they were not reverted.
- `worktree-status` reports generated runtime staging, but it does not unstage files automatically.
- Static Inspector copies commands; command execution requires CLI or an explicit future runner.

## Regression status for repo-local mode

Repo-local mode passed release flow and doctor after the team mode changes.
