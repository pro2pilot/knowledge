# Install And Git Policy Audit

This note records the pre-fix install/update assumptions for the
`fix/install-git-policy` hardening pass.

## Current Layout Assumption

The GitHub source repository is the contents of a future `.knowledge/`
directory. A release artifact must wrap source files as `.knowledge/...`.

Most runtime tools assume repo-local mode:

- `tools/flow.js` uses `knowledgeRoot = path.resolve(__dirname, '..')` and
  `repoRoot = path.resolve(knowledgeRoot, '..')`.
- `tools/doctor.js`, `tools/sync-tracked.js`,
  `tools/build-routing-bundle.js`, `tools/build-search-index.js`,
  `tools/build-visual-inspector.js`, `tools/install-git-hooks.js`, and
  `tools/run-git-hook-sync.js` use the same `.knowledge/` under target repo
  root model.
- `tools/install-agent-integrations.js` supports installed repo-local mode
  when `path.basename(knowledgeRoot) === '.knowledge'`, otherwise it falls
  back to `process.cwd()` for source-development mode.
- README, Quick-Start, cookbook docs, commands, and agent integration blocks
  all document commands as `node .knowledge/tools/...`.

This repo-local default must remain the default.

## Runtime/Generated Files

`flow import` can create or update:

- `project_index.json`
- `freshness.json`
- `maps/file_criticality.json`
- `maps/directory_map.json`
- `maps/entrypoints.json`
- `maps/dependency_map.json`
- `maps/wiki_graph.json`
- `maintenance/handoff_summary.json`
- `maintenance/repair_queue.json`
- `maintenance/trust_report.json`
- `maintenance/routing_bundle.json`
- `maintenance/wiki_lint_report.json`
- `maintenance/external_memory_status.json`
- `maintenance/secret_scan_report.json`
- `maintenance/quality_report.json`
- `maintenance/events/*.ndjson`
- `maintenance/flow-logs/*.json`
- `search/index.json`
- `inspector/data.json`
- `inspector/status.json`

`flow release` can additionally create or update:

- `metrics/baseline.json`
- `metrics/README.md`
- `maintenance/pr_summary.md`
- `maintenance/graphs/*.mmd`
- `evaluation/results/latest.json`

Update checks can create:

- `maintenance/update_status.json`

## System/Framework Files

System files are the framework implementation and docs that can be replaced by
new releases:

- `README.md`
- `Quick-Start.md`
- `Portal.md`
- `LICENSE`
- `NOTICE`
- `package.json`
- `config.yaml`
- `assets/`
- `agent-integrations/`
- `commands/`
- `docs/`
- `flows/`
- `github-action-templates/`
- `models/`
- `prompts/`
- `skills/`
- `templates/`
- `tools/`

## Project-Specific Knowledge

These files represent local project state and must not be overwritten during a
normal system update:

- `project_index.json`
- `freshness.json`
- `decisions.json`
- `contradictions.json`
- `glossary.json`
- `evidence/`
- `external_memory/`
- `invariants/`
- `maintenance/`
- `maps/`
- `metrics/`
- `modules/`
- `search/`
- `sessions/`
- `wiki/`
- `inspector/`

## Not Committed By Default

Runtime locks, temp files, logs, generated indexes, generated reports, caches,
and local backups should not be committed by default:

- `.lock/`
- `.runtime/`
- `maintenance/flow-logs/`
- `maintenance/events/`
- `maintenance/sync_log.json`
- `maintenance/update_status.json`
- `maintenance/install_check_report.json`
- `maintenance/update_system_files_report.json`
- `project_index.json`
- `freshness.json`
- `search/index.json`
- `inspector/data.json`
- `inspector/status.json`
- `metrics/baseline.json`
- `metrics/README.md`
- `*.tmp-*`
- `*.bak-*`
- logs and cache folders

Teams may intentionally commit selected generated artifacts such as
`routing_bundle.json`, `trust_report.json`, or `maps/wiki_graph.json`, but that
should be a team policy decision, not the default result of a fresh install.

## Current P0/P1 Failure Modes

- A user can copy the whole source repository into `.knowledge/`, including
  `.knowledge/.git`, instead of using a release artifact.
- There is no packaging command that proves the artifact root is exactly
  `.knowledge/` and excludes nested Git metadata.
- There is no install guard that distinguishes a normal fresh archive from a
  broken install.
- A fresh archive intentionally lacks `maintenance/routing_bundle.json`, but
  agents may misread that as an install failure before `flow import`.
- Existing update guidance relies on prose and can be ignored; a naive copy can
  overwrite `wiki/`, `modules/`, `evidence/`, `decisions.json`, and other
  project-specific knowledge.
- Generated JSON such as routing bundles, trust reports, search indexes,
  metrics, inspector data, and flow logs can create noisy merge conflicts.
- Git status after install is unclear unless `.knowledge/.gitignore` is
  present and explains curated/system vs generated/runtime artifacts.
