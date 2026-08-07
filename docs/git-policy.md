# Git Policy

`.knowledge` contains three kinds of files:

- curated system/framework files;
- project-specific knowledge;
- generated runtime artifacts.

The default policy is conservative: commit curated and project knowledge, but
do not commit locks, logs, temp files, caches, local reports, or generated heavy
outputs unless the team explicitly chooses to.

## Commit By Default

- `.knowledge/README.md`
- `.knowledge/Quick-Start.md`
- `.knowledge/config.yaml`
- `.knowledge/modules/`
- `.knowledge/evidence/`
- `.knowledge/decisions.json`
- `.knowledge/glossary.json`
- `.knowledge/invariants/`
- `.knowledge/wiki/`
- `.knowledge/docs/`
- `.knowledge/templates/`
- `.knowledge/prompts/`
- `.knowledge/skills/`
- `.knowledge/commands/`
- `.knowledge/agent-integrations/`

These files are either framework files or curated project knowledge.

## Do Not Commit By Default

- `.knowledge/.lock`
- `.knowledge/.runtime/`
- `.knowledge/maintenance/flow-logs/`
- `.knowledge/maintenance/events/`
- `.knowledge/maintenance/sync_log.json`
- `.knowledge/maintenance/update_status.json`
- `.knowledge/maintenance/install_check_report.json`
- `.knowledge/maintenance/update_system_files_report.json`
- `.knowledge/maintenance/stale_items.json`
- `.knowledge/maintenance/repair_queue.json`
- `.knowledge/maintenance/automation_status.json`
- `.knowledge/maintenance/handoff_summary.json`
- `.knowledge/maintenance/wiki_lint_report.json`
- `.knowledge/maintenance/external_memory_status.json`
- `.knowledge/maintenance/secret_scan_report.json`
- `.knowledge/maintenance/graphs/`
- `.knowledge/project_index.json`
- `.knowledge/freshness.json`
- `.knowledge/search/index.json`
- `.knowledge/inspector/`
- `.knowledge/metrics/baseline.json`
- `.knowledge/metrics/README.md`
- `.knowledge/maps/wiki_graph.json`
- `.knowledge/maps/file_criticality.json`
- `.knowledge/maps/dependency_map.json`
- `.knowledge/maps/directory_map.json`
- `.knowledge/maps/entrypoints.json`
- temporary `.tmp-*` files
- backup `.bak-*` files
- local `.zip` archive artifacts

These are local runtime state, logs, generated indexes, or safety backups.

## Optional, By Team Policy

- `.knowledge/maintenance/routing_bundle.json`
- `.knowledge/maintenance/trust_report.json`
- `.knowledge/maintenance/quality_report.json`
- `.knowledge/maintenance/pr_summary.md`
- `.knowledge/maps/wiki_graph.json`
- `.knowledge/maps/file_criticality.json`
- `.knowledge/metrics/baseline.json`

Committing these can make agent startup faster or CI review easier, but they are
generated artifacts and may create merge conflicts. If your team commits them,
refresh them consistently in CI or before merging.

## Recommended Files

Use this as the installed `.knowledge/.gitignore` baseline:

```txt
.knowledge/templates/git-policy/.knowledge.gitignore
```

Optionally copy this into the root `.gitattributes`:

```txt
.knowledge/templates/git-policy/gitattributes.snippet
```

The snippet marks generated/static artifacts as `linguist-generated=true`. It
does not require custom merge drivers or manual Git config.

## Agent Rule

Agents should never commit runtime files just because they appeared after
`flow import` or `flow release`. If a generated file is intentionally tracked,
that must be a team policy decision.
