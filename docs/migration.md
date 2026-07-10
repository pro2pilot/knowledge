# Migration Guide

When an older `.knowledge` exists:

1. Back it up.
2. Preserve `wiki/`, `modules/`, `evidence/`, `decisions.json`, `glossary.json`, `contradictions.json`, and `project_index.json`.
3. Do not copy runtime locks, temp files, local logs, provider state, generated benchmark results, or secrets.
4. Run the system updater from the new release, then verify the upgrade.
5. Inspect `repair_queue.json`, `quality_report.json`, and `.knowledge/maintenance/update_system_files_report.json`.

When migrating from `.knowledge`, extract the new archive so the repository contains `.knowledge/` directly.

## Update From 3.1.9 Or Newer

Use the installed updater:

```bash
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --dry-run --json
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --preflight --json
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --apply --yes --json
node .knowledge/tools/update-system-files.js --verify-upgrade --from <new-knowledge-root> --json
```

The updater writes a report with permission preflight, system
created/updated/removed counts, migration defaults, project-preserved counts,
semantic runtime regeneration checks, SHA-256 source parity, stale/repair
counts, and a post-check preservation proof for every pre-existing protected
curated file. New bootstrap files and explicitly runtime-managed
`module_registry.json`/`file_facts.json` changes are reported separately. A
backup is considered disposable only when
`backup_verification.safe_to_remove` is `true`; otherwise it remains a rollback
backup.

Verified backups are stored under `.knowledge/maintenance/install-backups/`
and can be pruned explicitly:

```bash
node .knowledge/tools/update-system-files.js --prune-verified-backups --yes --json
```

The prune command never removes an unverified backup. Legacy
`.knowledge_backup_*` directories in the repository root are excluded from
ingest/sync and surfaced by `doctor` for manual archival or cleanup.

## Bootstrap From 3.1.8-Like Installs

If the installed `.knowledge` does not have `tools/update-system-files.js`, run the updater from the extracted new release and point it at the target `.knowledge`:

```bash
node <new-knowledge-root>/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root <repo>/.knowledge --dry-run --json
node <new-knowledge-root>/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root <repo>/.knowledge --preflight --json
node <new-knowledge-root>/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root <repo>/.knowledge --apply --yes --json
node <repo>/.knowledge/tools/update-system-files.js --verify-upgrade --from <new-knowledge-root> --json
```

This mode installs the updater and all manifest-listed system paths before
running post-checks. If project runtime has never been initialized, it selects
one non-interactive `flow import` and then verifies with `flow release`; an
initialized project goes directly to `flow release`. It must not change an
existing protected curated file unless a separate migration mode explicitly
says so. Missing required project defaults, for example
`external_memory/registry.json` and `external_memory/retrieval_policy.json`, are
created only when absent and are reported as migration defaults.
