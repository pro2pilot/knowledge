# Migration Guide

## Public 3.2.11 to 3.3.0

3.3.0 is the supported public successor to 3.2.11. Version 3.2.12 was an
unpublished internal candidate and is not a required installation or migration
hop.

After the v3.3.0 release is published, obtain the attached
`knowledge-v3.3.0.zip` release asset. Do not use a repository source archive,
GitHub's automatic source ZIP, or a copied internal 3.2.12 candidate.

Extract the asset to a separate local directory. For the strongest
cross-version contract, run the updater from the extracted 3.3.0 asset and
point it at the target `.knowledge`:

```bash
node <extracted-3.3.0>/.knowledge/tools/update-system-files.js --from <extracted-3.3.0>/.knowledge --target-knowledge-root <repo>/.knowledge --dry-run --json
node <extracted-3.3.0>/.knowledge/tools/update-system-files.js --from <extracted-3.3.0>/.knowledge --target-knowledge-root <repo>/.knowledge --preflight --json
node <extracted-3.3.0>/.knowledge/tools/update-system-files.js --from <extracted-3.3.0>/.knowledge --target-knowledge-root <repo>/.knowledge --apply --yes --json
node .knowledge/tools/update-system-files.js --verify-upgrade --from <extracted-3.3.0>/.knowledge --json
node .knowledge/tools/install-check.js --json
node .knowledge/tools/doctor.js --json
```

The previously documented installed-updater sequence remains supported for the
public 3.2.11 to 3.3.0 transition. Its first process necessarily emits the
3.2.11 report shape; the newly installed 3.3.0 verifier reconstructs the
missing runtime-preservation proof from the retained, contained backup and
still fails closed on a missing, escaped, or changed backup.

The update preserves curated wiki pages, module cards, evidence, decisions,
glossary, contradictions, and the project index. It replaces release-managed
system files and regenerates runtime-derived search, graph, metrics, routing,
and Inspector state.

After migration, verify:

- `package.json` and `config.yaml` report `3.3.0`;
- wiki status is one of `healthy`, `usable_with_warnings`, or
  `structurally_broken`;
- `.knowledge/maintenance/routing_decision.json` explains the current routing
  mode and reports zero omitted relevant high-risk modules;
- existing protected curated files appear in the updater's preservation proof;
- any open protected security, contradiction, policy, or migration finding
  remains open until explicitly verified.

Field Report collection is local by default. It does not publish, upload, or
grant external-reuse permission unless the tester performs those explicit
steps. The research telemetry adapter is not enabled by an ordinary install or
normal runtime command.

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

## Agent integration path migration

- Windsurf workspace rules now live in `.windsurf/rules/knowledge.md` with `trigger: always_on`.
- Devin now uses the shared root `AGENTS.md` as its documented primary bridge and a supplemental `.devin/rules/knowledge.rules` vendor file. Windsurf remains in `.windsurf/rules/knowledge.md`; the two runtimes never share a vendor file.
- A recognized legacy Windsurf block under `.devin/rules/knowledge.md` is removed only by the Windsurf installer; a recognized legacy Devin block is removed only by the Devin installer. User-authored and other-runtime content is preserved.
- If that legacy file contains user-authored text outside the managed block, only the recognized Windsurf managed block is removed; user text and any unrelated managed content are preserved except for normalized surrounding blank lines.
- Codex, OpenClaw, Hermes, and Devin now reuse one runtime-neutral managed block in the root `AGENTS.md`; installing a new compatible runtime does not replace user text or add another `.knowledge` block.
