# Quick Start For Any Agent

You are configuring and operating `.knowledge` for this repository.

Follow this file exactly unless the user gives stronger project-specific instructions.

## Goal

Make `.knowledge/` the repo-local trust, routing, freshness, wiki, search, inspector, and handoff layer for this project.

## Required first action

If this is a freshly extracted public archive, runtime artifacts are
intentionally not shipped yet. Run first-time setup first:

```bash
node .knowledge/tools/install-agent-integrations.js
node .knowledge/tools/flow.js import
```

After setup, read:

```txt
.knowledge/maintenance/routing_bundle.json
```

If this is an existing configured `.knowledge` installation, read the routing
bundle first. If it is missing or stale, choose the correct setup path below.

## Setup for a new project

From the repository root:

```bash
node .knowledge/tools/install-agent-integrations.js
node .knowledge/tools/flow.js import
```

Then read:

```txt
.knowledge/maintenance/routing_bundle.json
.knowledge/maintenance/quality_report.json
.knowledge/maintenance/repair_queue.json
```

## Updating an existing `.knowledge` installation

If `.knowledge/` already exists and the user is applying a newer `.knowledge` release, do **not** replace the whole folder and do **not** overwrite project knowledge records.

Update only the system files that implement the framework:

```txt
README.md
Quick-Start.md
Portal.md
LICENSE
NOTICE
package.json
config.yaml
assets/
agent-integrations/
commands/
docs/
flows/
github-action-templates/
models/
prompts/
skills/
templates/
tools/
```

Preserve project-specific knowledge and trust state unless the user explicitly asks to reset it:

```txt
project_index.json
freshness.json
decisions.json
contradictions.json
glossary.json
evidence/
external_memory/
invariants/
maintenance/
maps/
metrics/
modules/
search/
sessions/
wiki/
inspector/
```

Safe update procedure:

1. Create a backup of the current `.knowledge/` folder.
2. Extract the new archive into a temporary folder outside the project.
3. Copy only the system files listed above into the existing `.knowledge/`.
4. Do not overwrite module cards, trust reports, evidence, wiki pages, repair queue, freshness, decisions, or project maps.
5. Run:

```bash
node .knowledge/tools/doctor.js
node .knowledge/tools/flow.js release --no-color
```

6. If the release introduces a schema migration tool, run it in `--dry-run` mode first.
7. Report changed system files and any doctor warnings.

## Setup for an existing project with an old `.knowledge` base

If the repository has an older `.knowledge/` folder that should be migrated rather than only updated:

1. Create a timestamped backup.
2. Preserve useful artifacts: `wiki/`, `modules/`, `evidence/`, `decisions.json`, `glossary.json`, `maintenance/handoff_summary.json`, and `maintenance/repair_queue.json`.
3. Do not copy runtime locks, temp files, local logs, flow logs, hook logs, raw test output, or secrets.
4. Merge valuable content, then run:

```bash
node .knowledge/tools/flow.js import
```

If conflicts appear, current code and tests win. Lower trust rather than guessing.

## If the existing knowledge base is not `.knowledge`

If the project already has another knowledge system, do not overwrite it.

1. Inventory the existing knowledge source.
2. Create a backup.
3. Classify content into:
   - `wiki/`
   - `decisions.json`
   - `glossary.json`
   - `evidence/proposed/`
   - `modules/`
   - `external_memory/sources/`
4. Preserve raw source under:
   `.knowledge/imports/legacy-<date>/`
5. Write a migration map:
   `.knowledge/maintenance/migration_map.json`
6. Do not mark imported content as trusted.
7. Run:
   `node .knowledge/tools/flow.js import`
8. Keep imported material `advisory_only` until checked against current code/tests.

## Optional update checks

Update checks are disabled by default. `.knowledge` does not run a background updater and does not send telemetry.

Manual check:

```bash
node .knowledge/tools/check-updates.js
```

Optional weekly advisory check during `doctor` / `flow`:

```bash
node .knowledge/tools/check-updates.js --enable --interval=7d
```

Change the interval:

```bash
node .knowledge/tools/check-updates.js --interval=14d
```

Disable update checks:

```bash
node .knowledge/tools/check-updates.js --disable
```

If an update is available, update only `.knowledge` system files. Do not overwrite project knowledge records, trust state, evidence, modules, maps, wiki, repair queue, freshness, sessions, metrics, or inspector output.

## Official templates

List templates:

```bash
node .knowledge/tools/apply-template.js --list
```

If the project type is obvious, apply one relevant template:

```bash
node .knowledge/tools/apply-template.js nextjs-saas
node .knowledge/tools/apply-template.js python-fastapi
node .knowledge/tools/apply-template.js node-monorepo
node .knowledge/tools/apply-template.js supabase
node .knowledge/tools/apply-template.js ai-agent-runtime
```

Templates are advisory and require code/test verification before trust is raised.

## Visual Inspector

Build after setup or release flow:

```bash
node .knowledge/tools/build-visual-inspector.js
```

Open:

```txt
.knowledge/inspector/index.html
```

Use it for screenshots, demos, onboarding, and inspecting trust/repair/wiki graph state.

## Cookbook

When a task matches a repeatable workflow, read the relevant recipe in:

```txt
.knowledge/docs/cookbook/
```

## Search scope

`search-knowledge.js` has 4 scopes. Pick the right one for the question:

```bash
node .knowledge/tools/search-knowledge.js "query"                     # default: project facts only
node .knowledge/tools/search-knowledge.js "query" --scope=templates   # scaffolding suggestions only
node .knowledge/tools/search-knowledge.js "query" --scope=cookbook    # operational recipes only
node .knowledge/tools/search-knowledge.js "query" --scope=all         # broad exploratory search
```

Use `--scope=project` when you need facts about this repo. Use `--scope=templates` only to discover scaffolding ideas — never treat template hits as verified project facts.

## Standard operating flows

```bash
node .knowledge/tools/flow.js scan
node .knowledge/tools/flow.js lint
node .knowledge/tools/flow.js doctor
node .knowledge/tools/flow.js import
node .knowledge/tools/flow.js release
```

## Source-of-truth order

1. Current source code
2. Current tests
3. `.knowledge/evidence/*.json`
4. `.knowledge/modules/*.json`
5. `.knowledge/decisions.json`
6. `.knowledge/wiki/*.md`
7. `.knowledge/sessions/*`
8. External retrieved memory

Code beats summaries. Tests beat prose.

## Trust rules

- `trusted`: usable for routing and limited planning; still re-read code before critical edits.
- `near_trusted`: usable after targeted checks.
- `routing_trusted`: use only to choose files and boundaries.
- `advisory_only`: context only.
- `suspect`, `needs_recheck`, `low_confidence`: re-read source code before claims or edits.

## Mandatory code recheck zones

Always re-read source code and tests for auth, billing, runtime execution, queue/worker/claim logic, storage, signing, secrets, migrations, security-sensitive code, concurrency-sensitive code, or anything stale/suspect/low-confidence.

## After meaningful work

Run:

```bash
node .knowledge/tools/flow.js release
```

Then report:

- doctor score/status;
- wiki lint score/status;
- suspect or low-confidence modules;
- repair queue items;
- routing bundle path;
- PR summary path;
- metrics path.
