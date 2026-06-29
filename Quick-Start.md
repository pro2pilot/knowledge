# Quick Start For Any Agent

You are configuring and operating `.knowledge` for this repository.

Follow this file exactly unless the user gives stronger project-specific instructions.

## Goal

Make `.knowledge/` the repo-local trust, routing, freshness, wiki, search, inspector, and handoff layer for this project.

Canonical product model:

```txt
.knowledge is a repo-local routing, evidence, trust, freshness, repair and PR-review system for coding agents.
```

Do not treat `.knowledge` as an agent manager, AI IDE, chat surface, or auto-merge system. External memory is advisory only.

Open the free local Inspector:

```bash
node .knowledge/inspector.js
```

If `First-run setup` is shown, complete it immediately before relying on agent-written reports.

## Choose your agent integration

Install only the repo-local integration for the agent that is currently operating this repository. If no runtime is obvious, ask the user which command to run instead of creating every vendor folder.

| Agent/runtime | Command | Files created or updated |
|---|---|---|
| Codex | `node .knowledge/tools/install-agent-integrations.js --runtime codex` | `AGENTS.md`, `.agents/skills/` |
| Claude Code | `node .knowledge/tools/install-agent-integrations.js --runtime claude` | `CLAUDE.md`, `.claude/skills/` |
| OpenCode | `node .knowledge/tools/install-agent-integrations.js --runtime opencode` | `.opencode/commands/` |
| OpenClaw | `node .knowledge/tools/install-agent-integrations.js --runtime openclaw` | `AGENTS.md`, `.agents/skills/` |
| Hermes | `node .knowledge/tools/install-agent-integrations.js --runtime hermes` | `AGENTS.md` |
| Gemini CLI | `node .knowledge/tools/install-agent-integrations.js --runtime gemini` | `GEMINI.md` |
| GitHub Copilot | `node .knowledge/tools/install-agent-integrations.js --runtime copilot` | `.github/copilot-instructions.md` |
| Devin | `node .knowledge/tools/install-agent-integrations.js --runtime devin` | `.devin/rules/knowledge.md` |
| Windsurf Cascade | `node .knowledge/tools/install-agent-integrations.js --runtime windsurf` | `.devin/rules/knowledge.md` |
| Continue | `node .knowledge/tools/install-agent-integrations.js --runtime continue` | `.continue/rules/knowledge.md` |
| Roo Code | `node .knowledge/tools/install-agent-integrations.js --runtime roo` | `.roo/rules/knowledge.md` |
| Aider | `node .knowledge/tools/install-agent-integrations.js --runtime aider` | `CONVENTIONS.md`, `.aider.conf.yml` |

Power users can install every supported integration explicitly:

```bash
node .knowledge/tools/install-agent-integrations.js --all
```

OpenClaw uses the `AGENTS.md` plus `.agents/skills/` workspace-skills bridge. Hermes uses an explicit `AGENTS.md` bridge without a vendor folder. Pi and other agents without a confirmed repo-local rules-file convention should read or paste `.knowledge/Quick-Start.md` until their documented convention is confirmed.

## Required first action

If this is a freshly extracted public archive, runtime artifacts are
intentionally not shipped yet. Run first-time setup first:

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime <agent>
node .knowledge/tools/flow.js import
node .knowledge/inspector.js
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
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime <agent>
node .knowledge/tools/flow.js import
node .knowledge/inspector.js
```

Then read:

```txt
.knowledge/maintenance/routing_bundle.json
.knowledge/maintenance/quality_report.json
.knowledge/maintenance/repair_queue.json
```

Do not stop after `flow.js import`. Open the live Inspector right away and complete `First-run setup` when it appears.

## Optional memory providers

Memory providers are advisory only. They never outrank current code, tests, evidence, or decisions.

```bash
node .knowledge/tools/memory-provider.js list --json
node .knowledge/tools/memory-provider.js preview mem0-oss --json
node .knowledge/tools/memory-provider.js status-all --json
node .knowledge/tools/memory-mem0.js health --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
node .knowledge/tools/memory-pinecone.js health --json
```

Mem0 OSS is the recommended optional free/core backend. Live Mem0 health auto-detects Python from explicit `--python`, Mem0/Python env vars, active virtual environments, PATH, Windows `py`/`pymanager`, and standard install directories. It does not scan the whole computer and never installs packages automatically; use `--python "<path>"` when the right interpreter is known. Only `health --adapter live` uses a 30000 ms default timeout for the live Mem0 import/health path, because the first `import mem0` on Windows can be noticeably slower than warm checks; discovery/probe checks remain short. If it times out, JSON reports `diagnostic_code: python_timeout`, and `--timeout-ms <ms>` can override the wait. Pinecone remains an optional vector/cloud retrieval bridge. Claude MEM is legacy migration data only.

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

1. Extract the new release artifact into a temporary folder outside the project.
2. Run a dry-run diff:

```bash
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --dry-run
```

3. If the diff only creates or updates system files, apply it:

```bash
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --apply --yes
```

The updater creates a timestamped backup of the current `.knowledge/`, writes
`.knowledge/maintenance/update_system_files_report.json`, then runs
`install-check`, `doctor`, and `flow release --no-color`.

Do not replace the whole `.knowledge/` folder unless the user explicitly asks
for a reset.

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

## Install guard and Git policy

Before trusting an install, run:

```bash
node .knowledge/tools/install-check.js --json
```

If it reports a nested `.knowledge/.git`, fix only with explicit confirmation:

```bash
node .knowledge/tools/install-check.js --fix --yes
```

Git policy is documented in:

```txt
.knowledge/docs/git-policy.md
```

Runtime files, locks, flow logs, generated indexes, inspector data, temp files,
and local backups are not committed by default.

## Update checks

Visual Inspector checks the official `pro2pilot/knowledge` release feed when it opens. `.knowledge` does not run a background updater, does not apply updates silently, and does not send telemetry.

Manual check:

```bash
node .knowledge/tools/check-updates.js
```

Keep or re-enable weekly advisory checks during `doctor` / `flow`:

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

If an update is available, update only `.knowledge` system files:

```bash
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --preflight --json
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --dry-run
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --apply --yes
```

The updater preserves curated project knowledge byte-for-byte, creates only missing migration defaults such as required `external_memory` policy files, regenerates runtime/status artifacts, and reports stale knowledge as repair work instead of silently deleting it.

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
node .knowledge/tools/build-wiki-graph.js
node .knowledge/tools/build-visual-inspector.js
```

The free Inspector is a local product with token-protected allowlisted actions. Static HTML remains a read-only fallback.

The graph section is the Free Core Trust Graph. It should show source-of-truth order, module routing, wiki relations, advisory external memory, relation counts, broken edges, and orphan pages. If it shows only disconnected nodes, run:

```bash
node .knowledge/tools/build-wiki-graph.js
node .knowledge/tools/self-test-free-core-graph.js
```

```bash
node .knowledge/inspector.js
```

## Release artifact

Do not use GitHub "Download ZIP" as the install package. Use the release asset only.

Use `dist/knowledge-v3.2.2.zip` as the install artifact. Do not copy the source checkout into `.knowledge/`.

```bash
node tools/package-release.js
node tools/validate-release-artifact.js dist/knowledge-v3.2.2.zip --json
```

## Free Inspector vs Inspector Pro

Free Inspector is local, static, one-repo, and command-copy by default. Inspector Pro is the separate waitlist product for deeper team workflows such as repair ownership, policy packs, memory governance, provider fleet status, multi-repo dashboards, and audit/history.

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

Use `--scope=project` when you need facts about this repo. Use `--scope=templates` only to discover scaffolding ideas -- never treat template hits as verified project facts.

## Standard operating flows

```bash
node .knowledge/tools/flow.js scan
node .knowledge/tools/flow.js lint
node .knowledge/tools/flow.js doctor
node .knowledge/tools/flow.js import
node .knowledge/tools/flow.js release
```

## Team mode for multiple agents

Use team mode only when the user explicitly wants multi-worktree or multi-agent
coordination. Repo-local mode remains the default.

```bash
node .knowledge/tools/team-init.js --team-root ../.knowledge-team --target-root . --json
node .knowledge/tools/workspace-register.js --team-root ../.knowledge-team --target-root <worktree-path> --workspace-id <task-id> --agent-id <agent-id> --json
node .knowledge/tools/worktree-status.js --target-root <worktree-path> --team-root ../.knowledge-team --workspace-id <task-id> --json
node .knowledge/tools/flow.js release --team-root ../.knowledge-team --target-root <worktree-path> --workspace-id <task-id> --agent-id <agent-id> --exclusive --json
node .knowledge/tools/team-pr-summary.js --team-root ../.knowledge-team --workspace-id <task-id> --json
```

In team mode, curated knowledge remains in the worktree `.knowledge/` for PR
review, while generated state goes to the workspace state directory under
`teamRoot`.

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
- metrics path;
- estimated tokens saved and percent saved when `.knowledge/metrics/baseline.json` contains routing metrics;
- an explicit note when metrics are unavailable or not regenerated yet.
