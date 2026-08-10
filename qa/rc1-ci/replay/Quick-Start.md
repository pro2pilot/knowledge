## Recommended meaningful-task entrypoint

Start scoped work with:

```text
node .knowledge/tools/agent-task.js begin --task="<task>" --scope-module=<id> --scope-path=<path> --json
```

Read the exact returned first-read body. Finish with the returned workflow ID,
first-read SHA, source files and physical test argv. This lets `.knowledge`
reuse the same native verification evidence for one safe task-relevant repair
without hiding unrelated debt. See `docs/agent-task-workflow.md`.

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
| Devin | `node .knowledge/tools/install-agent-integrations.js --runtime devin` | `AGENTS.md`, `.devin/rules/knowledge.rules` |
| Windsurf Cascade | `node .knowledge/tools/install-agent-integrations.js --runtime windsurf` | `.windsurf/rules/knowledge.md` |
| Continue | `node .knowledge/tools/install-agent-integrations.js --runtime continue` | `.continue/rules/knowledge.md` |
| Roo Code | `node .knowledge/tools/install-agent-integrations.js --runtime roo` | `.roo/rules/knowledge.md` |
| Aider | `node .knowledge/tools/install-agent-integrations.js --runtime aider` | `CONVENTIONS.md`, `.aider.conf.yml` |

Codex, OpenClaw, Hermes, and Devin share one runtime-neutral managed block in `AGENTS.md`; connecting another one updates that same block and preserves user-authored text. Devin and Windsurf also use separate vendor paths (`.devin/rules/knowledge.rules` and `.windsurf/rules/knowledge.md`) and never overwrite each other. Devin uses `AGENTS.md` as the documented primary bridge; the supplemental `.rules` bridge remains subject to a live Devin discovery canary.

Do not install every integration during first setup. Other agents can join later
by running their own `--runtime <agent>` command against the already installed
`.knowledge/` folder.

Power users can install every supported integration only when a human explicitly
requests it:

```bash
node .knowledge/tools/install-agent-integrations.js --all --confirm-all
```

## Connect another agent later

If `.knowledge/` is already installed and a different agent joins this same
repository, do not reinstall the system and do not run `--all`. The new agent
only installs its own repo-local bridge:

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime <new-agent>
node .knowledge/tools/flow.js doctor
```

Then the new agent starts from:

```txt
.knowledge/maintenance/routing_bundle.json
.knowledge/maintenance/handoff_summary.json
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

For an explicitly scoped task, create or refresh one task snapshot and read
its `first-read.md` before loading broader maintenance state:

```bash
node .knowledge/tools/task-routing.js create --task="<task>" --scope-module=<module> --scope-path=<path> --json
```

The result provides a task hash. A later refresh must preserve that recorded
scope contract:

```bash
node .knowledge/tools/task-routing.js refresh --task-id=<64-character-task-hash> --json
```

## Use Repair-on-touch during normal work

The default mode is `scoped`. It preserves verification an agent already
performs for the current task; it does not chase a perfect Doctor score or
expand into unrelated maintenance.

Inspect the effective policy and build a task-scoped plan:

```bash
node .knowledge/tools/repair-on-touch.js status \
  --task-id=<task-id> --session-id=<session-id> --json
node .knowledge/tools/repair-on-touch.js plan --request=<task-scope.json>
```

Use the scoped `plan_artifact` returned by `plan`;
`maintenance/repair_opportunities.json` is only the latest-run advisory view.
Only selected, task-relevant findings may proceed. A finding closes only after
the CLI executes the declared checks without a shell, stores a
content-addressed execution, binds current source hashes into a verification
receipt, and applies that receipt:

```bash
node .knowledge/tools/repair-on-touch.js verify --request=<verification.json>
node .knowledge/tools/repair-on-touch.js receipt --request=<receipt.json>
node .knowledge/tools/repair-on-touch.js apply --receipt=KVR-<sha256>
```

Never assert that a test ran, close a sibling finding, edit source merely to
raise health, or bypass confirmation for security/critical-path findings.
Unrelated debt remains deferred. Report the primary task first and knowledge
maintenance separately. See `docs/repair-on-touch.md`.

## Prepare a real-use Field Report

When the user wants a publishable account of real `.knowledge` use, start the
progressive interview. Answers may use any source language; the source defaults to `auto`, while the publication-ready report is always English.

```bash
node .knowledge/tools/field-report.js start --new --json
node .knowledge/tools/field-report.js questions --report-id=<id> --json
```

Ask only the returned questions. Then ingest the tester's answers. A non-English
source requires identity-attributed translation and independent tester approval
before rendering.

```bash
node .knowledge/tools/field-report.js ingest --report-id=<id> --answers=<path>
# Attach evidence-bound engineering results from task-results.template.json:
node .knowledge/tools/field-report.js results-ingest --report-id=<id> --results=<path>
# When translation is required: translation-export -> translation-ingest -> translation-approve
node .knowledge/tools/field-report.js render --report-id=<id>
```

The task-results file supplies the engineering task title and project-specific
checks such as build, tests, migrations, security, UI, or deployment. Each
public pass/warning/fail row is content-addressed to repository- or state-local
evidence. Informational rows may use `outcome_relevant=false`, for example when
deployment was intentionally outside scope. Evidence and the repository
snapshot are revalidated before render, approval, preview, and publication.

The public draft starts with an evidence-bound **Verified engineering outcome**
table. Doctor, wiki, Task Readiness, routing, and Repair-on-touch remain in a
separate system-state table. A local draft may describe a dirty snapshot, but
GitHub publication is blocked until the final Git worktree is clean and facts
are recollected. Repair telemetry is reported as current, stale, invalid, or
unavailable; stale/invalid metrics are withheld. Internal workspace and
organization labels are generalized. Do not infer usefulness, accuracy, speed,
or provider-token effects from health scores or local estimates, and do not
approve or publish on the tester's behalf. Approval and GitHub publication are
two separate explicit actions. See `docs/field-report.md`.

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
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json
node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json
node .knowledge/tools/memory-provider.js status-all --json
node .knowledge/tools/memory-mem0.js health --json
node .knowledge/tools/memory-mem0.js health --adapter live --json
node .knowledge/tools/memory-pinecone.js health --json
```

Mem0 OSS is the recommended optional free/core backend. Start with `setup mem0-oss --live --json`; it creates or reuses the receipt, writes repo-local config, regenerates the Mem0 cookbook recipe, checks live runtime explicitly, and updates the runtime status cache. Choose the Mem0 embedding backend separately with `configure-embeddings`: OpenAI API and Local FastEmbed are both normal guided choices, while LLM provider, embedding provider, Qdrant vector store, and SQLite history store stay distinct. Local FastEmbed must use a new Qdrant collection when provider, model, or dimensions change. Status commands stay offline-safe and distinguish `receipt_present`, `runtime_available`, and `package_installed`. Live add/search/recall require explicit `--adapter live --yes-live-memory`; add is an external-memory write and search/recall return advisory context only. If live import times out, JSON reports `diagnostic_code: live_operation_timeout`, and `--timeout-ms <ms>` can override the wait. Pinecone remains an optional vector/cloud retrieval bridge. Claude MEM is legacy migration data only.

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
`install-check`, `doctor`, and `flow release` with semantic JSON checks. It also
compares every installed system file with the update source by SHA-256 and,
after all semantic post-checks, proves that every pre-existing protected
curated file is still present and unchanged. Newly bootstrapped files and the
explicitly runtime-managed module registry/file-facts are reported separately.

If an older installed artifact has not completed project initialization yet,
the updater runs one non-interactive `flow import` before the final
`flow release`. An initialized project uses `flow release` directly and is not
blindly re-ingested.

Backups live under `.knowledge/maintenance/install-backups/`, outside project
source discovery. A successful update writes `backup-verification.json` with
`safe_to_remove: true`. Keep any backup without that verdict. To remove only
verified backups, with an explicit confirmation:

```bash
node .knowledge/tools/update-system-files.js --prune-verified-backups --yes --json
```

Legacy project-root directories such as `.knowledge_backup_<timestamp>` are
ignored by discovery and reported by `doctor`; archive or remove them only
after `--verify-upgrade --from <new-knowledge-root> --json` passes.

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

If it reports `source_checkout_in_target_root`, a source checkout such as
`knowledge-src/` is inside the target project. Move that folder outside the
project before running import. Do not continue with `flow.js import` while a
source checkout is present in the target root.

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

The updater preserves every pre-existing protected curated file through the
final post-checks, creates only missing migration defaults such as required
`external_memory` policy files, regenerates runtime/status artifacts, and
reports additions or allowed runtime-managed registry changes separately.

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
node .knowledge/tools/lint-wiki.js --strict
node .knowledge/tools/doctor.js
```

```bash
node .knowledge/inspector.js
```

## Release artifact

Do not use GitHub "Download ZIP" as the install package. Use the release asset only.

Use `dist/knowledge-v<package.version>.zip` as the install artifact. Do not copy the source checkout into `.knowledge/` or leave it beside `.knowledge/` as `knowledge-src/`.

Packaging and validation commands are maintainer-only source checkout tools.
They are intentionally excluded from installed user `.knowledge` artifacts.

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
- one mutually exclusive workspace-to-task first-read estimate state:
  - **narrowing**: `Estimated workspace-to-task first-read narrowing: X estimated local context tokens (Y%).`
  - **overhead**: `Estimated workspace-to-task first-read overhead: X estimated local context tokens (+Y%).`
  - **neutral**: `No material estimated local first-read context difference.`
  - **unavailable/not comparable**: `Workspace-to-task first-read estimate is unavailable or not comparable: <reason>.`

> This is a deterministic local context estimate, not provider-reported model-token usage.

Do not show a percentage when the claim is ineligible, the route is stale, the
baseline is invalid, task context is ambiguous, or no comparable estimate is
available.
