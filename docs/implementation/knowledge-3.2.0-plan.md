# .knowledge 3.2.0 implementation plan

Generated: 2026-06-05

## Current repo inventory

- The outer workspace directory is not currently a git repository, so branch work should happen inside the active free package repo.
- Free/open-core package under work: `knowledge-3.2.0/`.
- Existing CLI style: Node.js CommonJS scripts in `knowledge-3.2.0/tools/`.
- Existing core runtime artifacts: `maintenance/`, `metrics/`, `search/`, `inspector/`, `maps/wiki_graph.json`, `maps/file_criticality.json`, and flow logs.
- Existing curated artifacts: `modules/`, `evidence/`, `wiki/`, `decisions.json`, `contradictions.json`, `project_index.json`, `docs/`, `templates/`, `invariants/`, and `external_memory/` registry files.
- Paid Inspector workspace: `pro2pilot-inspector/`, ignored at the root so it does not enter free `.knowledge` commits.

## Current scripts and artifacts

- Existing flow runner: `node .knowledge/tools/flow.js release --json`
- Existing health: `doctor.js`, `install-check.js`, `git-policy.js`, `scan-secrets.js`
- Existing graph/search/UI: `build-wiki-graph.js`, `lint-wiki.js`, `render-graph-execution.js`, `build-search-index.js`, `build-visual-inspector.js`
- Existing reports: `collect-metrics.js`, `generate-pr-summary.js`, `evaluation-harness.js`, `external-memory-status.js`
- Existing persistence helper: `tools/lib/json-store.js`

## Changes needed

- Add a context layer that separates `systemRoot`, `targetRoot`, `projectKnowledgeRoot`, `stateRoot`, `teamRoot`, `repoId`, `workspaceId`, and `agentId`.
- Add git/worktree detection with dirty/staged runtime warnings.
- Add team mode registry commands: `team-init`, `workspace-register`, `team-status`, `workspace-unregister`.
- Add locks/events storage under `<teamRoot>/repos/<repoId>/`.
- Make runtime writers use `stateRoot` while curated knowledge stays under `projectKnowledgeRoot`.
- Add a readonly free Team Mode panel and Command Center in the static Inspector.
- Add optional memory-provider status as advisory only.
- Add graph outputs for free/team/external-memory/PR impact flows.
- Add a GitHub Actions template that falls back to repo-local mode.
- Add a self-test that creates temp repos/worktrees, runs team commands, and verifies state separation.

## Free core changes

- Keep repo-local mode as default.
- Keep Apache-2.0, no telemetry, no required cloud, no login, and no hosted backend.
- Keep static Inspector useful: health, routing, trust, why-not-trusted, repair, stale, critical files, wiki graph, search preview, PR summary preview, command copy buttons, memory provider status, and basic team mode context.

## Team team modehanges

- Public name: `team mode`.
- Backward compatibility note: older planning docs may mention `team mode`; UI/commands should call it `team mode`.
- Team mode is explicit and requires `teamRoot`, `targetRoot`, `workspaceId`, and `agentId`.
- Curated knowledge remains branch/worktree-local and mergeable through Git.
- Generated/runtime state goes to `<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/`.
- Exclusive flows hold `flow.lock`.

## Inspector UI changes

- Add Command Center copy buttons for doctor, import, release, inspector, search, graphs, PR summary, worktree status, team init/register/status, team PR summary, and memory provider status.
- Add Team Mode panel with current mode, repoId, workspaceId, agentId, targetRoot, branch/head, lock owner, active workspace count, warnings, and next commands.
- Add paid-only disabled preview actions from a manifest, without moving paid implementation into free core.

## External memory / Memory Provider integration changes

- Keep external memory optional and advisory.
- Show provider, detected/enabled state, path, mode, trust role, license/provenance, and warnings.
- Warn when team mode uses shared memory across worktrees.
- Do not raise trust from external memory alone.

## Tests

- `node knowledge-3.2.0/tools/self-test-team-mode.js`
- `node knowledge-3.2.0/tools/flow.js release --no-color`
- `node knowledge-3.2.0/tools/doctor.js --json`
- `node knowledge-3.2.0/tools/build-visual-inspector.js --json`
- `node knowledge-3.2.0/tools/render-graph-execution.js --json`

## Known risks

- The root workspace is not a git repository, so branch creation and local git status cannot prove final commit readiness here.
- `03_inspector_monetization_logic.md` is advisory and may change soon; implementation should avoid hard-coding its price/package details into free core behavior.
- Some legacy scripts were written for one fixed `.knowledge` root; each runtime writer must be checked before calling team team modeomplete.

## Exact commands to run

```bash
node .knowledge/tools/team-init.js --team-root <teamRoot> --target-root <targetRoot> --json
node .knowledge/tools/workspace-register.js --team-root <teamRoot> --target-root <targetRoot> --workspace-id codex-task-1 --agent-id codex-01 --json
node knowledge-3.2.0/tools/team-status.js --team-root C:\tmp\knowledge-team --json
node .knowledge/tools/worktree-status.js --target-root <targetRoot> --json
node .knowledge/tools/flow.js release --team-root <teamRoot> --target-root <targetRoot> --workspace-id codex-task-1 --agent-id codex-01 --exclusive --json
node knowledge-3.2.0/tools/team-pr-summary.js --team-root C:\tmp\knowledge-team --workspace-id codex-task-1 --json
node knowledge-3.2.0/tools/self-test-team-mode.js
```


