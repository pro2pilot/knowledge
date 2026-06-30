# 05 — team mode / Multi-worktree mode

## Назначение файла

Этот файл превращает приложенный текст про team mode в проектную спецификацию для `.knowledge 3.2.3`. Режим должен быть экспериментальным, но рабочим: несколько агентов работают в разных Git worktrees/branches, имеют общий team registry, отдельные workspace states, стабильные agent IDs, централизованные locks/events/status и безопасную merge-модель через Git.

## Product summary

**team mode = explicit team mode для multi-worktree / multi-agent работы.**

Он добавляет командную координацию, не ломая default repo-local mode:

- repo-local mode остается дефолтом;
- team mode включается только явно;
- branch-local curated knowledge остается в Git;
- runtime/generated state разделяется по workspace/agent;
- shared dirty working tree не становится нормальным сценарием;
- основной workflow — один branch/worktree на одного агента/task.

## Принятые решения по приложенному тексту

| Идея из текста | Решение | Причина |
|---|---|---|
| `systemRoot`, `targetRoot`, `projectKnowledgeRoot`, `stateRoot` | Использовать полностью. | Это ключ к разделению tool code, target repo, curated knowledge and runtime state. |
| Явное включение team mode | Использовать полностью. | Сохраняет backwards compatibility. |
| No daemon/cloud/server required | Использовать полностью. | Соответствует local-first обещанию. |
| No telemetry | Использовать полностью. | Совпадает с product trust. |
| No shared dirty working tree | Использовать как warning + policy. | Без этого multi-agent state будет опасен. |
| Все команды имеют `--json` | Использовать полностью. | Нужно для Inspector, CI, automation. |
| Windows/PowerShell paths | Использовать как QA gate. | Иначе продукт выглядит Unix-only. |
| Symlink optional only | Использовать полностью. | На Windows symlink часто требует admin/dev mode. |
| `team-init`, `workspace-register`, `team-status`, `workspace-unregister` | Использовать полностью. | Минимальный registry workflow. |
| Locks/events centralization | Использовать полностью. | Нужна защита от JSON corruption и conflict visibility. |
| Context-aware core scripts | Использовать полностью. | Без этого team mode останется декоративным. |
| Inspector team panel in free | Использовать как readonly/basic. | Free видит локальный status; deeper collaboration/history remain outside free core. |
| CI fallback repo-local | Использовать полностью. | GitHub Actions не должен требовать central teamRoot. |
| Self-test with temp repo + 2 worktrees | Использовать полностью. | Это Definition of Done. |

## Core concepts

```text
systemRoot
  Где лежит код .knowledge/tools, templates, docs, agent integrations.

targetRoot
  Конкретный repo/worktree, по которому агент сейчас работает.

projectKnowledgeRoot
  Branch-local .knowledge внутри target repo, где лежат curated artifacts:
  modules/, evidence/, wiki/, decisions.json.

stateRoot
  Writable runtime/generated state для конкретного workspace/agent.
  Repo mode: targetRoot/.knowledge
  Team mode: <teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/
```

## Default repo-local mode

Default behavior must stay compatible:

```json
{
  "mode": "repo",
  "systemRoot": "<targetRoot>/.knowledge",
  "targetRoot": "<repo>",
  "projectKnowledgeRoot": "<targetRoot>/.knowledge",
  "stateRoot": "<targetRoot>/.knowledge",
  "teamRoot": null,
  "repoId": null,
  "workspaceId": null,
  "agentId": null
}
```

Repo-local mode must not require:

- `KNOWLEDGE_MODE`;
- `KNOWLEDGE_TEAM_ROOT`;
- workspace registration;
- daemon;
- cloud;
- central team state.

## Team mode topology

Recommended topology:

```text
repo-main/
  .knowledge/

../worktrees/
  codex-task-1/
    .knowledge/
  claude-task-2/
    .knowledge/
  opencode-task-3/
    .knowledge/

../.knowledge-team/
  registry.json
  repos/
    <repoId>/
      repo.json
      workspaces/
        <workspaceId>/
          workspace.json
          state/
            maintenance/
            sessions/
            metrics/
            search/
            inspector/
      locks/
      events/
```

## Why curated knowledge stays in Git

Curated knowledge includes:

- `modules/`
- `evidence/`
- `wiki/`
- `decisions.json`
- hand-curated docs/specs
- project-level rules

These artifacts are code-adjacent. They should:

- move with branches;
- be reviewed in PR;
- merge back to main;
- keep historical context;
- remain inspectable by agents and humans.

## Why runtime state moves to workspace-specific central state

Runtime/generated state includes:

- `maintenance/routing_bundle.json`
- `maintenance/repair_queue.json` generated state, if not curated;
- `maintenance/pr_summary.md`
- `metrics/`
- `search/`
- `inspector/`
- flow logs;
- lock files;
- temporary outputs.

In team mode, runtime state should not be shared across branches/worktrees. Each workspace gets:

```text
<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/
```

This prevents:

- one agent overwriting another agent's runtime state;
- stale inspector state leaking across branches;
- JSON corruption from parallel writes;
- wrong PR summary for another branch;
- mixed session state.

## Path context library

Create:

```text
.knowledge/tools/lib/path-context.js
```

Function:

```js
resolveKnowledgeContext(options = {})
```

Returns:

```json
{
  "mode": "repo|team",
  "systemRoot": "...",
  "targetRoot": "...",
  "projectKnowledgeRoot": "...",
  "stateRoot": "...",
  "teamRoot": "...",
  "repoId": "...",
  "workspaceId": "...",
  "agentId": "...",
  "branch": "...",
  "headSha": "...",
  "isGitWorktree": true,
  "warnings": []
}
```

Configuration sources:

CLI flags:

```text
--team-root
--target-root
--workspace-id
--agent-id
--state-root
--project-knowledge-root
```

Environment variables:

```text
KNOWLEDGE_MODE=repo|team
KNOWLEDGE_TEAM_ROOT
KNOWLEDGE_TARGET_ROOT
KNOWLEDGE_WORKSPACE_ID
KNOWLEDGE_STATE_ROOT
KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT
KNOWLEDGE_AGENT_ID
```

Fallback:

- repo mode: current logic, `.knowledge` parent = target repo;
- team mode: required `teamRoot`, `targetRoot`, `workspaceId`, `agentId`.

Stable `repoId`:

1. prefer normalized git remote URL + repo root hash;
2. fallback target path hash;
3. sanitize for filesystem.

## Git/worktree awareness

Create:

```text
.knowledge/tools/lib/git-context.js
```

Must detect:

- is git repo;
- branch;
- head sha;
- worktree root;
- git common dir;
- dirty status summary;
- changed files;
- remote URL.

Command:

```bash
node .knowledge/tools/worktree-status.js --target-root <path> --json
```

Output:

```json
{
  "is_git_repo": true,
  "branch": "bot/codex-task-1",
  "head_sha": "...",
  "dirty": true,
  "changed_files": [],
  "remote_url": "...",
  "warnings": []
}
```

Warnings:

- agent is on main;
- dirty working tree shared by multiple active workspaces;
- workspace branch mismatch;
- targetRoot does not match registered path;
- generated runtime files are staged for commit;
- worktree not registered;
- repoId mismatch;
- legacy Claude MEM shared across worktrees in team mode.

## Team registry commands

### team-init

```bash
node .knowledge/tools/team-init.js --team-root <path> --target-root <path> --json
```

Creates:

```text
<teamRoot>/registry.json
<teamRoot>/repos/<repoId>/repo.json
<teamRoot>/repos/<repoId>/locks/
<teamRoot>/repos/<repoId>/events/
```

Writes event:

```text
team_init
```

### workspace-register

```bash
node .knowledge/tools/workspace-register.js \
  --team-root <path> \
  --target-root <path> \
  --workspace-id codex-task-1 \
  --agent-id codex-01 \
  --json
```

Creates:

```text
<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/workspace.json
<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/
```

`workspace.json` fields:

```json
{
  "workspaceId": "codex-task-1",
  "agentId": "codex-01",
  "targetRoot": "...",
  "branch": "bot/codex-task-1",
  "headSha": "...",
  "created_at": "...",
  "updated_at": "...",
  "last_flow": null,
  "last_status": null,
  "lock_status": null,
  "pr_number": null,
  "notes": null,
  "status": "active"
}
```

### team-status

```bash
node .knowledge/tools/team-status.js --team-root <path> --json
```

Shows:

- repos;
- workspaces;
- active agents;
- branch/head;
- last flow result;
- locks;
- stale workspaces;
- warnings.

### workspace-unregister

```bash
node .knowledge/tools/workspace-unregister.js \
  --team-root <path> \
  --workspace-id <id> \
  --json
```

Behavior:

- soft delete only;
- set `status: archived`;
- do not delete state by default;
- optional `--delete-state` only with explicit confirmation later.

## Locks and events

Create or extend:

```text
.knowledge/tools/lib/team-store.js
```

Locks:

```text
Repo-level lock:
<teamRoot>/repos/<repoId>/locks/repo.lock

Workspace-level lock:
<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/.lock

Flow exclusive lock:
<teamRoot>/repos/<repoId>/locks/flow.lock
```

Lock owner format:

```json
{
  "pid": 12345,
  "hostname": "machine",
  "agentId": "codex-01",
  "workspaceId": "codex-task-1",
  "branch": "bot/codex-task-1",
  "targetRoot": "...",
  "started_at": "2026-06-04T00:00:00Z"
}
```

Events path:

```text
<teamRoot>/repos/<repoId>/events/YYYY-MM-DD.ndjson
```

Event types:

```text
team_init
workspace_register
workspace_unregister
flow_start
flow_step
flow_end
lock_acquired
lock_released
lock_timeout
pr_summary_generated
doctor_result
trust_status_changed
worktree_warning
external_memory_status_changed
```

## Context-aware core scripts

Minimum scripts that must become context-aware:

```text
flow.js
sync-tracked.js
build-routing-bundle.js
build-search-index.js
build-visual-inspector.js
doctor.js
collect-metrics.js
generate-pr-summary.js
render-graph-execution.js
evaluation-harness.js
install-agent-integrations.js
external-memory-status.js
```

Path rules:

| Read/write category | Path root |
|---|---|
| tool code/templates/docs | `systemRoot` |
| source repo scan | `targetRoot` |
| curated knowledge read/write | `projectKnowledgeRoot` |
| generated/runtime outputs | `stateRoot` |
| locks/events | `teamRoot/repos/<repoId>/...` |

Repo-local equivalence:

```text
projectKnowledgeRoot === stateRoot === systemRoot === targetRoot/.knowledge
```

## flow.js flags

Add:

```text
--team-root
--target-root
--workspace-id
--agent-id
--exclusive
--json
```

In `--exclusive` mode, hold `flow.lock` for the whole flow, not just individual JSON writes.

`flow --json` response must include:

```json
{
  "flow": "release",
  "mode": "team",
  "repo_id": "...",
  "workspace_id": "...",
  "agent_id": "...",
  "target_root": "...",
  "project_knowledge_root": "...",
  "state_root": "...",
  "branch": "...",
  "head_sha": "...",
  "overall_status": "ok|failed",
  "warnings": []
}
```

## PR / merge workflow helpers

Command:

```bash
node .knowledge/tools/team-pr-summary.js --team-root <path> --workspace-id <id> --json
```

It gathers:

- workspace metadata;
- branch/head;
- changed source files;
- changed curated knowledge files;
- doctor score;
- trust buckets;
- repair queue delta;
- critical files touched;
- suggested reviewer notes;
- path to generated `pr_summary.md`.

Recipe:

```text
.knowledge/docs/cookbook/07-team-worktree-pr.md
```

Scenario:

```text
team-init
workspace-register
agent work
flow release --exclusive
team-pr-summary
open PR
CI
merge to main
refresh main baseline
archive workspace
```

## Merge model

### Mergeable through PR

- curated modules;
- evidence files;
- wiki pages;
- decisions;
- docs;
- source changes;
- tests;
- policy config if project-level.

### Rebuild after merge

- routing bundle;
- search index;
- inspector output;
- runtime metrics;
- generated PR summary;
- workspace state;
- locks;
- events aggregation.

### Safe merge checklist

Before PR:

1. `worktree-status --json`
2. `flow release --exclusive --json`
3. `team-pr-summary --json`
4. no generated runtime files staged unless intentionally tracked;
5. no unresolved repair items blocking changed critical paths;
6. no branch mismatch;
7. no lock held;
8. no external memory conflict.

After merge:

1. update main;
2. run repo-local `flow release --json` on main;
3. refresh main baseline;
4. archive workspace;
5. clear stale locks;
6. retain events for history.

## Inspector support

Free local Inspector should show team-mode panel if team metadata exists:

- current mode;
- repoId;
- workspaceId;
- agentId;
- targetRoot;
- branch/head;
- lock owner;
- active workspaces summary;
- last flow result;
- warnings;
- copied commands for next step.

Inspector Pro can add:

- active workspace dashboard;
- compare workspaces;
- owner/status;
- GitHub PR mapping;
- team history;
- alerts;
- policy checks;
- audit export.

UI button:

```text
Team Mode
```

Sub-actions:

```text
Initialize team root
Register this workspace
Show team status
Check worktree
Run release with exclusive lock
Generate team PR summary
Archive workspace
```

## Memory providers and legacy Claude MEM in team mode

Problem: external memory can be shared across worktrees for the same git repository. That can conflict with the team mode rule "do not mix runtime state across branches/worktrees".

Required behavior:

1. Use `node .knowledge/tools/memory-provider.js status-all --json` for provider status.
2. Keep provider runtime state under `stateRoot` in team mode.
3. If legacy Claude MEM state is shared across worktrees, show warning.
4. Treat legacy Claude MEM as migration-only advisory data.
5. Record provider configuration in the memory provider registry.
6. Never let external memory raise trust without code/test/evidence.
7. Include Mem0/Pinecone and legacy-provider status in `doctor`, metrics and Inspector.

Suggested legacy status shape:

```json
{
  "provider": "legacy-claude-mem",
  "enabled": false,
  "mode": "workspace-specific-legacy|shared-legacy|legacy",
  "path": "<stateRoot>/external_memory/claude_mem/",
  "source": "legacy stateRoot or CLAUDE_MEMORY_PATH detection",
  "version": "detected-or-unknown",
  "license": "unknown",
  "trust_role": "advisory_only",
  "warnings": []
}
```

## CI template

Create:

```text
.knowledge/github-action-templates/knowledge-team-workspace.yml
```

Minimum:

```yaml
name: knowledge-team-workspace
on: [pull_request]
jobs:
  knowledge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Install check
        run: node .knowledge/tools/install-check.js --json
      - name: Doctor
        run: node .knowledge/tools/flow.js doctor --json
      - name: PR summary
        run: node .knowledge/tools/generate-pr-summary.js --json
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: knowledge-artifacts
          path: |
            .knowledge/maintenance/pr_summary.md
            .knowledge/maintenance/quality_report.json
```

Note: CI can run fallback repo-local mode. Do not require central `teamRoot` in GitHub Actions.

## Self-test

Create:

```bash
node tools/self-test-team-mode.js
```

Test must:

1. create temp git repo;
2. install/copy `.knowledge`;
3. create two worktrees:
   - `bot/codex-task-1`
   - `bot/claude-task-2`
4. create shared team root;
5. run `team-init`;
6. run `workspace-register` for two workspaces;
7. run two flows in parallel:
   - one `flow doctor`;
   - one `flow release --exclusive`;
8. verify no JSON corruption;
9. verify locks released;
10. verify events written;
11. verify workspace states separated;
12. verify `team-status` sees both workspaces;
13. verify branch/head correct;
14. verify changes in one worktree do not overwrite state of another;
15. verify default repo-local mode separately;
16. verify path with spaces;
17. verify path with Cyrillic;
18. verify Git warnings:
    - agent on main;
    - dirty workspace;
    - staged generated runtime file;
19. verify legacy Claude MEM shared-memory warning when applicable.

## Manual smoke

```bash
# 1. Create temp repo
mkdir "tmp knowledge тест" && cd "tmp knowledge тест"
git init

# 2. Add/copy .knowledge
# ...

# 3. Create worktrees
git checkout -b main
git worktree add ../worktrees/codex-task-1 -b bot/codex-task-1
git worktree add ../worktrees/claude-task-2 -b bot/claude-task-2

# 4. Init team root
node .knowledge/tools/team-init.js --team-root ../.knowledge-team --target-root . --json

# 5. Register workspaces
node .knowledge/tools/workspace-register.js --team-root ../.knowledge-team --target-root ../worktrees/codex-task-1 --workspace-id codex-task-1 --agent-id codex-01 --json
node .knowledge/tools/workspace-register.js --team-root ../.knowledge-team --target-root ../worktrees/claude-task-2 --workspace-id claude-task-2 --agent-id claude-01 --json

# 6. Run flows
node .knowledge/tools/flow.js release --team-root ../.knowledge-team --target-root ../worktrees/codex-task-1 --workspace-id codex-task-1 --agent-id codex-01 --exclusive --json
node .knowledge/tools/flow.js doctor --team-root ../.knowledge-team --target-root ../worktrees/claude-task-2 --workspace-id claude-task-2 --agent-id claude-01 --json

# 7. Status and summary
node .knowledge/tools/team-status.js --team-root ../.knowledge-team --json
node .knowledge/tools/team-pr-summary.js --team-root ../.knowledge-team --workspace-id codex-task-1 --json
```

## Definition of Done

team mode is done when:

- several agents can be registered in one team root;
- each agent can work in a different Git worktree/branch;
- each workspace has separate runtime state;
- locks/events/status work;
- PR summaries can be generated per workspace;
- default repo-local mode is not broken;
- all commands support `--json`;
- Windows/PowerShell paths, spaces and Cyrillic paths pass tests;
- Inspector has Team Mode panel;
- Inspector Pro can build on top of the same registry without changing free core semantics.
