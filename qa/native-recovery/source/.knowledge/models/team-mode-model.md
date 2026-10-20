# Team Mode Model

Team mode separates where tools live, what repo is being inspected, where
curated knowledge is reviewed, and where generated runtime state is written.

```json
{
  "mode": "repo|team",
  "systemRoot": ".knowledge tool/template/docs root",
  "targetRoot": "source repository or git worktree",
  "projectKnowledgeRoot": "branch-local curated .knowledge root",
  "stateRoot": "runtime/generated state root",
  "teamRoot": "shared team registry root",
  "repoId": "stable repository identifier",
  "workspaceId": "task/worktree identifier",
  "agentId": "stable agent identifier",
  "branch": "current git branch",
  "headSha": "current git HEAD"
}
```

Repo-local mode keeps `systemRoot`, `projectKnowledgeRoot`, and `stateRoot`
equal to the installed `.knowledge` folder. Team mode writes generated artifacts
to:

```text
<teamRoot>/repos/<repoId>/workspaces/<workspaceId>/state/
```

Curated artifacts stay in Git:

- `modules/`
- `evidence/`
- `wiki/`
- `decisions.json`
- hand-written docs, templates, policies, and models

Generated/runtime artifacts stay workspace-specific in team mode:

- `maintenance/`
- `metrics/`
- `search/`
- `inspector/`
- `sessions/`
- generated `maps/wiki_graph.json` and `maps/file_criticality.json`

