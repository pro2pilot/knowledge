# 14 — Site / docs FAQ draft

## What is `.knowledge`?

`.knowledge` is a repo-local routing, evidence, trust, freshness, repair and PR-review system for coding agents.

It helps agents and humans understand what repo knowledge can be trusted, what is stale, what needs repair and how changes affect review.

## Is `.knowledge` an AI coding agent?

No. It does not replace Claude, Codex, Cursor, OpenCode, Cline, Antigravity or other agents.

Agents execute work. `.knowledge` verifies, records, routes, repairs and reviews the knowledge around that work.

## Does `.knowledge` manage subagents automatically?

No. Agent runtimes may have their own subagent systems. `.knowledge` provides a repo-local coordination and trust layer. Connected agents should register sessions, reports, workspaces and locks.

## What is Free Core?

Free Core is the open local system: files, schemas, CLI, routing, evidence, trust/freshness, repair and PR-review data.

## What is Free Inspector?

Free Inspector is the local visual interface included with `.knowledge`. It shows Repo Readiness, Knowledge Trust, PR Review, Agents Activity, Reports and Settings.

## What is Pro?

Pro is a paid subscription that unlocks deeper workflows inside the same Inspector: PR Impact Pro, Repair Planner, Trust History, Policy Packs, advanced reports, Team dashboards and Memory Governance.

## Does free `.knowledge` require cloud or login?

No. Free Core and Free Inspector are local-first and should work without cloud, login or telemetry.

## What is Knowledge Trust?

Knowledge Trust shows whether agents can rely on a module, summary, evidence item or memory result.

States include Trusted, Needs Recheck, Stale, Suspect, Advisory Memory, Missing Evidence, Conflict and Blocked.

## What is Restore Trust?

Restore Trust is a safe action that recomputes health, routing, trust/freshness and repair queue. It can rebuild generated `.knowledge` reports and demote stale memory to advisory. It does not change source code or merge branches.

## What is Evidence?

Evidence is the proof behind knowledge. It links summaries and claims to current source code, tests, decisions or verified artifacts.

## What is Routing?

Routing tells agents what to read first and what source-of-truth order to follow.

## What is Agents Activity?

Agents Activity shows connected agent sessions, reports, locks, queues, workspaces, handoffs and merge readiness.

## Do users need to switch active agents?

No. Connected agents register their sessions automatically. Inspector shows active sessions instead of forcing a global active-agent switch.

## What happens if several agents work at the same time?

Default: Safe Queue. Write zones are locked, and agents wait if a zone is already locked.

Advanced: Parallel Worktrees. Each agent works in a separate branch/worktree, and `.knowledge` prepares an integration/merge report.

## Can agents auto-merge?

Not by default. Auto merge should be disabled except for explicitly allowed low-risk policies. Human approval is default for source code and critical paths.

## What is Agent Report Footer?

Connected agents can add a short `.knowledge` status block at the end of their chat/report: trust state, estimated system context tokens, estimated saved context and suggested Restore Trust action.

## What is Simple Mode?

Simple Mode is not a chat in Inspector. It makes reports plain-language, uses safe defaults and shows one-click safe actions such as Restore Trust.

## Can other apps use `.knowledge` under the hood?

Yes. `.knowledge` is designed headless-first through files, CLI, local API and event streams.

## Is there a VS Code extension?

Planned. VS Code should provide a developer shell around the same local Inspector server: status bar, tree views, commands, file decorations and webview.

## Will there be a desktop app?

Not in V1. The recommended path is VS Code extension + browser Inspector + headless API.
