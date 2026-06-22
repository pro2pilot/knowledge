# 01 — Product canon

## One-sentence definition

```txt
.knowledge is a repo-local routing, evidence, trust, freshness, repair and PR-review system for coding agents.
```

## Product category

```txt
Knowledge governance layer for coding agents.
```

Not:

```txt
AI IDE
agent orchestrator
memory app
PR-review bot only
generic workflow canvas
project management tool
```

## Core promise

`.knowledge` gives any connected coding agent a repo-local, inspectable, evidence-backed source of truth about:

- where to start reading;
- what knowledge can be trusted;
- what knowledge is stale;
- what evidence supports claims;
- what must be repaired;
- how PR changes affect trust, critical files and review;
- which agents/workspaces are touching the repo.

## What `.knowledge` controls

```txt
routing
evidence
trust
freshness
repair
PR review
agent activity state
locks
workspaces
merge readiness
reports
```

## What `.knowledge` does not control

```txt
It does not replace the agent runtime.
It does not manage all subagents automatically.
It does not own the chat experience.
It does not silently run or merge code.
It does not make external memory source-of-truth.
```

## Main UX surfaces

```txt
Free Inspector — local visual interface.
VS Code Extension — developer shell around the same local server.
Browser Inspector — standalone local UI for all other users.
Headless CLI/API — for apps using .knowledge under the hood.
Pro Unlock — subscription opens Pro features inside the same Inspector.
```

## Canonical navigation

```txt
Home
Review
Knowledge Trust
Agents Activity
Reports
Settings
Pro Preview
```

## Main terms

| Term | Meaning |
|---|---|
| Routing | Where an agent should start and what source-of-truth order it must follow. |
| Evidence | Concrete basis for knowledge claims. |
| Trust | Whether an agent can rely on a knowledge item now. |
| Freshness | Whether knowledge is stale after code/test/repo changes. |
| Repair | Work needed to restore trust. |
| PR Review | Diff/change review through trust, freshness, critical paths and policy. |
| Agent Activity | Sessions, runs, locks, queues, workspaces, reports and handoffs produced by connected agents. |
| Safe Queue | Multi-agent mode where write zones are locked and agents wait instead of colliding. |
| Parallel Worktrees | Advanced mode where agents work in separate branches/worktrees. |
| Merge Queue | Review/approval queue for agent-created branches/workspaces. |
| Restore Trust | Safe workflow to recompute health/trust/freshness/repair and produce a plain-language report. |

## Public positioning

Use:

```txt
Repo-local trust and freshness for coding agents.
Evidence-backed memory for AI-assisted repositories.
PR review with trust, freshness and repair context.
Bring any coding agent into a safer repo-local knowledge workflow.
```

Avoid:

```txt
We replace Cursor/Claude/Codex.
We eliminate hallucinations.
We guarantee safe PRs.
We auto-manage all agents.
Memory is always trusted.
```
