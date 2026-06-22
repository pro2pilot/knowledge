# 03 — Free Inspector UX spec

## Role

Free Inspector is the visual interface included with `.knowledge`.

It must be a usable product, not a debug table.

## Launch model

One command:

```bash
node .knowledge/inspector.js
```

Behavior:

```txt
starts local server on 127.0.0.1
opens browser or VS Code webview
creates session token
serves Inspector UI
exposes allowlisted action API
writes action logs locally
```

Static HTML remains read-only fallback.

Served Inspector and static fallback use the same renderer and the same tab structure. Static mode copies commands and prompts; served mode adds token-protected local action buttons.

Windows installs include a click launcher:

```txt
open-inspector.vbs
tools/create-inspector-shortcut.ps1
```

The click launcher starts `node .knowledge/inspector.js --open` without a visible terminal window.

Served Inspector checks the official release feed on launch through `tools/check-updates.js`. It may show an advisory update banner and dry-run commands, but it must not apply updates silently.

## Navigation

```txt
Home
Review
Knowledge Trust
Agents Activity
Reports
Settings
Pro Preview
```

No top-level `Metrics` tab. Metrics are cards.

No top-level `Command Center` tab. Actions are contextual buttons and a global action drawer.

No top-level `Work` tab. `.knowledge` does not start/own agent work; it observes and coordinates agent activity.

## Home

Purpose:

```txt
Tell the user if the repo is ready, whether agent knowledge can be trusted, and what to do next.
```

Cards:

```txt
Repo Readiness
Knowledge Trust
Evidence Coverage
Routing Status
Repair Pressure
PR Review Status
Agent Activity
Memory Providers
Next Recommended Action
Recent Reports
```

Metric cards must look like status metrics, not action buttons. Warning/problem states use yellow; critical states use red.

### Repo Readiness

Operational repo state:

```txt
git clean?
doctor ok?
branch safe?
runtime files not staged?
active locks?
last flow passed?
release artifact valid?
```

### Knowledge Trust

Knowledge/memory state:

```txt
trusted modules
stale items
suspect memory
missing evidence
external memory conflicts
repair queue
```

## Review

```txt
PR Impact
Changed Files
Critical Paths
Policy Warnings
Reviewer Notes
Approve / Request Fix / Export Review Pack
```

Free includes basic PR Impact. Pro adds advanced scoring, policy packs, history and workflow.

## Knowledge Trust

```txt
Trust Overview
Evidence
Routing
Why Not Trusted
Freshness
Repair Queue
Search
Wiki Graph
Restore Trust
Repair trust with an agent
```

Evidence and Routing are fundamental, but nested here to keep the sidebar human-readable.

Knowledge Trust includes a `Trust repair prompt for agent` copy action. The prompt tells an agent to use `kb-repair-trust` and to ask before risky trust, source, test, or critical-path changes.

## Agents Activity

```txt
Active Sessions
Agent Reports
Safe Queue
Locks
Parallel Worktrees
Merge Queue
Handoff
Branch Policy
Git Branch Diagnostics
```

No `Switch Active Agent`. Active agents are derived from sessions, heartbeats, locks and reports.

Git Branch Diagnostics includes a branch selector. It defaults to the active Git branch and may switch the Inspector diagnostic target to another local branch without running `git checkout`.

## Reports

```txt
Agent Reports
Debug Bundle
Pro Snapshot
Benchmark Proof
Audit Export
Marketing Proof Pack
```

## Settings

```txt
User Mode: Simple / Advanced
Agent Report Footer
Autonomy / Permissions
Concurrent Work Policy
Merge Policy
Git Policy
Memory Providers
VS Code Integration
Local Server
License / Pro Preview
```

## Pro Preview

```txt
Coming Soon
What Pro unlocks
Export Pro Snapshot
Join waitlist / Activate later
```

No prices inside Inspector in the free release.

## Button behavior

Buttons should execute allowlisted local actions via the local action server.

Copy command is secondary fallback, not primary UX.

Action lifecycle:

```txt
idle → queued → running → passed / failed / blocked
```

Each run must show:

```txt
action id
duration
stdout/stderr summary
artifacts updated
warnings/errors
next recommended actions
```

## Action risk levels

| Risk | Examples | UX |
|---|---|---|
| read_only | doctor, status, search | run immediately |
| local_write | flow release, build inspector, restore trust | run with visible log |
| network/provider | update check, Mem0 install, license activation | confirmation modal |
| destructive | delete memory, uninstall provider | strong confirmation |
| paid_only | Pro policy gates, team ownership | locked card / Pro Preview |

## Simple vs Advanced UI

Simple Mode is not a tab.

It changes language and defaults:

```txt
plain-language summaries
safe defaults
fewer raw details
Restore Trust button when trust is incomplete
```

Advanced Mode shows:

```txt
raw JSON
locks/events
schemas
routing bundle
evidence graph
branch policy
agent adapters
```
