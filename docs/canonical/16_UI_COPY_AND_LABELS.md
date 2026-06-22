# 16 — UI copy and labels

## Product formula

```txt
Repo-local trust, freshness and repair for coding agents.
```

## Sidebar labels

```txt
Home
Review
Knowledge Trust
Agents Activity
Reports
Settings
Pro Preview
```

## Home cards

### Repo Readiness

```txt
Can agents safely work in this repo right now?
```

### Knowledge Trust

```txt
Can agents trust the knowledge they are using?
```

### Evidence Coverage

```txt
How much knowledge is backed by evidence?
```

### Routing Status

```txt
Do agents know where to start and what to read first?
```

### Repair Pressure

```txt
What needs to be repaired to restore trust?
```

### PR Review Status

```txt
How risky are the current changes?
```

### Agent Activity

```txt
Who is working, waiting or ready for review?
```

### Memory Providers

```txt
External memory is advisory and cannot override evidence.
```

## Buttons

```txt
Run Health Check
Restore Trust
Review Current Changes
Open Repair Queue
Open Merge Queue
Export Debug Bundle
Export Pro Snapshot
Open Inspector
```

## Empty states

### No repair items

```txt
No repair work is currently required. Knowledge trust is clean for the current reports.
```

### No active agents

```txt
No connected agent sessions are active. New agent runs will appear here automatically.
```

### No PR changes

```txt
No current changes detected. PR Impact will appear when files change.
```

### No evidence

```txt
No evidence is linked yet. Agents can still use routing, but trust will remain limited until evidence is added.
```

## Warning states

### Trust incomplete

```txt
Some knowledge needs recheck before agents should rely on it.
```

### External memory conflict

```txt
External memory conflicts with current code. It has been marked advisory.
```

### Locked zone

```txt
This area is locked by another agent. The current agent should wait or use a separate worktree.
```

### Auto merge disabled

```txt
Auto merge is disabled by default. Human approval is required for source-code changes.
```

## Pro Preview copy

```txt
Pro unlocks deeper governance: PR Impact Pro, Repair Planning, Policy Packs, Team Dashboards, Memory Governance and Audit History.
```

```txt
Coming soon. Free `.knowledge` stays local-first and fully usable.
```

## Agent footer copy

Compact:

```txt
.knowledge: Trust needs recheck · ~1.2k system tokens · ~38% estimated context saved
```

Full heading:

```txt
## .knowledge report
```
