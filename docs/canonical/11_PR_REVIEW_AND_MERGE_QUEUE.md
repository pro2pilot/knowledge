# 11 — PR Review and Merge Queue

## PR Review role

Free `.knowledge` includes basic PR review. Pro adds governance workflow.

## Basic PR Review

```txt
changed files
critical files touched
affected modules
trust/freshness impact
repair delta
generated runtime staged warning
basic reviewer notes
```

## PR Impact Pro

Adds:

```txt
risk scoring
policy packs
recommended tests
snapshot compare
history/trends
approval states
export formats
```

## Review workflow

```txt
Diff → Changed Files → Modules → Trust/Freshness → Critical Paths → Policy → Reviewer Notes
```

## Merge Queue

Not only for PRs. It is the integration point for agent workspaces.

States:

```txt
Draft
Running
Waiting
Ready for Review
Needs Fix
Approved
Blocked
Merged
Archived
```

Entry:

```json
{
  "workspace_id": "ws_billing",
  "agent_instance_id": "claude-code-03",
  "operator_id": "andrii",
  "branch": "agent/billing",
  "status": "ready_for_review",
  "changed_files": [],
  "trust_delta": {},
  "repair_delta": {},
  "policy_warnings": [],
  "recommended_merge_action": "human_review"
}
```

## Merge gates

```txt
no active locks
workspace completed
doctor pass
PR impact generated
no critical suspect trust
policy gates pass
tests pass or explicitly skipped
human approval if source code changed
```

## Default merge policy

```txt
Auto merge disabled.
Manual review required.
```

## Safe auto policies later

```txt
docs-only: possible after checks
tests-only: possible with confirmation
source code: human approval
critical path: human approval always
secrets/infra/prod: blocked
```

## UI

`Review` screen:

```txt
PR Impact
Changed Files
Critical Paths
Policy Warnings
Reviewer Notes
Request Fix
Approve
Export Review Pack
```

`Agents Activity` screen:

```txt
Merge Queue
Workspaces ready for review
Blocked workspaces
Lock conflicts
Integration report
```
