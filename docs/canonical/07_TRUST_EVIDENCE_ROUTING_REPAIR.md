# 07 — Routing, Evidence, Trust, Freshness, Repair

## Purpose

This is the core value of `.knowledge`.

```txt
Routing tells agents where to look.
Evidence tells why knowledge is trusted.
Trust tells if knowledge is usable.
Freshness tells if knowledge is stale.
Repair tells how to restore trust.
```

## Routing

Answers:

```txt
What should the agent read first?
What source-of-truth order should it follow?
Which module/file owns this topic?
```

Artifacts:

```txt
maintenance/routing_bundle.json
maps/directory_map.json
maps/dependency_map.json
```

## Evidence

Answers:

```txt
What is this knowledge claim based on?
Which code/tests/files support it?
When was it verified?
```

Evidence states:

```txt
present
missing
stale
conflicting
partial
```

## Trust

States:

```txt
Trusted
Needs Recheck
Stale
Suspect
Advisory Memory
Missing Evidence
Conflict
Blocked
```

## Freshness

Triggers:

```txt
source file changed
test file changed
evidence older than code
routing changed
memory conflict found
module moved/deleted
wiki link broken
```

## Repair

Repair queue item must include:

```json
{
  "id": "repair_...",
  "status": "open",
  "severity": "low|medium|high|critical",
  "reason": "missing_evidence|stale_summary|conflict|broken_link",
  "affected_files": [],
  "affected_modules": [],
  "recommended_actions": [],
  "safe_auto_fix": false,
  "requires_human_review": true
}
```

## Restore Trust safe action

Button:

```txt
Restore Trust
```

Safe workflow:

```txt
Run Health Check
Refresh routing/search/indexes
Recompute trust/freshness
Detect stale/suspect/missing evidence
Auto-fix generated/runtime artifacts
Demote stale memory to advisory
Refresh repair queue
Produce plain-language report
```

Must not automatically:

```txt
change source code
merge branches
raise trust without evidence
rewrite curated evidence/wiki/decisions without approval
```

## Simple report example

```md
I checked the project knowledge.

What was wrong:
- 2 summaries were outdated.
- 1 memory note did not match current code.
- Search/routing files were stale.

What I fixed:
- Rebuilt routing and search.
- Marked outdated memory as advisory.
- Updated the repair queue.

What still needs review:
- Billing module evidence should be confirmed by a developer.
```
