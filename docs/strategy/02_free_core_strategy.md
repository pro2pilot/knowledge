# 02 — Free/Core `.knowledge` strategy after competitive analysis

## Purpose

Free `.knowledge` must win against fragmented open-source alternatives by being the first coherent repo-local system that combines:

```txt
context packing + routing + trust/freshness + repair queue + local search + PR summary + Inspector + optional memory bridges
```

It must not be a weak teaser for Pro Inspector. It must be useful as a serious local tool.

## Market comparison

| Market layer | Competitors | What they do well | What free `.knowledge` must add |
|---|---|---|---|
| Context packers | Repomix, gitingest | pack repo into AI-readable format | first-read routing + trust + repair + freshness |
| Memory layers | Mem0, Letta, Graphiti | persistence / long-term memory | source-of-truth order and advisory boundary |
| Agent runtimes | Cline, Aider, Claude Code, Copilot | execute/edit code | runtime-neutral knowledge contract |
| PR tools | PR-Agent | review/summarize PR | repair debt + trust/freshness + critical paths |
| Search/code intelligence | Sourcegraph | deep code search | lightweight local install artifact |

## Free core product promise

```txt
Install `.knowledge` into any repo.
Build a first-read route for agents.
See what knowledge is trusted, stale or suspect.
Repair knowledge debt.
Generate PR context.
Use local Inspector buttons instead of raw JSON.
No cloud required.
No telemetry.
```

## Required free features

| Feature | Free requirement | Competitive reason |
|---|---|---|
| Clean install artifact | `dist/knowledge-v3.2.0.zip`, no source checkout junk | must feel more serious than scripts pasted into repo |
| Routing Bundle | first operational read for any agent | competes with context packers |
| Trust Ledger | trusted/near/suspect/advisory buckets | differentiates from memory apps |
| Freshness | stale artifacts and recheck reasons | differentiates from summaries |
| Repair Queue | actionable next steps | turns governance into work |
| Local Search | scoped artifacts search | prevents full repo recrawl |
| PR Summary | markdown PR context | bridge into review market |
| PR Impact preview | changed files → modules/trust/criticality | must not concede to PR review tools entirely |
| Visual Inspector | tabbed, button-first cockpit | turns smart folder into product |
| Command Center | copy/run commands safely | reduces CLI friction |
| Memory Providers | Mem0/Pinecone status, advisory-only | compete with memory layers without becoming memory app |
| Team Mode status | current workspace/worktree/lock warnings | bridge to paid team layer |
| Export Debug Bundle | redacted reports, no secrets | support and proof loop |
| No-cloud/no-telemetry badge | explicit local mode proof | core trust differentiator |

## Free Inspector required tabs

```txt
Overview
Command Center
Routing
Trust Ledger
Why Not Trusted
Freshness
Repair Queue
Critical Files
Wiki Graph
Search
PR Summary
PR Impact Preview
Memory Providers
Team Mode
Integrations
Metrics
Export / Debug
Pro Preview
```

## Minimum free button map

| Button | Command | Notes |
|---|---|---|
| Run Doctor | `node .knowledge/tools/doctor.js --json` | read-only status |
| Refresh Release | `node .knowledge/tools/flow.js release --no-color --json` | explicit action |
| Build Inspector | `node .knowledge/tools/build-visual-inspector.js` | local output |
| Search | `node .knowledge/tools/search-knowledge.js "query" --json` | scoped |
| Generate PR Summary | `node .knowledge/tools/generate-pr-summary.js --json` | local markdown |
| Preview PR Impact | `node .knowledge/tools/pr-impact.js --json` | if missing, implement |
| Export Debug Bundle | `node .knowledge/tools/export-debug-bundle.js --json` | redacted |
| Team Status | `node .knowledge/tools/team-status.js --json` | local/team mode |
| Memory Status | `node .knowledge/tools/memory-provider.js status-all --json` | no API key required |
| Mem0 Preview | `node .knowledge/tools/memory-provider.js preview mem0-oss --json` | no install |
| Pro Snapshot | `node .knowledge/tools/export-pro-snapshot.js --json` | sanitized |

## Required free quality bar

Free core can be called release-ready only if:

```txt
self-test-install-policy: pass
self-test-memory-providers: pass
self-test-external-memory: pass
self-test-team-mode: pass
self-test-inspector-ui: pass
flow release: pass
clean install smoke: pass
validate-release-artifact: pass
no local path leak: pass
no unexpected network calls in status/report/build: pass
```

## Free messaging

Use:

```txt
Stop making every agent rediscover your repo.
One first-read routing bundle.
Trust/freshness before memory.
Repair queue for stale knowledge.
A local Inspector for what agents know.
```

Do not use:

```txt
Best AI IDE
Autonomous coding platform
Guaranteed hallucination-free agents
Replace code review
Memory that knows everything
```

## Free/core roadmap priority

1. Fix release artifact and Team Mode self-test.
2. Make PR Impact Preview real enough to compare with PR tools.
3. Make Inspector tabs and buttons polished.
4. Make Mem0 status/runtime adapter honest and useful.
5. Add benchmark proof artifacts for orientation, freshness, repair, PR impact, Team Mode, no-cloud.
6. Publish demos and README proof section only after tests pass.
