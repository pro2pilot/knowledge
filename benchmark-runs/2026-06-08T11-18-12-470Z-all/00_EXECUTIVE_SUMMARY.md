# Benchmark run 2026-06-08T11-18-12-470Z-all - Executive summary

## Verdict
partial

## What can be marketed now
| Claim | Status | Metric | Evidence | Limitation |
|---|---|---|---|---|
| Release and QA Gate produced a local benchmark result with recorded limitations. | measured | release_gate_passed=1 | maintenance/release-gate-report.json | fixture/local run scope |
| Install and Release Health produced a local benchmark result with recorded limitations. | measured | artifact_entries=262 | tools/package-release.js | fixture/local run scope |
| A compact routing bundle gives agents a first-read route before loading broad context. | measured | routing_bundle_present=1 | maintenance/routing_bundle.json | fixture/local run scope |
| Trust and freshness state are visible before planning. | measured | modules_total=1 | maintenance/trust_report.json | fixture/local run scope |
| Repair queue state is structured for follow-up work. | measured | repair_items_total=0 | maintenance/repair_queue.json | fixture/local run scope |
| Critical Files / Stale Risk produced a local benchmark result with recorded limitations. | measured | critical_or_important_files=0 | maps/file_criticality.json | fixture/local run scope |
| Wiki Graph produced a local benchmark result with recorded limitations. | measured | wiki_nodes=5 | maps/wiki_graph.json | fixture/local run scope |
| Local Search and Source-of-Truth produced a local benchmark result with recorded limitations. | measured | search_documents=44 | search/index.json | fixture/local run scope |
| Inspector UX / Command Center produced a local benchmark result with recorded limitations. | measured-on-fixture | inspector_checks=10 | tools/self-test-inspector-ui.js | fixture/local run scope |
| PR Impact maps changed files to modules, policy warnings and reviewer notes in a local fixture. | measured-on-fixture | changed_files=255 | tools/pr-impact.js | fixture/local run scope |
| External memory is visible but remains advisory and cannot raise trust. | measured-on-fixture | provider_checks=17 | tools/self-test-memory-providers.js | fixture/local run scope |
| Team Mode fixture preserves separate workspace state with zero JSON corruption. | measured-on-fixture | workspaces=3 | tools/self-test-team-inspector-json.js | fixture/local run scope |
| The release artifact passes local privacy/leak validation with no cloud dependency. | measured | release_violations=0 | tools/validate-release-artifact.js | fixture/local run scope |
| Performance / Scale produced a local benchmark result with recorded limitations. | measured | routing_ms=693.8 | tools/build-routing-bundle.js | fixture/local run scope |

## What cannot be marketed
| Claim | Why not | Required next evidence |
|---|---|---|
| Agent Neutrality / Handoff produced a local benchmark result with recorded limitations. | preview | agent-neutral routing has local integration surfaces, but no multi-runtime live benchmark was run |
| Pro Inspector Governance produced a local benchmark result with recorded limitations. | preview | Pro Inspector is a private-preview demo app, not production governance service |

## Top proof points
1. GATE-00: pass (measured).
2. KB-01: pass (measured).
3. KB-02: pass (measured).
4. KB-03: pass (measured).
5. KB-04: pass (measured).

## Main blocker, if any
No failed suite in this run.

## Reproduction
- `verification/reproduction.sh`
- `verification/reproduction.ps1`
