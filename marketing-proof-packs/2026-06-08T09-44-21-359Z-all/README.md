# Marketing Proof Pack

Run: 2026-06-08T09-44-21-359Z-all

Verdict: partial

This pack only promotes suites with `measured` or `measured-on-fixture` claim status. Preview, planned, diagnostic and failed suites are included only as limitations.

## Approved public claims

- GATE-00 Release and QA Gate: release_gate_passed=1. Evidence: `maintenance/release-gate-report.json`.
- KB-01 Install and Release Health: artifact_entries=262. Evidence: `tools/package-release.js`.
- KB-02 First-read Routing vs Context Packing: routing_bundle_present=1. Evidence: `maintenance/routing_bundle.json`.
- KB-03 Trust/Freshness Calibration: modules_total=1. Evidence: `maintenance/trust_report.json`.
- KB-04 Repair Queue Actionability: repair_items_total=0. Evidence: `maintenance/repair_queue.json`.
- KB-05 Critical Files / Stale Risk: critical_or_important_files=0. Evidence: `maps/file_criticality.json`.
- KB-06 Wiki Graph: wiki_nodes=5. Evidence: `maps/wiki_graph.json`.
- KB-07 Local Search and Source-of-Truth: search_documents=44. Evidence: `search/index.json`.
- KB-08 Inspector UX / Command Center: inspector_checks=10. Evidence: `tools/self-test-inspector-ui.js`.
- KB-09 PR Summary and PR Impact: changed_files=191. Evidence: `tools/pr-impact.js`.
- KB-11 Memory Provider Safety and Governance: provider_checks=17. Evidence: `tools/self-test-memory-providers.js`.
- KB-12 Team Mode / Multi-worktree: workspaces=3. Evidence: `tools/self-test-team-inspector-json.js`.
- KB-14 No-cloud / Privacy / Reproducibility: release_violations=0. Evidence: `tools/validate-release-artifact.js`.
- KB-15 Performance / Scale: routing_ms=964.6. Evidence: `tools/build-routing-bundle.js`.

## Not approved

- KB-10 Agent Neutrality / Handoff: preview; agent-neutral routing has local integration surfaces, but no multi-runtime live benchmark was run.
- KB-13 Pro Inspector Governance: preview; Pro Inspector is a private-preview demo app, not production governance service.

## Reproduce

```sh
node .knowledge/benchmarks/run-benchmarks.js --suite all --runs 5 --json
node .knowledge/benchmarks/generate-marketing-pack.js --latest --json
```
