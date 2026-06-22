# README Block

## Benchmark Proof

- GATE-00 Release and QA Gate: release_gate_passed=1. See `maintenance/release-gate-report.json`.
- KB-01 Install and Release Health: artifact_entries=262. See `tools/package-release.js`.
- KB-02 First-read Routing vs Context Packing: routing_bundle_present=1. See `maintenance/routing_bundle.json`.
- KB-03 Trust/Freshness Calibration: modules_total=1. See `maintenance/trust_report.json`.
- KB-04 Repair Queue Actionability: repair_items_total=0. See `maintenance/repair_queue.json`.
- KB-05 Critical Files / Stale Risk: critical_or_important_files=0. See `maps/file_criticality.json`.
- KB-06 Wiki Graph: wiki_nodes=5. See `maps/wiki_graph.json`.
- KB-07 Local Search and Source-of-Truth: search_documents=44. See `search/index.json`.
- KB-08 Inspector UX / Command Center: inspector_checks=10. See `tools/self-test-inspector-ui.js`.
- KB-09 PR Summary and PR Impact: changed_files=191. See `tools/pr-impact.js`.
- KB-11 Memory Provider Safety and Governance: provider_checks=17. See `tools/self-test-memory-providers.js`.
- KB-12 Team Mode / Multi-worktree: workspaces=3. See `tools/self-test-team-inspector-json.js`.
- KB-14 No-cloud / Privacy / Reproducibility: release_violations=0. See `tools/validate-release-artifact.js`.
- KB-15 Performance / Scale: routing_ms=964.6. See `tools/build-routing-bundle.js`.

Full methodology and limitations are in the benchmark run folder.
