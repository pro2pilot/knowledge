# Proof Cards

## GATE-00 Release and QA Gate

- Approved wording: GATE-00 Release and QA Gate: release_gate_passed=1.
- Evidence: maintenance/release-gate-report.json
- Scope: local fixture scope

## KB-01 Install and Release Health

- Approved wording: KB-01 Install and Release Health: artifact_entries=262.
- Evidence: tools/package-release.js, tools/validate-release-artifact.js
- Scope: local fixture scope

## KB-02 First-read Routing vs Context Packing

- Approved wording: KB-02 First-read Routing vs Context Packing: routing_bundle_present=1.
- Evidence: maintenance/routing_bundle.json
- Scope: local fixture scope

## KB-03 Trust/Freshness Calibration

- Approved wording: KB-03 Trust/Freshness Calibration: modules_total=1.
- Evidence: maintenance/trust_report.json, maintenance/stale_items.json
- Scope: local fixture scope

## KB-04 Repair Queue Actionability

- Approved wording: KB-04 Repair Queue Actionability: repair_items_total=0.
- Evidence: maintenance/repair_queue.json
- Scope: local fixture scope

## KB-05 Critical Files / Stale Risk

- Approved wording: KB-05 Critical Files / Stale Risk: critical_or_important_files=0.
- Evidence: maps/file_criticality.json, maintenance/stale_items.json
- Scope: local fixture scope

## KB-06 Wiki Graph

- Approved wording: KB-06 Wiki Graph: wiki_nodes=5.
- Evidence: maps/wiki_graph.json
- Scope: local fixture scope

## KB-07 Local Search and Source-of-Truth

- Approved wording: KB-07 Local Search and Source-of-Truth: search_documents=44.
- Evidence: search/index.json, tools/search-knowledge.js
- Scope: local fixture scope

## KB-08 Inspector UX / Command Center

- Approved wording: KB-08 Inspector UX / Command Center: inspector_checks=10.
- Evidence: tools/self-test-inspector-ui.js
- Scope: local fixture scope

## KB-09 PR Summary and PR Impact

- Approved wording: KB-09 PR Summary and PR Impact: changed_files=191.
- Evidence: tools/pr-impact.js, tools/self-test-pr-impact.js
- Scope: local fixture scope

## KB-11 Memory Provider Safety and Governance

- Approved wording: KB-11 Memory Provider Safety and Governance: provider_checks=17.
- Evidence: tools/self-test-memory-providers.js, tools/self-test-external-memory.js
- Scope: local fixture scope

## KB-12 Team Mode / Multi-worktree

- Approved wording: KB-12 Team Mode / Multi-worktree: workspaces=3.
- Evidence: tools/self-test-team-inspector-json.js
- Scope: local fixture scope

## KB-14 No-cloud / Privacy / Reproducibility

- Approved wording: KB-14 No-cloud / Privacy / Reproducibility: release_violations=0.
- Evidence: tools/validate-release-artifact.js, maintenance/external_memory_status.json
- Scope: local fixture scope

## KB-15 Performance / Scale

- Approved wording: KB-15 Performance / Scale: routing_ms=964.6.
- Evidence: tools/build-routing-bundle.js, tools/build-search-index.js, tools/build-visual-inspector.js
- Scope: local fixture scope


## Guardrails

- Do not say best, fastest, guaranteed, enterprise-ready, replaces code review, or 10x.
- Keep preview and planned suites out of public claims.
- Mention fixture scope when using measured-on-fixture claims.

## Held-back proof

- KB-10: preview; agent-neutral routing has local integration surfaces, but no multi-runtime live benchmark was run.
- KB-13: preview; Pro Inspector is a private-preview demo app, not production governance service.
