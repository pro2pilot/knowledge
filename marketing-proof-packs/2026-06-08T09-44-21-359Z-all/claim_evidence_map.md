# Claim Evidence Map

## Public-ready

| Suite | Status | Claim status | Metrics | Evidence | Limitation |
|---|---|---|---|---|---|
| GATE-00 | pass | measured | release_gate_passed=1, p0_commands=12, clean_install_steps=12 | maintenance/release-gate-report.json | local fixture scope |
| KB-01 | pass | measured | artifact_entries=262, artifact_violations=0 | tools/package-release.js | local fixture scope |
| KB-02 | pass | measured | routing_bundle_present=1, routed_modules=1, first_read_declared=1 | maintenance/routing_bundle.json | local fixture scope |
| KB-03 | pass | measured | modules_total=1, modules_low_confidence=0, stale_items_total=0 | maintenance/trust_report.json | local fixture scope |
| KB-04 | pass | measured | repair_items_total=0, open_repair_items=0 | maintenance/repair_queue.json | local fixture scope |
| KB-05 | pass | measured | critical_or_important_files=0, stale_items_total=0 | maps/file_criticality.json | local fixture scope |
| KB-06 | pass | measured | wiki_nodes=5, wiki_edges=0, broken_edges=0 | maps/wiki_graph.json | local fixture scope |
| KB-07 | pass | measured | search_documents=44, search_command_passed=1 | search/index.json | local fixture scope |
| KB-08 | pass | measured-on-fixture | inspector_checks=10, team_mode_fixture=1 | tools/self-test-inspector-ui.js | local fixture scope |
| KB-09 | pass | measured-on-fixture | changed_files=191, affected_modules=1, policy_warnings=54, fixture_checks=5 | tools/pr-impact.js | local fixture scope |
| KB-11 | pass | measured-on-fixture | provider_checks=17, external_checks=6, external_memory_override_count=0, external_memory_can_raise_trust=0 | tools/self-test-memory-providers.js | local fixture scope |
| KB-12 | pass | measured-on-fixture | workspaces=3, json_corruption_count=0, workspace_state_isolation_pass=1 | tools/self-test-team-inspector-json.js | local fixture scope |
| KB-14 | pass | measured | release_violations=0, external_memory_can_raise_trust=0, no_cloud_default=1 | tools/validate-release-artifact.js | local fixture scope |
| KB-15 | pass | measured | routing_ms=964.6, search_index_ms=667.4, inspector_build_ms=773.8 | tools/build-routing-bundle.js | local fixture scope |

## Held back

| Suite | Status | Claim status | Metrics | Evidence | Limitation |
|---|---|---|---|---|---|
| KB-10 | preview | preview | agent_integration_surfaces=3 | agent-integrations/codex | agent-neutral routing has local integration surfaces, but no multi-runtime live benchmark was run |
| KB-13 | preview | preview | pro_test_passed=1, pro_build_passed=1, kb13_sub_suites=5 | ../pro2pilot-inspector/scripts/test.mjs | Pro Inspector is a private-preview demo app, not production governance service |
