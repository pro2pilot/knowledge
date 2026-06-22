# Scorecard

| Suite | Status | Claim status | Runs | Key metrics |
|---|---|---|---:|---|
| GATE-00 Release and QA Gate | pass | measured | 5 | release_gate_passed=1, p0_commands=12, clean_install_steps=12 |
| KB-01 Install and Release Health | pass | measured | 5 | artifact_entries=262, artifact_violations=0 |
| KB-02 First-read Routing vs Context Packing | pass | measured | 5 | routing_bundle_present=1, routed_modules=1, first_read_declared=1 |
| KB-03 Trust/Freshness Calibration | pass | measured | 5 | modules_total=1, modules_low_confidence=0, stale_items_total=0 |
| KB-04 Repair Queue Actionability | pass | measured | 5 | repair_items_total=0, open_repair_items=0 |
| KB-05 Critical Files / Stale Risk | pass | measured | 5 | critical_or_important_files=0, stale_items_total=0 |
| KB-06 Wiki Graph | pass | measured | 5 | wiki_nodes=5, wiki_edges=0, broken_edges=0 |
| KB-07 Local Search and Source-of-Truth | pass | measured | 5 | search_documents=44, search_command_passed=1 |
| KB-08 Inspector UX / Command Center | pass | measured-on-fixture | 5 | inspector_checks=10, team_mode_fixture=1 |
| KB-09 PR Summary and PR Impact | pass | measured-on-fixture | 5 | changed_files=191, affected_modules=1, policy_warnings=54, fixture_checks=5 |
| KB-10 Agent Neutrality / Handoff | preview | preview | 5 | agent_integration_surfaces=3 |
| KB-11 Memory Provider Safety and Governance | pass | measured-on-fixture | 5 | provider_checks=17, external_checks=6, external_memory_override_count=0, external_memory_can_raise_trust=0 |
| KB-12 Team Mode / Multi-worktree | pass | measured-on-fixture | 5 | workspaces=3, json_corruption_count=0, workspace_state_isolation_pass=1 |
| KB-13 Pro Inspector Governance | preview | preview | 5 | pro_test_passed=1, pro_build_passed=1, kb13_sub_suites=5 |
| KB-14 No-cloud / Privacy / Reproducibility | pass | measured | 5 | release_violations=0, external_memory_can_raise_trust=0, no_cloud_default=1 |
| KB-15 Performance / Scale | pass | measured | 5 | routing_ms=964.6, search_index_ms=667.4, inspector_build_ms=773.8 |
