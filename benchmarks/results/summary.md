# Benchmark Proof Pack

Generated: 2026-06-07T20:48:06.489Z

Status: 7 pass, 0 limited, 0 fail.

| ID | Benchmark | Status | Key metrics | Limitations |
|---|---|---|---|---|
| B1 | Repo Orientation | pass | routing_bundle_present=1, routed_modules=1, first_read_declared=1 | orientation improvement is structural; fewer-file claim needs multi-task human/agent trials |
| B2 | Trust/Freshness | pass | modules_total=1, modules_low_confidence=0, stale_items_total=0 | precision/recall is not claimed until injected stale fixtures are expanded |
| B3 | Repair Queue | pass | repair_items_total=0, open_repair_items=0 | actionability is measured by structured queue shape, not reviewer satisfaction yet |
| B4 | PR Impact | pass | changed_files=144, affected_modules=1, policy_warnings=48, critical_files=0, command_duration_ms=975 | current run uses local working-tree diff; PR range metrics depend on selected base/head |
| B8 | Team Mode | pass | checks_total=24, state_contamination_count=0, json_corruption_count=0, command_duration_ms=26186 | temp-repo self-test, not a large production worktree benchmark |
| B10 | Local-first Privacy | pass | static_inspector_generator_present=1, release_leak_validator_present=1, external_memory_can_raise_trust=0, no_telemetry_claim_scope=1 | network-call count is asserted by design/offline commands; packet capture is not included |
| B11 | Memory Provider Safety | pass | checks_total=6, override_attempts_blocked=1, command_duration_ms=579 | provider runtime integration is simulated unless users install real Mem0/Pinecone credentials |

Claims remain bounded to these artifacts; no best/guaranteed/10x claims are made.
