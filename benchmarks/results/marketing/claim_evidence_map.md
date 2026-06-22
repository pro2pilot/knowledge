# Claim Evidence Map

| Claim | Benchmark | Metric | Evidence | Limitation |
|---|---|---|---|---|
| Agents can start with a compact routing bundle. | B1 | routing_bundle_present, routed_modules | results/summary.json, maintenance/routing_bundle.json | Does not yet prove fewer opened files across many tasks. |
| Trust and freshness state are visible before planning. | B2 | modules_total, stale_items_total | results/summary.json, maintenance/trust_report.json | Precision/recall needs larger injected stale fixtures. |
| Repair debt is structured enough for board workflows. | B3 | repair_items_total, open_repair_items | results/summary.json, maintenance/repair_queue.json | Human usefulness still needs team trials. |
| PR Impact maps diff to trust, freshness, criticality and repair signals. | B4 | changed_files, affected_modules, policy_warnings | tools/pr-impact.js, tools/self-test-pr-impact.js | Current run depends on selected git diff/range. |
| Team Mode avoids state contamination in temp worktree tests. | B8 | state_contamination_count, json_corruption_count | tools/self-test-team-mode.js | Not a production-scale worktree benchmark. |
| Core is designed for local static Inspector and no telemetry. | B10 | static_inspector_generator_present, release_leak_validator_present | tools/build-visual-inspector.js, tools/validate-release-artifact.js | Packet capture is not included. |
| External memory remains advisory and cannot raise trust. | B11 | override_attempts_blocked | tools/self-test-external-memory.js | Real provider installs are optional and credential-dependent. |
