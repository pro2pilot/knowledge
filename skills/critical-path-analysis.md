# critical-path-analysis

Use when identifying high-risk code paths.

1. Read `.knowledge/maps/critical_paths.json`.
2. Read `.knowledge/maps/file_criticality.json`.
3. Read `.knowledge/evidence/test_links.json`.
4. Re-read source files for critical paths directly.
5. Update evidence only after verifying behavior against code/tests.

Critical paths with missing tests or stale artifacts should keep trust at `near_trusted`, `suspect`, or `low_confidence` until verified.
