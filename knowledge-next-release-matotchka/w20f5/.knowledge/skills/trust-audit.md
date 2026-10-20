# trust-audit

Use this playbook before planning or editing code.

1. Read `.knowledge/project_index.json`.
2. Read `.knowledge/maintenance/trust_report.json`.
3. Read `.knowledge/maintenance/handoff_summary.json`.
4. Read `.knowledge/maintenance/concurrency_policy.json`.
5. Read relevant `.knowledge/modules/*.json`.
6. Re-read source code for any `suspect`, `needs_recheck`, `low_confidence`, uncovered, or critical area.

Output:

- relevant modules
- current trust tier
- files that must be checked directly
- stale/repair items that affect the task
- whether the knowledge layer is usable for routing only or limited planning
