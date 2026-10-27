---
name: kb-handoff
description: Prepare a compact handoff summary for another agent or a new chat using .knowledge.
disable-model-invocation: true
---

Prepare a handoff using:

- `.knowledge/maintenance/routing_bundle.json`
- `.knowledge/project_index.json`
- `.knowledge/maintenance/trust_report.json`
- `.knowledge/maintenance/handoff_summary.json`
- `.knowledge/maintenance/concurrency_policy.json`
- `.knowledge/maps/critical_paths.json`
- relevant `.knowledge/modules/*.json`
- open repair/stale items

Output:

1. Project summary.
2. Trusted modules.
3. Near-trusted modules.
4. Routing-only modules.
5. Suspect / low-confidence modules.
6. Mandatory code recheck zones.
7. Recommended first files for the next agent.
8. Maintenance commands to run after changes.
