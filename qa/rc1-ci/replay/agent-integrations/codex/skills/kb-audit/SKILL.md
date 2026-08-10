---
name: kb-audit
description: Audit .knowledge trust, freshness, contradictions, and module coverage before planning or editing.
---

Audit `.knowledge/` for the current task.

Steps:

1. Read `.knowledge/maintenance/routing_bundle.json`.
2. Read `.knowledge/maintenance/trust_report.json`.
3. Read `.knowledge/maintenance/handoff_summary.json`.
4. Read `.knowledge/maintenance/quality_report.json` if present.
5. Identify relevant module cards from `.knowledge/modules/`.
6. Use `.knowledge/tools/search-knowledge.js "<query>"` only when extra wiki/module/evidence context is needed.
7. If anything is `suspect`, `needs_recheck`, `low_confidence`, `advisory_only`, or `routing_trusted`, re-read the minimal relevant source files.
8. Report relevant modules, trust tier, files to inspect, mandatory code recheck zones, and whether `.knowledge` is safe for routing only or limited planning.
