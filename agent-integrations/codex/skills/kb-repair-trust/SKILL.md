---
name: kb-repair-trust
description: Repair .knowledge trust, doctor degradation, or repair queue issues. Use when the user says "почини доверие", "repair trust", "doctor degraded", "doctor below 90", "restore trust did not improve score", or "repair queue".
---

Repair `.knowledge` trust without assuming summaries are true.

1. Read `.knowledge/maintenance/routing_bundle.json` first.
2. Read the current doctor/quality report, trust report, freshness data, and repair queue:
   - `.knowledge/maintenance/quality_report.json`
   - `.knowledge/maintenance/trust_report.json`
   - `.knowledge/freshness.json`
   - `.knowledge/maintenance/stale_items.json`
   - `.knowledge/maintenance/repair_queue.json`
3. Classify every problem before editing:
   - generated artifact drift
   - missing or moved tracked files
   - stale module/wiki/evidence references
   - contradictory knowledge
   - low confidence or suspect module summaries
   - code/test behavior that must be rechecked
4. Prefer safe rebuilds first:
   - `node .knowledge/tools/sync-tracked.js`
   - `node .knowledge/tools/build-routing-bundle.js`
   - `node .knowledge/tools/build-search-index.js`
   - `node .knowledge/tools/doctor.js`
   - `node .knowledge/tools/restore-trust.js --safe --json`
5. Recertify a specific module only after its source, evidence, and tests have
   been rechecked: `node .knowledge/tools/recertify.js <module-id> --json`.
   Recertification is fail-closed and must never be replaced by a manual trust
   elevation.
6. For contested knowledge, read current source code, tests, and evidence before changing modules, wiki pages, or decisions.
7. After repairs, rerun sync/restore/doctor and report before/after quality score, trust status, stale count, and repair queue count.

Ask for explicit user confirmation before:

- deleting or untracking missing files
- editing source code
- editing tests
- manually raising trust, confidence, or evidence levels
- changing auth, payments, security, database, or other critical paths
- taking any action where the cause is uncertain

Never push, merge, or publish as part of this skill unless the user separately asks for release work.
