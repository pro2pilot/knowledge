# Changelog

## 3.3.0 — task-scoped trust, safe integrations, and publication-ready Field Reports

- Added task-scoped routing with a four-state deterministic local first-read
  comparison: narrowing, overhead, neutral, or unavailable/not comparable.
- Separated repository-wide Doctor health from task-scoped readiness.
- Added bounded Repair-on-touch, dedicated verification receipts, lifecycle
  history, and fail-closed recertification.
- Hardened contained locks, filesystem containment, update preservation, and
  coexistence across supported agent integrations.
- Added an English, tester-approved Field Report workflow with privacy-stable
  translation, claim safety, explicit publication approval, repository profile,
  and generalized internal organization labels.
- Added evidence-bound engineering task results for Field Report. Public task
  rows are SHA-256-bound to local evidence, the overall task outcome is derived
  from outcome-relevant checks, `.knowledge` system health is presented
  separately, dirty final Git snapshots block GitHub publication, and
  Repair-on-touch telemetry is classified as current, stale, invalid, or
  unavailable before metrics are shown.
- Added compatibility and release evidence for the 3.2.11 to 3.3.0 upgrade
  path. Comparative speed, accuracy, error-rate, cost, and model-token claims
  remain unsupported unless separately measured.

## 3.2.11 — Mem0 list normalization patch

- Normalized Mem0 2.x list results and stable record IDs.
- Hardened semantic JSON validation, release evidence freshness, update
  preservation, and shared-root behavior.
- Added evaluation latency and routing context-economy fields without turning
  local estimates into provider-token claims.

For older release history, use the versioned Git tags and release notes from the
maintainer repository.
