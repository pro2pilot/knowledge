# Competitive 10/10 Baseline Inventory

Generated: 2026-06-07
Agent: codex-goal-10-of-10

This inventory captures the starting state for the competitive 10/10 pass. Current code and tests remain the source of truth; this file is only a repair checklist.

## Required Strategy Docs

- `docs/strategy/` was missing in the source checkout at baseline.
- The supplied planning package contains strategy files `00_INDEX.md` through `10_current_decision_record.md`; these need to be copied into source docs so the release artifact carries the positioning decision.

## Core Release Gaps

- `tools/pr-impact.js` was missing.
- `benchmarks/` was missing.
- `package.json` had self-tests for install policy, team mode, memory providers, external memory and Inspector UI, but no PR Impact or benchmark scripts.

## Free Inspector Gaps

- Existing tab labels included `Trust`, `Stale Items`, and `PR Summary`.
- Competitive spec requires `Trust Ledger`, `Freshness`, and `PR Impact Preview`.
- Existing Command Center labels included `Flow Import`, `Flow Release`, `Memory Provider Status`, and `Mem0 Preview`.
- Competitive spec requires exact action labels: Run Doctor, Refresh Release, Build Inspector, Search, Generate PR Summary, Review PR Impact, Export Debug Bundle, Team Status, Memory Status, Preview Mem0, Export Pro Snapshot.
- Inspector UI self-test did not parse `inspector/data.json` after team-mode Inspector generation.

## Pro Inspector Gaps

- Navigation included `Team Mode` and `Policy Packs`; competitive spec requires `Team Spaces` and `Policy Gates`.
- `Analytics` screen was missing.
- Snapshot import was not implemented as an interactive Pro capability.
- Repair Board displayed static cards without tested state transitions.
- Additional schemas required by the competitive plan were missing: `team-spaces.schema.json`, `policy-gates.schema.json`, `audit-event.schema.json`.

## Benchmark / Proof Pack Gaps

- No runnable benchmark proof pack existed at baseline.
- Required minimum coverage: B1, B2, B3, B4, B8, B10, B11.
- Required results files were missing: `benchmarks/results/runs.jsonl`, `summary.md`, `summary.json`, `metrics.csv`, and `marketing/claim_evidence_map.md`.

## Memory Provider Inventory

- Mem0 OSS and Pinecone provider surfaces existed.
- Graphiti and Zep appeared as Pro/Enterprise provider cards.
- Claude MEM references remained only as legacy/deprecation docs and detection paths, which is allowed by the plan.

## Release Artifact Risk

- Runtime/maintenance inventory files should not ship in the clean release artifact.
- New docs, benchmarks, and tests must avoid local path leaks and workspace-name leaks checked by `tools/validate-release-artifact.js`.
