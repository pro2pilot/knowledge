# Phase 0 Inventory

Generated: 2026-06-08
Agent: codex-archive-benchmark-update

This file records the pre-implementation reality check for the benchmark competitive update package. Current code and current tests remain authoritative.

## 1. Branch

- Source checkout branch: `feat/knowledge-3-2-0-inspector-team-mode`.
- The worktree already contains many local changes from the prior `.knowledge 3.2.0` release/Inspector pass.
- No GitHub push or commit is part of this task.

## 2. Existing Failures / Missing Gates

- `tools/self-test-team-inspector-json.js` was missing.
- `tools/release-gate.js` was missing.
- `tools/validate-source-deliverable.js` was missing.
- `benchmarks/` existed only as generated `results/`; it did not have the required harness layout.
- `npm run smoke` was missing in the adjacent Pro Inspector app.

## 3. Source Layout

- Core source checkout: `knowledge-3.2.0/`.
- Adjacent Pro Inspector app: `pro2pilot-inspector/`.
- Installed release artifact path: `dist/knowledge-v3.2.0.zip`.
- Source checkout becomes `.knowledge/` when packaged.

## 4. Release Artifact State

- Existing package/validation tooling exists:
  - `tools/package-release.js`
  - `tools/validate-release-artifact.js`
- Package exclusion rules already cover git metadata, temp dirs, runtime metrics, Inspector runtime data, flow logs, external memory runtime state and known local path leaks.
- New runtime reports from this pass must be excluded from the install artifact unless they are part of the benchmark harness itself.

## 5. Pro Inspector State

- The app is dependency-light and private-preview.
- It has lint/test/build/dev smoke scripts and structured demo data.
- It currently exposes governance screens and demo interactions, not production collaboration services.

## 6. Team Mode State

- Existing `tools/self-test-team-mode.js` covers worktrees, locks, events, state isolation and Inspector builds.
- The archive requires a dedicated JSON/NDJSON corruption test that parses every generated team/state JSON artifact.

## 7. Memory Provider State

- Mem0 OSS is the recommended optional provider.
- Pinecone is optional vector/cloud status.
- Graphiti and Zep are Pro/Enterprise provider contracts.
- Claude MEM is legacy-only advisory data.
- External memory cannot raise trust.

## 8. Benchmark Harness State

- Prior generated results covered a small proof pack.
- The archive requires a proper `benchmarks/` harness with suites, reports, reproduction files, redaction, claim rules and marketing proof packs.

## 9. Local Path Leaks

- Source files may contain intentional validator patterns for forbidden local path checks.
- Release artifact validation is the authoritative public-surface leak check.
- Runtime inventory and gate reports are maintenance outputs and must not ship in the install artifact.
