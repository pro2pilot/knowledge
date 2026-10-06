# Release Notes

## v3.4.3 - Covered recheck recovery

Fixes related stale-recheck closure, invalid-evidence rebinding, shared KVR
budget/telemetry accounting and durable file-fact coverage. Detects and safely
migrates the obsolete root gate, and authenticates extension signatures.
Also fixes Windows lock transitions, watcher shutdown, repeated updates,
fail-closed import, live Mem0 Unicode handling, and oversized Inspector requests.
See the [full change list](.release-notes/v3.4.3.md) and
[upgrade notes](docs/upgrade-3.4.3.md).

## v3.4.1 - Documentation and release-contract corrections

- Makes the integrated `agent-task` begin/finish workflow the only normal
  meaningful-task entrypoint in Quick Start. Direct `task-routing` commands
  are documented for advanced diagnostics and recovery.
- Replaces the hand-maintained update path inventory with
  `install-manifest.json`, the machine-checked system-path contract. This
  removes the obsolete `prompts/` path and keeps shipped paths aligned.
- Corrects the shipped configuration reference to `config.yaml`.
- Clarifies the stable v3.4.0 release notes without changing runtime behavior.

## v3.4.0 - Integrated task routing and evidence reuse

Adds the integrated `agent-task` begin/finish workflow so task-specific routing
is consumed before broad exploration and physical verification can be reused
for one exact safe Repair-on-touch closure. The release also binds finish to a
content-addressed first-read acknowledgement, rejects request/test-cwd path
escapes, and makes release packaging deterministic. It makes no comparative
speed, accuracy, error-rate, or model-token-savings claims.

## v3.3.0 - Safer local knowledge maintenance and task-scoped routing

Users of v3.2.11 can directly upgrade to v3.3.0.

- Agent integrations now coexist safely: Codex, OpenClaw, Hermes, and Devin share one runtime-neutral `AGENTS.md` managed block, while Devin and Windsurf use separate `.devin/rules/knowledge.rules` and `.windsurf/rules/knowledge.md` vendor files.
- Finding-specific repair and bounded Repair-on-touch preserve relevant
  verification while keeping unrelated maintenance visible.
- Doctor global health and task readiness are distinct outputs.
- Task-scoped routing reports a deterministic local first-read estimate as
  narrowing, overhead, neutral, or unavailable/not comparable; it is not
  provider-reported model-token usage.
- Field Report keeps local collection, translation, claim validation, approval, redaction, and optional publication state separate. Public drafts are English, retain an auditable question catalog, and now lead with an evidence-bound engineering-task table rather than internal counters. Task checks are content-addressed, overall outcome is derived from outcome-relevant rows, `.knowledge` health is shown separately, dirty final Git snapshots block GitHub publication, Discussion titles use a structured task title, and Repair-on-touch telemetry is classified as current, stale, invalid, or unavailable before any metrics are shown.
- Install, update, and release safety checks preserve curated knowledge and
  keep generated runtime state and maintainer material out of installed files.
- Installed agent integrations use the same four-state local-context estimate contract; maintainer benchmark and release-preparation tooling remain source-only.

The release contains focused approval, redaction, translation, publication
state, routing, repair, and update-safety regression coverage. It makes no
comparative speed, accuracy, error-rate, or model-token-savings claims.
