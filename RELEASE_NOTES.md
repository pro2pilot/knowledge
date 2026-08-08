# Release Notes

## v3.3.0 - Safer local knowledge maintenance and task-scoped routing

v3.3.0 is the direct public upgrade from v3.2.11.

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
