---
name: kb-field-report
description: Prepare an English, tester-approved Field Report from real .knowledge use without inventing evidence or publishing automatically.
---

Use the Field Report CLI as a progressive-disclosure interview.

1. Start with explicit `--language=<source-bcp47>`, or resume with
   `node .knowledge/tools/field-report.js questions --json`. Public output is
   fixed to English; do not select another public language. If the source was
   deliberately set to `auto`, resolve it once through
   `translation-export --language=<source-bcp47>`.
2. Ask only the returned questions, including the report relationship
   (independent user, first-party maintainer dogfooding, internal QA, or
   controlled comparison). Preserve negative and uncertain answers; ask at most
   one concrete follow-up when evidence is vague. Use generalized descriptions
   instead of internal workspace, department, client, or team names.
3. Save answers as JSON and run
   `ingest --report-id=<id> --answers=<path>`. For a non-English source, use
   `translation-export`. Translate only the privacy-stable exported answers,
   preserve both `original_hash` and `exported_answers_hash`, require complete
   translator identity (`provider`, `model`, `actor`) and all safety
   attestations, then use `translation-ingest`.
4. Run `translation-approve --yes --tester-actor=<independent-reviewer>` only
   after that tester reviews the English translation. The reviewer must not be
   the translator. Then render.
5. Check that `public.md` contains the disclosure, repository profile, verified
   outcome table, metric explanations, English prose, and no internal
   organization labels. Show the tester `public.md` and the redaction status.
   Do not approve on the tester's behalf.
6. Run `approve --report-id=<id> --yes --tester-actor=<github-login>` only after
   the tester explicitly approves that exact draft.
7. On a separate request, create an actor-bound preview with
   `publish --dry-run --yes --tester-actor=<github-login>`. Actual publication
   requires another explicit request and
   `--confirm-preview=<exact-preview-hash>`.

Never infer usefulness, accuracy, speed, publication permission, or external
reuse from Doctor scores or test results. Doctor is repository health, lifecycle
queue rows are not current-blocker counts, verification receipts are evidence
volume, and routing context numbers are deterministic local estimates rather
than provider-reported token usage. A language, privacy, or high-severity
redaction finding blocks approval and publication.

Publication has no republish override. If its state is `publishing` or
`reconciliation_required`, keep the durable journal and run the same confirmed
final-publication command so the exact idempotency marker is reconciled first.
Never start a fresh create or edit the bound artifacts to escape
reconciliation.
