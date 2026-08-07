# Field Report

Field Report is a semi-automatic, agent-assisted account of real `.knowledge`
use, not a benchmark. Local facts come from runtime artifacts; usefulness,
accuracy, speed, limitations, publication permission, and reuse permission
remain the tester's judgments.

## Public-output contract

- The tester may answer in any language. The source language defaults to `auto` and is resolved only after complete answers are available.
- The publication-ready report is always English.
- Non-English answers require an identity-attributed, agent-assisted
  translation and approval by an independent tester/reviewer.
- Original answers remain stored unchanged as internal evidence.
- Public output begins with a report-type disclosure: independent user,
  first-party maintainer dogfooding, internal QA, or controlled comparison.
- Internal workspace, department, team, organization, and client labels are
  generalized. Public output is built from allowlisted facts, then generalized,
  redacted, scanned, and approved.
- Numeric facts are public only when the renderer can provide a deterministic
  interpretation. Raw lifecycle counters remain internal unless their meaning
  is explained.

A non-English `--public-language` is rejected. The canonical public language is
`en`; `--public-language=en` may be supplied for clarity but is not required.

## Safe workflow

```bash
node .knowledge/tools/field-report.js start --new --json
node .knowledge/tools/field-report.js questions --report-id=<id> --json
node .knowledge/tools/field-report.js ingest --report-id=<id> --answers=<path>
node .knowledge/tools/field-report.js render --report-id=<id>
node .knowledge/tools/field-report.js approve --report-id=<id> --yes --tester-actor=<github-login>
node .knowledge/tools/field-report.js publish --report-id=<id> --yes --dry-run --tester-actor=<github-login>
```

Ask only the questions returned by `questions --json`. Show the tester
`public.md` and `redaction-report.json` before approval. Approval binds the exact
title/body, semantic facts, routing snapshot, canonical baseline, metrics
comparison, live-input digest, readiness, continuation, translation, and
redaction identities. A semantic edit invalidates approval; collection
timestamps and other excluded runtime metadata do not.

English free-text answers are resolved to `en` conservatively after complete ingest. If the source remains `auto`, resolve it once with:

```bash
node .knowledge/tools/field-report.js translation-export --report-id=<id> --language=<source-bcp47> --json
```

When the source language is not English, run:

```bash
node .knowledge/tools/field-report.js translation-export --report-id=<id> --json
node .knowledge/tools/field-report.js translation-ingest --report-id=<id> --answers=<translation.json>
node .knowledge/tools/field-report.js translation-approve --report-id=<id> --yes --tester-actor=<independent-reviewer>
node .knowledge/tools/field-report.js render --report-id=<id>
```

The translation export is privacy-stable: internal organization labels and
medium-severity private values are generalized or redacted before they leave the
workspace, while unresolved high-severity findings block export. The translation
response must identify `provider`, `model`, and `actor`, retain both the immutable
`original_hash` and exact `exported_answers_hash`, and attest that it adds no
facts, does not soften negative answers, and preserves uncertainty. The
approving tester/reviewer must be explicitly identified and must not be the
translator. Ingest and approval revalidate the exact privacy-stable export,
identity, hashes, attestations, and English public prose.

Actual GitHub publication is a second explicit action without `--dry-run` and
with `--confirm-preview=<exact-preview-hash>`. The default target is
`pro2pilot/knowledge`, category `field-reports`. Before the remote create, a
write-ahead journal binds the report, actor, target, approved content, preview,
and idempotency marker. If the outcome is unknown, the report enters
`reconciliation_required`; the next final-publish attempt searches for that
exact marker before it can create anything. Ambiguous matches or a content-hash
mismatch fail closed and never create another Discussion. There is no republish
override, and a published report cannot be published again.

If automated publication is unavailable, copy `discussion-title.txt` and
`discussion-body.md` into the GitHub Discussion form manually. The bundled
schema is pinned to the current form field IDs and dropdown labels; contract
drift fails closed before the interview starts.

## Automatic facts and public rendering

The facts file uses `knowledge-field-report-facts.v2`. Each fact carries its
value, kind (`observed`, `derived`, or `unavailable`), source, schema path,
collection time, confidence, and warning.

The public report contains these deterministic sections. `questions.json` retains an audit catalog of every required prompt and whether it was answered, even after no follow-up questions remain.


1. **Disclosure** — the tester's relationship to `.knowledge`.
2. **Project context** — generalized context plus standalone/team repository
   scope. Functional modules are never treated as separate projects.
3. **Repository profile** — tracked file/content and source file/content counts.
4. **Verified outcome** — understandable task, Doctor, wiki, task-readiness,
   verification, repair, and eligible routing outcomes.
5. **System observations** — deterministic explanations for noticeable values.
6. **Tester judgments** — what helped, what added overhead, limitations,
   comparison, and final assessment.

### Repository profile

The collector prefers a Git-index snapshot and current working-tree file sizes. It records whether tracked or untracked changes made the snapshot dirty; untracked files affect the cleanliness label but are not added to the size totals.
If Git inventory is unavailable, it uses a filtered filesystem fallback. The
profile excludes `.git`, `.knowledge`, dependencies, builds, caches, coverage,
temporary/release/QA directories, `.env` files other than examples, and
secret/credential-like filenames. It does not report full disk usage or read
excluded secret contents.

### Explained metrics

The renderer does not place raw values such as repair-queue rows or stale
artifacts in the main outcome table without interpretation. Examples:

- Doctor is repository-health evidence, not model accuracy.
- Repair-queue rows may include historical or inactive lifecycle records and
  are not the number of current blockers.
- Stale artifacts are freshness/recheck signals, not failed tasks.
- Verification receipt count is evidence volume, not a success rate.
- Functional module count is not repository/project count.
- A routing estimate is a deterministic local first-read estimate, not
  provider-reported token usage, cost, accuracy, or speed.
- Embedded package metadata may identify a release-candidate build such as `3.3.0 RC57`; it is not the artifact SHA.

When exactly one task snapshot is bound to the report, Field Report records its
scope and source, workspace/task module and path counts, unrelated-path
narrowing, canonical workspace-baseline identity, required-source state,
comparison validity, claim eligibility, and measurement kind. An ineligible,
non-comparable, or stale route does not block the report; the public output
states the limitation and omits an unsupported percentage.

The comparison kind is `workspace_to_task_first_read_narrowing`: a canonical
workspace-wide first read versus the task-scoped first read for the selected
task. It is intentionally not a same-scope, release-version, provider-token,
speed, accuracy, or error-rate comparison. The formatter exposes exactly one
state: narrowing, overhead, neutral, or unavailable/not comparable.

Before publication, a deterministic claim-safety gate blocks free-text assertions that conflict with observed candidate identity or claim routing effects, provider-token/cost savings, accuracy improvement, or speed improvement without the required supporting facts. Explicit uncertainty and negative statements remain allowed.

Enum identifiers are converted to labels only while rendering typed fields.
Free-form tester text otherwise remains semantically unchanged, except for
required privacy redaction, internal-organization generalization, and the
English-publication gate.

## Evidence rules

- Agents must not invent answers, make negative answers more positive, or
  approve on the tester's behalf.
- Ask at most one useful follow-up when an answer is vague or lacks evidence.
- Preserve the tester's original language and meaning. Translation is
  agent-assisted, identity-attributed, and independently approved.
- `measured` speed derives a signed percentage from comparable durations:
  positive is faster, negative is slower.
- `estimated_from_comparable_tasks` and `general_observation` are not
  measurements.
- Accuracy is never inferred from Doctor score, test success, or flow duration.
- GitHub publication permission and external-reuse permission are separate
  required answers.
- First-party dogfooding must not be presented as an independent testimonial.

## Privacy and storage

Artifacts live under
`<stateRoot>/reports/field-reports/<report-id>/`: original and public answers,
facts, provenance, internal/public Markdown, redaction report, Discussion
payload, and publication record. Writes are atomic and report-specific locks
prevent concurrent mutation.

Before rendering, internal organization labels, local paths, emails,
credentials, tokens, and private URLs are generalized or redacted. Substantial
non-English publication prose and high-severity unresolved secrets block
approval and publication. `--anonymize` additionally hides repository identity
and owner. No telemetry, upload, or network request happens before explicit
`publish`. By default `--dry-run` is an offline preview and never creates a
Discussion; add `--verify-remote` only when a live GitHub
viewer/repository/category check is intended.

The CLI accepts the shared context flags, including `--system-root`,
`--target-root`, `--project-knowledge-root`, `--state-root`, and team-mode
flags. Repeat the same flags on noninteractive follow-up commands, or provide
the equivalent `KNOWLEDGE_*` environment variables, so report state remains in
the intended isolated workspace.

`field-report --help` exits successfully before context resolution and has no
filesystem or network side effects. An unknown flag exits with code 2 before
context resolution and likewise leaves report state untouched.

To remove an unfinished report, first confirm the exact report ID and delete
only that report directory. Runtime report directories are excluded from
release packages and ignored by the installed Git policy.

## Agent protocol

When a user asks for a Field Report, resolve the source language, keep public
output fixed to English, run `questions --json`, ask only the returned
questions, and ingest the answers. If translation is required, export its
contract, retain translator identity and attestations, and stop for an
independent tester review before rendering. Show the public draft and redaction
report, then stop for explicit approval. Create a publication preview only on
request; publish only after a separate explicit request that supplies the exact
preview hash. If reconciliation is required, preserve the journal and reconcile
it rather than starting a fresh publication.
