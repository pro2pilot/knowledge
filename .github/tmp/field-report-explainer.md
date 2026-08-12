# Field Reports: share real-world `.knowledge` experience without exposing sensitive information

If `.knowledge` is genuinely useful, that should be demonstrated not only by our internal tests, but by **real reports from real repositories**.

That is what the **Field Report** format is for.

A Field Report is not a marketing form designed to produce a flattering quote. It is a structured account of real `.knowledge` usage that helps answer three practical questions:

1. What was actually tested?
2. What proved useful in practice?
3. Where did the system help—and where did it not?

## Two ways to create a Field Report

### 1. Write it manually

Use the GitHub Discussion template, complete only the sections you actually observed, review every sentence, and publish the final report yourself.

This is the right option when you want full manual control.

### 2. Build it locally with `field-report`

The local workflow can collect observable facts, ask for the missing human context, and prepare a public draft without publishing anything on its own.

A typical run is:

```bash
node .knowledge/tools/field-report.js start --new --json
node .knowledge/tools/field-report.js questions --report-id=<id> --json
node .knowledge/tools/field-report.js ingest --report-id=<id> --answers=<path>
node .knowledge/tools/field-report.js results-ingest --report-id=<id> --results=<path>
node .knowledge/tools/field-report.js render --report-id=<id>
```

You then review the generated `public.md` and `redaction-report.json`. Approval binds the exact public title, body, semantic facts, routing snapshot, evidence, translation state, and redaction state. A meaningful edit invalidates that approval.

The goal is not for an agent to “publish something on its own.” The goal is to remove repetitive reporting work **without taking control away from you**.

## What a Field Report can collect

Depending on what is actually available, a report can include:

- a generalized project context and repository profile;
- the real engineering task and its evidence-bound outcome;
- build, test, migration, security, UI, documentation, or deployment rows;
- task routing and first-read observations;
- Doctor, Task Readiness, Inspector, verification inventory, and Repair-on-touch state;
- installation, first-run, upgrade, or workflow friction;
- the tester's judgments about usefulness, accuracy, speed, limitations, and whether they would keep using the system.

The report keeps **Verified engineering outcome** separate from **System state at collection**. A healthy `.knowledge` state is not treated as proof that the engineering task succeeded, and a successful test is not treated as proof of model accuracy.

A metric that was not observed does not need to be filled in. A formal benchmark is not required.

## How task results are bound to evidence

Structured task results can be added through `results-ingest`.

Every public `pass`, `warning`, or `fail` row must point to a safe regular evidence file under the repository or state root. The evidence is stored by relative path and SHA-256. Symlinks, hardlinks, path escapes, changed bytes, oversized files, secret-like paths, and conflicting automated status fail closed.

The repository snapshot is bound too. If source or evidence changes after the result was prepared, the report must be regenerated before approval or publication.

## Why this workflow is designed to be trustworthy

The obvious question is: **could this expose something sensitive?**

Field Report is designed so the answer is **no—when the workflow is used as intended**.

### Security and privacy boundaries

- collection and rendering happen **locally**;
- original answers remain local internal evidence;
- public output is built from allowlisted facts, then generalized, redacted, scanned, and approved;
- local paths, emails, credentials, tokens, private URLs, internal workspace names, and organization labels are removed or generalized;
- `--anonymize` can additionally hide repository and owner identity;
- non-English public prose uses an identity-attributed translation workflow and independent tester approval;
- unresolved high-severity privacy findings block approval and publication;
- a dirty Git worktree may be documented locally, but GitHub publication fails closed until the final snapshot is clean and current;
- no telemetry, upload, or network request occurs before explicit `publish`;
- the default `publish --dry-run` is an offline preview;
- real publication is a separate explicit action bound to the exact approved preview hash;
- unknown remote outcomes enter reconciliation instead of creating a duplicate Discussion.

In other words, Field Report is not a mechanism for exporting your project. It is a way to **share real-world experience safely, deliberately, and with an auditable evidence boundary**.

## What the public report contains

The publication-ready English report is organized around:

1. **Disclosure** — independent user report, maintainer dogfooding, internal QA, or controlled comparison.
2. **Project context** — generalized context without internal workspace or client labels.
3. **Repository profile** — filtered tracked/source file and content counts.
4. **Verified engineering outcome** — evidence-derived task results.
5. **System state at collection** — Doctor, readiness, routing, verification, and repair state.
6. **System observations** — explanations for noticeable values and limitations.
7. **Tester judgments** — what helped, what added overhead, and the final assessment.

Raw lifecycle counters are not promoted into unexplained marketing numbers. Routing estimates are described as deterministic local first-read estimates—not provider token usage, cost, speed, or accuracy.

## Why Field Reports matter to the project

Real user reports help us understand:

- where `.knowledge` works best;
- which repository types benefit most;
- what still needs improvement;
- which public claims are already justified—and which are still premature.

## What makes a useful Field Report

A strong Field Report is usually concise, specific, honest, grounded in observable facts, and unwilling to make the project sound better than the actual result.

A simple structure is enough:

- what the task was;
- where `.knowledge` was used;
- what helped;
- what did not help or required manual intervention;
- whether the additional trust layer was worth it;
- whether you would use it again.

## How to help right now

If you have already tried `.knowledge` on a repository, the most useful next step is to publish **your own Field Report** in the **Field Reports** category.

One honest, carefully prepared report is more valuable than ten general testimonials without evidence.

**[Open the Field Report form](https://github.com/pro2pilot/knowledge/discussions/new?category=field-reports)**
