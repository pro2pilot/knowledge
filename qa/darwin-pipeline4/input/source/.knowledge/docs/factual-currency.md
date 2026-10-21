# Factual currency overlays

Factual currency is an opt-in, review-bound projection of selected current
claims. It can mark scoped facts as `routing_trusted`; it does not certify
application safety, close lifecycle findings, or rewrite the stale-items or
repair-queue ledgers. The output keeps open application risks and terminal
protected findings visible as unassessed. Doctor's legacy joint `quality_score`
is not replaced: currency facts and application assurance are separate
projections, and operational unknown-history remains in the legacy score.

The current CLI accepts only `knowledge-currency-request.v3` child requests.
Local v1/v2 prototype receipts are not v3 evidence. Automatic migration,
deletion, and index reset for those artifacts are not implemented. Existing
recording-path overrides do not automatically bypass the currency privacy
check. Use the exact CLI check from the checkout that contains the currency
runtime; a general central-install integration is not promised. A disjoint
state root is supported by the runtime's tests, but that does not extend the
CLI integration promise.

## Supported commands

Run these from the target repository root. Paths are canonical repository-
relative files.

```bash
node .knowledge/tools/knowledge-currency.js status
node .knowledge/tools/knowledge-currency.js prepare --request=.knowledge/evidence/currency-request.json
node .knowledge/tools/knowledge-currency.js check --request=.knowledge/evidence/currency-request.json --scope=<scope-sha256> --risk-scope=<protected-risks-sha256>
node .knowledge/tools/knowledge-currency.js prepare-batch --request=.knowledge/evidence/currency-batch.json
node .knowledge/tools/knowledge-currency.js check-batch --request=.knowledge/evidence/currency-batch.json
node .knowledge/tools/knowledge-currency.js issue-batch --request=.knowledge/evidence/currency-batch.json --execution=<KVE-id> --verification-result=native-verify-result.json
```

`prepare` computes the reviewed scope and hashes. `check` confirms those exact
scope and protected-risk hashes are still current; it does not issue a receipt.
Use `prepare-batch` before review and `check-batch` after review. Issuance is
available only through `issue-batch`, with one or more native passing KVE IDs
and their exact `verification_acceptances` from the native verification JSON
result. Store that JSON as `native-verify-result.json` for the command above.
The task workflow carries this acceptance automatically. Legacy or partial
command-only records cannot authorize new issuance.
There is no single-request issuance command. Even one child request must be
wrapped in a batch.

The direct `check` command requires the exact `--scope` and `--risk-scope`
values returned by `prepare`. The angle-bracket values above are placeholders,
not literal strings. Batch commands accept a request path; `issue-batch` also
accepts one or more comma-separated native execution IDs shown in its result
records. Replace placeholders before running commands.

## v3 child request

Each child file uses this structure. The example is a shape only: replace every
placeholder with current repository evidence and a claim that the reviewer can
verify. Do not include execution IDs in the immutable child request.

```json
{
  "schema_version": "knowledge-currency-request.v3",
  "author_id": "<stable author label>",
  "task_id": "<task label>",
  "session_id": "<session label>",
  "source_files": ["src/example.js", ".knowledge/evidence/example.json"],
  "claims": [
    {
      "claim_id": "example-claim",
      "path": "src/example.js",
      "module_id": "example_module",
      "description": "<specific current fact supported by source>",
      "evidence_paths": ["src/example.js", ".knowledge/evidence/example.json"],
      "provenance": [
        { "path": ".knowledge/evidence/example.json", "pointer": "/claims/0" }
      ]
    }
  ],
  "modules": [
    { "module_id": "example_module", "card_path": ".knowledge/modules/example_module.json" }
  ],
  "provenance_paths": [],
  "review_path": ".knowledge/evidence/example-review.json",
  "supersedes": []
}
```

`source_files` names the files asserted by the request. Each claim needs a
source path, a nonempty set of evidence paths, and provenance references whose
JSON pointers resolve to the claim description and source. A module card must
match the physical module registry and cover its declared required paths; the
scope also binds typed ownership paths and conditional dependencies from that
registry. The runtime adds its exact shared authority file pins and calculates
the complete scoped protected-risk inventory. Include the required scope files
and computed pins in the later native verification source set.

## Review record

Run `prepare` for the child and use its `scope_sha256`,
`protected_risks_sha256`, claim IDs, claim hashes and source/supporting pins to
prepare a separate review file. Its schema is `knowledge-currency-review.v1`:

```json
{
  "schema_version": "knowledge-currency-review.v1",
  "author_id": "<same author label as request>",
  "reviewer_id": "<different reviewer label>",
  "reviewed_at": "<ISO-8601 timestamp>",
  "scope_sha256": "<prepare output>",
  "protected_risks_sha256": "<prepare output>",
  "result": "confirmed",
  "method": "source_and_claim_review",
  "routing_only": true,
  "security_certificate": false,
  "claims": [
    {
      "claim_id": "example-claim",
      "claim_sha256": "<prepare output>",
      "result": "confirmed",
      "notes": "<substantive explanation of the checked evidence>",
      "checked_paths": [
        "src/example.js",
        ".knowledge/evidence/example.json",
        ".knowledge/modules/example_module.json"
      ]
    }
  ]
}
```

The reviewer record must cover each claim's source, evidence and provenance
paths, plus module required paths. Different author and reviewer IDs are a
separation-of-labels check. They are not cryptographic proof of independent
human review or identity. A review does not certify security or application
assurance.

## Exact-input batch

After the child request and review files are finalized, calculate the child
request file's SHA-256 and create a batch request that binds its exact bytes.
The batch schema is `knowledge-currency-batch-request.v1`:

```json
{
  "schema_version": "knowledge-currency-batch-request.v1",
  "task_id": "<same task label as child>",
  "session_id": "<same session label as child>",
  "requests": [
    {
      "path": ".knowledge/evidence/currency-request.json",
      "sha256": "<64 lowercase hex characters for the exact child file bytes>"
    }
  ],
  "supersedes": []
}
```

For this example, calculate the request-file hash with the local Node runtime:

```bash
node -e "const fs=require('fs'),c=require('crypto'); console.log(c.createHash('sha256').update(fs.readFileSync(process.argv[1])).digest('hex'))" .knowledge/evidence/currency-request.json
```

Use that exact lowercase digest in the batch `requests[0].sha256` field.

This one-entry `requests` array is the supported single-unit recipe: prepare
and review one v3 child, pin its exact bytes in this batch, then use the same
batch for checking and issuance. For a multi-child batch, each child must have
the same task and session IDs, a unique request and review path, and disjoint
ownership of findings, claimed files and modules. The batch-level `supersedes`
array must equal the union of the child requests' `supersedes` IDs. A
supersession must preserve prior factual file and module coverage. Unrelated
active receipts remain in the projection.

Run `prepare-batch`, review its computed binding, then run `check-batch` after
the review file exists. The batch and every child request's exact bytes must
also be included in the native KVE before/after source snapshots. The KVE set
must cover every computed source/supporting pin and the review file. The
effective receipt time is the latest included KVE timestamp; retries using the
same exact batch and KVE inputs therefore reconstruct deterministic receipt
IDs.

### Issuing from `agent-task finish`

The recommended task workflow supports a batch path in the finish request:

For this workflow, both child and batch `task_id` must equal
`begin.route.task_scope_hash`, and `session_id` must equal `begin.workflow_id`.
Use the values returned by that exact begin call, rather than arbitrary labels.

```json
{
  "schema_version": "knowledge-agent-task-finish-request.v1",
  "route_first_read_sha256": "<begin output>",
  "changed_files": ["src/example.js"],
  "source_files": [
    "src/example.js",
    "tests/example.test.js",
    ".knowledge/evidence/example.json",
    ".knowledge/evidence/example-review.json",
    ".knowledge/evidence/currency-request.json",
    ".knowledge/evidence/currency-batch.json"
  ],
  "tests_to_run": [
    { "argv": ["node", "tests/example.test.js"], "cwd": ".", "timeout_ms": 120000 }
  ],
  "currency_updates": ".knowledge/evidence/currency-batch.json"
}
```

Add every computed pin returned by batch preparation to `source_files`,
including authority files and the review file. Finish adds the native
`check-batch` invocation to the physical verification batch and, after
verification passes, issues factual currency using those same KVE records.
It executes one verification batch and factual mode creates no KVR. The
`currency_updates` option is opt-in and must be one canonical relative path to
the batch request.

Alternatively, after obtaining native KVE IDs that contain the exact batch,
child and scope inputs, invoke the documented `issue-batch` command above.
Do not substitute ordinary test success or hand-written IDs for native KVE
records.

## Maintenance and boundaries

The overlay writes immutable currency receipts, their index and a batch
operation record. It never edits the raw stale-items or repair-queue ledger and
never closes findings. The `knowledge_currency` facts projection remains
separate from the `application_assurance` projection. Protected risks, including
terminal rows, are bound into scope and reported as open or not assessed; they
cannot be cleared by factual currency. Neither projection resets Doctor's
legacy joint quality score or removes operational unknown-history from it.

In `agent-task finish`, `knowledge_maintenance` reports `status`,
`chat_notice`, `next_action`, pending/deferred lifecycle IDs and any currency
blockers separately from the primary engineering verification. A currency
update does not turn a primary failure into success, and a primary pass does
not renew factual claims by itself. If `knowledge_maintenance.chat_notice` is
present, relay it to the user immediately in their preferred language. Do not
assume an arbitrary runner provides a chat-delivery hook. A deferral requires
exact currently eligible lifecycle IDs and a reason; protected risks and
globally blocked currency state cannot be deferred.

`sync-tracked` preserves ignored module-card bytes and non-lifecycle legacy
rows by default. `--preserve-history` explicitly requests that same policy;
malformed, negative or duplicated preservation flags fail before mutation.
There is no destructive history-cleanup option. Obsolete generated tracking
may still leave the active registry; preserved history is reported as cleanup
debt, never as verification or closure evidence.

The stale-items/repair-queue pair is committed with exact byte guards in one
JSON transaction. This does not make every other derived sync output part of
that transaction or certify historical outcomes.

## Current RC5 audit: complete verification read set

When a signed batch acceptance is reused, admission authenticates every KVE
command record in that batch, including siblings not directly selected by
the currency child. The transaction now retains physical compare-and-swap
guards for every record read and the KVF finalization. A sibling change
between admission and commit rejects issuance with `transaction_guard_drift`.
The failed transaction must not issue a receipt or currency index, and raw
lifecycle records remain unchanged. Portable signed-data regressions exercise
this reader/transaction contract; they do not establish Linux native command
execution or replace a fresh Windows producer test. See the
[current audit](audit-3.4.4-rc5-mechanisms.md).
