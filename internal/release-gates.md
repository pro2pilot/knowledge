# Release Gates

No public claim is allowed without local evidence.
The canonical successful `release-gate-report.v2` status is `pass`; `passed`
is not accepted by benchmark GATE-00.

## Canonical Local Release Candidate Gate

```bash
node tools/release-gate.js --mode release --memory-battle-report <mem0-fastembed-results.json> --json
```

This command removes the stale candidate `dist/knowledge-v<package.version>.zip`
before packaging, builds a fresh artifact, validates it, runs source self-tests,
writes full step logs, records SHA-256 evidence, and performs clean-install
smoke. Steps that depend on a failed package or validation step are skipped so
the report cannot accidentally prove an older artifact.

Conformance-report generation is also fail-closed. The generator is invoked
once; an exception or invalid generator result adds
`generate-conformance-report` as a failed step, changes the final report status
to `fail`, and produces a non-zero release-gate exit.

`release` requires a current Mem0/FastEmbed battle report. `full` validates the
same report when `--memory-battle-report` or
`KNOWLEDGE_MEMORY_BATTLE_REPORT` is supplied, but remains runnable without it
for compatibility PRs that do not carry release-only memory evidence. The report
must include command-level semantic outcomes, current source hashes, useful
live add/search/recall/list evidence, a working lock failure injection, clean
UTF-8/Unicode paths, and zero unexpected semantic failures. OpenAI quota blocks
are reported separately and never presented as a successful live recall.

On a clean release-source checkout, `full` and `release` bootstrap
`.knowledge/project_index.json` with the absolute
`tools/ingest-existing-project.js --merge --no-sync` entrypoint before source
self-tests. This does not weaken `doctor`, does not use `flow import`, and runs
after the candidate artifact was packaged.

## Modes

```bash
node tools/release-gate.js --mode quick --json
node tools/release-gate.js --mode full --json
node tools/release-gate.js --mode full --memory-battle-report <mem0-fastembed-results.json> --json
node tools/release-gate.js --mode release --memory-battle-report <mem0-fastembed-results.json> --json
node tools/release-gate.js --mode post-release --tag vX.Y.Z --repo pro2pilot/knowledge --expected-owner pro2pilot --json
```

| Mode | When | Scope |
|---|---|---|
| `quick` | PR and tight iteration | impact classifier, offline public-copy consistency, package, artifact validation, supply-chain metadata, targeted Mem0/Inspector checks |
| `full` | compatibility-impacting PR | quick plus conformance, optional semantic memory battle evidence when supplied, source bootstrap/self-tests, evaluation metrics, and clean-install smoke |
| `release` | before tag/upload | full plus required semantic memory battle evidence, source deliverable validation, SHA/log evidence, and non-fail-fast failure map |
| `post-release` | after GitHub release upload | download live GitHub asset, validate it, compute SHA-256, and run install smoke |

The release-candidate workflow requires a repository-relative path to a
sanitized, source-only memory battle report and passes it through
`KNOWLEDGE_MEMORY_BATTLE_REPORT`. Do not commit raw memory contents, provider
state, credentials, or user data as release evidence.

## Pull-request routing

The `PR Fast` job keeps a stable job identifier for branch protection, but its
gate mode comes from `classify-release-impact.js`; it does not hard-code
`quick`. Documentation-only changes require the `quick` capability and the
offline `public-consistency` capability. Compatibility or release-infrastructure
changes require `full` and `conformance-suite`, so the routed job runs
`release-gate.js --mode full`. An unknown required capability fails closed.

The separate compatibility workflow remains a platform matrix. Its path
triggers include release workflows and `internal/**`, so a routing or
release-governance change cannot silently bypass compatibility coverage.

`tools/check-public-consistency.js` checks the current package version, scoped
release note, current public headings, current artifact references, and
install-manifest version locally. It performs no network requests and reports
external website/social channels as `not_evaluated`. It is maintainer-only:
the public ZIP must omit it, and artifact validation rejects an injected copy.

## SPARK v2 Evidence Contract

`knowledge-spark-battle.v2` is fail-closed. Every functional `commands[]` item
has a required, unique `command_id`, exactly one declared coverage owner, and a
coverage-specific command. It points to a contained, non-empty regular JSON
trace using `log_path` and `log_sha256`. The trace schema is
`knowledge-spark-command-trace.v1` and must exactly bind the command id, case,
scenario, coverage area, arm, repeat, command, exit, duration, semantic
outcome, source fingerprint, and canonical observation. Observation hashes are
recomputed from canonical JSON; a self-reported hash is not trusted.

Both adjacent comparative benchmark files use the same top-level
`oracle_path` and `oracle_sha256`. The contained
`knowledge-comparative-oracle.v1` sidecar binds a hashed
`knowledge-comparative-preregistration.v1` file. Every unique case binds its
registered scenario, contained source path and SHA-256, contained per-case
`knowledge-comparative-oracle-evidence.v1` record, expected hash, and canonical
observation. Benchmark rows also require globally unique per-arm `command_id`
values, exact row-to-trace binding, and exact case/repeat parity between arms.
Trace paths and command identifiers cannot be reused across assisted and
baseline arms.

The sidecar is an integrity and provenance envelope: it detects mutation,
substitution, missing coverage, generic trace reuse, and inconsistent claims.
It does **not** establish that the preregistered expected answer is semantically
correct. Independent review of case design and expected answers remains a
separate research responsibility.

This is an intentional backwards-incompatible evidence tightening. Older v2
reports that only declare semantic booleans, non-JSON logs, relative paths
without hashes, generic reused traces, or unbound oracle claims are rejected
and must be regenerated.

## Debug Individual Failed Steps

Run these only when `release-gate.js` reports a failing step:

```bash
node tools/self-test-inspector-launcher.js --json
node tools/self-test-inspector-actions.js --json
node tools/self-test-inspector-next-actions.js
node tools/self-test-agent-activity.js --json
node tools/self-test-safe-queue.js --json
node tools/self-test-agent-footer.js --json
node tools/self-test-restore-trust.js --json
node tools/self-test-install-policy.js
node tools/self-test-memory-providers.js
node tools/self-test-external-memory.js
node tools/check-public-consistency.js --json
node tools/validate-sbom.js --json
node tools/validate-third-party-notices.js --json
node tools/validate-source-deliverable.js --profile source_release --json
```

## Post-Publish Live Asset Gate

After uploading the GitHub release asset:

```bash
VERSION="$(node -p "require('./package.json').version")"
node tools/release-gate.js --mode post-release --tag "v${VERSION}" --repo pro2pilot/knowledge --expected-owner pro2pilot --json
```

The post-release mode downloads `knowledge-v${VERSION}.zip` from
`pro2pilot/knowledge`, validates the downloaded artifact, computes SHA-256, and
runs clean-install smoke against the live asset. It blocks when the GitHub
release author, asset uploader, or available asset digest do not match the
expected Pro2Pilot release identity.

## Required Release Evidence

- release gate report
- artifact SHA-256
- full step logs under `.qa-tmp/release-gate/logs/`
- live GitHub asset proof after upload
- conformance install smoke report
- current semantic Mem0/FastEmbed battle report
- evaluation report with trust-layer latency and context-economy estimates
- public consistency report when public copy changed
- identity/attribution proof for the GitHub release author/uploader
