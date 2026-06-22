Use `.knowledge/` as the first trust/routing layer for this repository.

## First file to read

1. `.knowledge/maintenance/routing_bundle.json`

Then read only what the bundle says is relevant:

- `.knowledge/project_index.json`
- `.knowledge/maintenance/trust_report.json`
- `.knowledge/maintenance/handoff_summary.json`
- `.knowledge/wiki/index.md`
- relevant `.knowledge/modules/*.json`
- relevant source files and tests

## Source-of-truth order

1. Current code
2. Current tests
3. `.knowledge/evidence/*.json`
4. `.knowledge/modules/*.json`
5. `.knowledge/decisions.json`
6. `.knowledge/wiki/*.md`
7. `.knowledge/sessions/*`

Code beats summaries. Tests beat prose. Wiki is advisory unless backed by evidence and current code/tests.

## Trust rules

- `trusted`: usable for routing and limited planning; re-read code before critical behavior edits.
- `near_trusted`: usable after targeted code checks.
- `routing_trusted`: use only to choose files, modules, and boundaries.
- `advisory_only`: context only; never source of truth.
- `suspect`, `needs_recheck`, `low_confidence`: re-read source code before behavior claims or edits.

## Maintenance

After significant changes, run:

`node .knowledge/tools/sync-tracked.js`

When new files, wiki pages, or module summaries changed, also run:

`node .knowledge/tools/build-routing-bundle.js`
`node .knowledge/tools/build-search-index.js`
`node .knowledge/tools/doctor.js`
