# Task-scoped routing

`maintenance/routing_bundle.json` is a small workspace bootstrap, not a dump
of maintenance debt. Create an explicit task snapshot before doing scoped work:

```bash
node .knowledge/tools/task-routing.js create \
  --task="Audit and update only the Pro2Pilot knowledge website" \
  --task-class=content_consistency_audit \
  --scope-module=pro2pilot \
  --scope-path=pro2pilot/ --json
```

Routing snapshots are stored at `routing/tasks/<task_scope_hash>/snapshots/<snapshot_hash>/`.
Canonical workspace baselines are stored independently under
`routing/workspace-baselines/<baseline_hash>/`, and per-task comparison metrics
are stored under `routing/tasks/<task_scope_hash>/comparisons/<metrics_comparison_hash>/`.
Read `first-read.md` first; use `bundle.json` operationally and `decision.json`
only for selection details. `current.json` is the canonical three-way per-task
pointer to the routing snapshot, baseline, and comparison;
`manifest.json` is an immutable-history projection and `routing/index.json` is
a rebuildable discovery projection. There is deliberately no global active-task
pointer. Every create, refresh, status, list, Inspector build, and Field Report
read reconciles those projections from canonical `current.json`.

An explicit module or path scope is a hard boundary: routing may add only a
direct dependency, never a module selected by a generic task word. Each
snapshot is complete only after `complete.json` verifies all six routing
artifacts, including `continuation.json`. Baseline and comparison directories
have independent completion receipts. A partial directory is never made
current. A prepared transaction either leaves the old canonical current state
visible or is reconciled to the new one; readers do not accept a mixed pointer
state.

`flow release` refreshes the workspace bootstrap, maintenance debt, every
current task's canonical baseline/comparison, and the task index without
deleting immutable artifacts. It marks a task stale when its relevant
read-set changes; unrelated workspace debt remains aggregated in
`maintenance/maintenance_debt.json`.

The estimator implements `workspace_to_task_first_read_narrowing`. It compares
a canonical workspace-wide first read with the first read selected for one
explicit task. The scopes are intentionally different. This is an estimated
local content comparison (`bytes / 4`), not provider token telemetry, a model
speed measurement, a version comparison, or a same-scope experiment.
Publicly usable percentages require a complete canonical workspace baseline,
an explicit task scope, a current ready route, complete required sources,
accounted relevant Git state, and a valid current comparison. An invalid or
stale comparison is never displayed as `0 saved`.

Task bundles have a mode-specific inline path budget. Non-critical omissions
are recorded with reasons. High-risk overflow is placed in the verified
`continuation.json`, which is mandatory before a route is ready or eligible for
a public claim; it is never silently omitted. Current Git/PR diff and untracked
paths are merged with freshness, explicit scope, and direct-dependency paths,
with provenance for each path. Git porcelain is collected as NUL-delimited
`--porcelain=v1 -z --untracked-files=all`. Modified, added, deleted, renamed,
copied, untracked, and conflicted states remain distinct, including paths with
spaces or Unicode. A deleted, unsafe, unreadable, or missing required source
blocks readiness and comparative claim eligibility.

The claim-capable baseline is produced only by the built-in
`knowledge-workspace-first-read-recipe` `v1` and
`pro2pilot.workspace-baseline.canonical-generator`. Its versioned,
role-specific projections cover the workspace project index, module registry,
trust summary, source-of-truth policy, and bounded optional repair, handoff,
critical-path, and concurrency summaries. Unknown fields cannot inflate the
projection; malformed identities, duplicate modules, unsafe paths, missing
required roles, and size anomalies fail closed. Arbitrary files are not
measurement inputs. A custom file list remains diagnostic-only and always
reports `custom_baseline_not_claim_eligible`:

```bash
node .knowledge/tools/task-routing.js baseline --task-id=<sha256> --json
node .knowledge/tools/task-routing.js baseline --task-id=<sha256> --custom-baseline=<path> --json
```

The route must also be ready, fully accessible, and canonically current before
`claim_eligible=true`. Snapshot, baseline, and comparison identities are
independent, so a baseline-only change can persist a new comparison without
rewriting the routing snapshot. Snapshot identity explicitly excludes Git HEAD
and unrelated path counts, so unrelated commits do not churn a task route.
Legitimate unrelated workspace growth may change the workspace baseline and
comparison while leaving the task routing snapshot unchanged.

All public consumers use one mutually exclusive formatter. It reports exactly
one of narrowing, overhead, neutral, or an unavailable limitation, always with
the disclaimer that the value is a deterministic local estimate rather than
provider-reported model-token usage. Field Report, PR Summary, and Inspector
re-evaluate live routing state instead of publishing a raw stored assessment.

## Canonical baseline hardening

Workspace-narrowing percentages are claim-eligible only when every canonical
baseline role passes its role-specific semantic contract. The project index,
module registry, trust summary, repair summary, handoff summary, critical-path
summary, source-of-truth policy, and concurrency policy are projected through
bounded fields and bounded collections. Module identifiers, dependency
references, trust buckets, status values, counts, and cross-references must be
coherent. Unknown fields are ignored, but oversized known fields, ghost module
IDs, overlapping trust buckets, invalid enum values, and contradictory counters
make the comparison unavailable rather than inflating the estimate.

Role sources are resolved with an explicit root policy. Curated roles come from
the project `.knowledge` root. Runtime roles such as trust, repair, handoff, and
generated critical-path state prefer the active workspace `stateRoot` in team
mode. Every physical read verifies lexical and real-path containment and rejects
parent symlinks, junctions, and reparse-point escapes. The selected physical
root and raw source digest are recorded in baseline provenance.
