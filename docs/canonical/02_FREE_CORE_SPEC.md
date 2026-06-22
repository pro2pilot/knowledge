# 02 — Free Core spec

## Role

Free Core is the open, embeddable `.knowledge` system:

```txt
file layout + schemas + CLI + trust/freshness/repair engine + routing/evidence artifacts + JSON reports
```

Free Core must be useful without Inspector and without Pro.

## Must be free

| Capability | Requirement |
|---|---|
| File layout | `.knowledge/` structure, schemas and conventions. |
| CLI with `--json` | All core commands scriptable by humans, agents and apps. |
| Routing bundle | First-read path and source-of-truth order. |
| Evidence model | Evidence files and evidence coverage data. |
| Trust/Freshness engine | Trusted/stale/suspect/advisory states. |
| Repair queue data | Actionable repair items as JSON/Markdown. |
| Source-of-truth rules | Code/tests/evidence outrank summaries and memory. |
| Basic PR summary | Local PR summary output. |
| Basic PR Impact data | Changed files → modules → trust/freshness/criticality baseline. |
| Search/Wiki graph | Local scoped search and knowledge graph data. |
| Memory provider status | Mem0/Pinecone status as advisory-only. |
| Agent report footer contract | Standard footer fields and settings. |
| Restore Trust safe action | Safe recompute/report workflow. |
| Basic Agent Activity | Agent identity, sessions, reports, locks and handoff metadata. |
| Safe Queue primitives | Lock zones and waiting state. |
| Basic Git policy checks | Detect staged runtime/generated files. |
| Export Debug Bundle | Redacted local support/export bundle. |
| Export Pro Snapshot | Sanitized bridge to future Pro. |
| Embedding contracts | Files, CLI, API and event contracts for other apps. |

## Must not be required by Free Core

```txt
login
cloud
telemetry
Pro subscription
Stripe/Cloudflare backend
Pro extension bundle
live Mem0 runtime
GitHub App
SSO/RBAC
enterprise offline license
```

## Source-of-truth order

```txt
1. current source code
2. current tests
3. evidence
4. modules
5. decisions/wiki
6. sessions/handoffs
7. external memory
```

Rule:

```txt
External memory is advisory only.
It can suggest context.
It cannot raise trust automatically.
```

## Required core commands

```bash
node .knowledge/tools/doctor.js --json
node .knowledge/tools/flow.js release --no-color --json
node .knowledge/tools/build-visual-inspector.js
node .knowledge/tools/pr-impact.js --json
node .knowledge/tools/restore-trust.js --safe --json
node .knowledge/tools/export-debug-bundle.js --json
node .knowledge/tools/export-pro-snapshot.js --json
node .knowledge/tools/agent-session.js start --json
node .knowledge/tools/agent-session.js finish --json
node .knowledge/tools/team-status.js --json
node .knowledge/tools/worktree-status.js --json
```

## Free Core acceptance criteria

- Works from clean install artifact.
- No cloud/login required.
- No hidden telemetry.
- All reports are local files.
- All core commands support `--json`.
- External memory cannot raise trust.
- Restore Trust does not modify source code.
- Runtime/generated files are not staged by `git add .`.
- Embedded apps can consume files/CLI/API without the Inspector.
