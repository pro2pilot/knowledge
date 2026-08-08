# Local Inspector

The Inspector is optional. `.knowledge` works without it, but the Inspector is the primary visual interface for routing, evidence, trust, freshness, repair, PR review, reports and agent activity.

## Launch

```bash
node .knowledge/inspector.js
```

`node .knowledge/inspector.js` - live local Inspector with buttons.

It starts a `127.0.0.1` local server, creates a session token, serves the Inspector UI, exposes allowlisted local actions and writes action logs locally.

On first run, complete the setup before relying on agent-written reports.
Repair-on-touch defaults to `scoped`; the wizard explains its finding, time,
context, generated-artifact, and protected-path controls. The complete setup is
committed as one recoverable JSON transaction, so a partial settings save
cannot leave mixed policy state.

## Navigation

Canonical navigation:

- Home
- Review
- Knowledge Trust
- Agents Activity
- Reports
- Settings
- Pro Preview

There are no top-level `Metrics`, `Command Center`, `Work` or chat tabs. Metrics are cards. Static HTML remains a read-only fallback.

## Static Fallback

```bash
node .knowledge/tools/build-visual-inspector.js
```

`node .knowledge/tools/build-visual-inspector.js` - static fallback only.

Output:

```txt
.knowledge/inspector/index.html
.knowledge/inspector/data.json
.knowledge/inspector/status.json
```

The static fallback copies commands only. For real local buttons, use `node .knowledge/inspector.js`.

## Local API

```txt
GET /api/session
GET /api/state
GET /api/trust
GET /api/repair
GET /api/settings/repair-on-touch
POST /api/settings/repair-on-touch
GET /api/team
GET /api/actions
POST /api/actions/:id/run
GET /api/runs/:runId
```

All API routes except `/api/session` require the session token.

The repair page keeps global Doctor health separate from current-task
readiness. It shows task-relevant selected/deferred/closed findings, actual-only
maintenance cost, and receipt provenance. Inspector cannot manufacture a
receipt or convert an unexecuted check into evidence.
