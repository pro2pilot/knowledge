# 09 — VS Code, browser Inspector and embedding

## UX surfaces

```txt
VS Code Extension — primary developer shell.
Browser Inspector — standalone local UI.
Headless API/CLI/files — embedding under other apps.
```

No desktop app in V1.

## One-file launcher

```bash
node .knowledge/inspector.js
```

Starts:

```txt
127.0.0.1 local server
session token
action API
Inspector UI
```

## VS Code extension

### Activity Bar

```txt
.knowledge
```

### Views

```txt
Health
Review
Knowledge Trust
Agents Activity
Reports
```

### Status Bar

```txt
.knowledge 92 · Trust: Needs Recheck · Agents: 2
```

### Commands

```txt
.knowledge: Open Inspector
.knowledge: Run Health Check
.knowledge: Restore Trust
.knowledge: Review Current Changes
.knowledge: Open Merge Queue
.knowledge: Export Report
```

### Webview

Open full Inspector inside VS Code.

### File decorations

```txt
trusted
stale
critical
agent changed
needs evidence
```

## Browser Inspector

For non-VS Code users:

```bash
node .knowledge/inspector.js
```

Then open:

```txt
http://127.0.0.1:<port>
```

Browser mode is not second-class. It uses the same API and data model.

Browser/server mode and static `inspector/index.html` use the same renderer. Static mode is read-only; server mode enables token-protected action buttons.

## Embedding in other apps

Apps can use `.knowledge` under the hood via four contracts.

### File contract

```txt
maintenance/*.json
maps/*.json
inspector/data.json
events/*.ndjson
reports/*.md
```

### CLI contract

```bash
node .knowledge/tools/doctor.js --json
node .knowledge/tools/flow.js release --json
node .knowledge/tools/team-status.js --json
node .knowledge/tools/pr-impact.js --json
node .knowledge/tools/restore-trust.js --safe --json
```

### Local API contract

```txt
GET /api/state
GET /api/trust
GET /api/repair
GET /api/team
GET /api/actions
GET /api/git/branches
GET /api/git/diagnostics?branch=<name>
GET /api/update/status
POST /api/update/dry-run
POST /api/update/apply
POST /api/actions/:id/run
GET /api/runs/:id
```

### Event stream

```txt
.knowledge/events/*.ndjson
```

## Embedding rule

`.knowledge` must remain headless-first. UI is optional. The system must be useful as files + CLI + local API.
