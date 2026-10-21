# VS Code, Browser And Embedding

V1 uses a browser Inspector, planned VS Code shell and headless embedding contracts. There is no desktop app in V1.

Browser launch:

```bash
node .knowledge/inspector.js
```

Local API contract:

```txt
GET /api/session
GET /api/state
GET /api/trust
GET /api/repair
GET /api/team
GET /api/actions
POST /api/actions/:id/run
GET /api/runs/:runId
```

Embedding apps can use files, CLI, local API and events without the Inspector.
