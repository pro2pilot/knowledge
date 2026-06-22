# Inspector Monetization Logic

Source: `knowledge_3_2_0_docs/03_inspector_monetization_logic.md`.

This file records how the 03 monetization direction is implemented in
`.knowledge` 3.2.0 without hard-coding prices or feature-to-plan bindings into
the free core.

## Implemented Model

- Sell Pro2Pilot Inspector as a workflow/governance layer for AI-assisted
  engineering teams, not as AI memory, code RAG, a low-code canvas, or a
  replacement for Codex/Claude/OpenCode/MCP/GitHub.
- Keep `.knowledge Core` useful as the free, local-first, Apache-2.0 trust
  layer: routing, trust/freshness, repair queue, local search, PR summary,
  static Inspector, agent integrations, local action templates, external memory
  status, and no telemetry by default.
- Keep paid implementation outside this package in
  `<paid-inspector-root>`.
- Represent paid value in the free Inspector as config-driven disabled actions,
  contextual conversion signals, and license/provenance rules.
- Use `docs/product/paid-feature-manifest.json` as the free-core contract for
  capabilities, conversion triggers, billable dimensions, non-billable free
  behavior, add-on categories, private-preview shape, GTM motions, and
  anti-patterns.
- Use `pro2pilot-inspector/versions/0.1.0/commercial-model.json` as the
  separate paid workspace catalog for commercial implementation planning.

## Explicitly Not Hard-Coded

- No prices live in free-core code or in the free manifest.
- No capability is bound to a specific paid plan in free-core code.
- No billing service, entitlement engine, hosted backend, GitHub App, SSO/RBAC,
  audit export, alert engine, or policy-pack marketplace is implemented in the
  free package.
- Plan names, prices, limits, discounts, and feature packaging must remain in a
  separate paid/commercial config when those decisions stabilize.

## Free Inspector Behavior

The static free Inspector now reads `paid-feature-manifest.json` and renders:

- paid capability previews from data, not from an inline action list;
- contextual conversion signals near real paid-value actions;
- billable dimensions and free non-billable boundaries;
- usage-billing guidance that avoids per-run/per-token billing at launch;
- license/provenance rules for external memory and third-party connectors.

The static HTML still copies commands only and does not execute local commands.

## Paid Inspector Direction

The paid workspace should build the implementation for:

- multi-repo dashboards;
- team mode management beyond readonly local status;
- interactive PR impact graph and GitHub automation;
- repair ownership, SLA, comments, and history;
- policy packs, workflow/stack packs, approvals, alerts, and audit exports;
- SSO/RBAC, hosted/private/VPC deployment, pack registry, and support.

Those capabilities are modeled as product capabilities, not plan bindings.
