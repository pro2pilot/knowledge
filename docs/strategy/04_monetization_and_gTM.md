# 04 — Monetization and GTM after competitive analysis

## Pricing principle

`.knowledge` is open-core adoption. Pro Inspector is governance subscription.

Do not price against cheap memory tools. Price against:

- team review overhead;
- codebase context risk;
- governance/compliance needs;
- PR-review automation;
- multi-agent coordination;
- repair debt management;
- auditability.

## Competitive price anchors

| Competitor | Relevant anchor | Implication |
|---|---|---|
| Sourcegraph | enterprise starts high, code intelligence platform | leave room for lighter local-first product |
| Greptile | $30/seat/month PR review | Pro Inspector must justify above/beside review bots |
| Qodo/CodeRabbit/Graphite | $20–$50/user/month review workflows | PR Impact needs credible value |
| Cursor/Devin | team/enterprise dashboards and admin controls | team surface must be polished |
| Mem0/Graphiti/Zep | memory and graph infra | memory governance is an add-on, not core identity |
| n8n/Dify/Retool | workflow builder pricing | avoid being compared as generic workflow canvas |

## Recommended product packages

### Free Local

```txt
Price: $0
License: Apache-2.0 core
Scope: one repo, local/static Inspector, no cloud, no telemetry
```

Includes:

- routing bundle;
- trust/freshness;
- repair queue;
- stale items;
- local search;
- PR summary;
- PR Impact preview;
- Team Mode local status;
- Mem0/Pinecone optional status;
- export debug bundle.

### Pro Inspector Preview

```txt
Price: invite/private preview
Use: design partners and pilot teams
```

Includes:

- Pro app;
- snapshot import;
- PR Impact;
- Repair Board;
- Team Spaces;
- Memory Governance;
- basic Audit/History;
- policy pack preview.

### Inspector Team

```txt
Recommended: $149–299/month per workspace
```

For:

- teams already using coding agents;
- agencies;
- founder-led engineering teams;
- 2–15 engineers.

Includes:

- 5 repos;
- 10 users;
- PR Impact;
- Repair Board ownership;
- Team Spaces;
- standard policy packs;
- memory provider fleet status;
- GitHub App beta;
- 90-day history.

### Inspector Scale

```txt
Recommended: $599–999/month per org
```

For:

- platform teams;
- larger agencies;
- 10–50 engineers;
- multiple repos/worktrees.

Includes:

- 25 repos;
- 50 users;
- multi-repo dashboard;
- advanced Team Spaces;
- alerts;
- audit export;
- custom policy packs;
- Graphiti/Zep provider governance;
- advanced analytics.

### Enterprise / Sovereign

```txt
Recommended: from $30k–80k ACV
```

For:

- regulated teams;
- enterprise buyers;
- private/VPC deployments;
- security-sensitive agent workflows.

Includes:

- SSO/RBAC/SCIM;
- private/VPC/self-host;
- compliance export;
- BYOC memory providers;
- policy gate workflows;
- extended audit retention;
- SLA/support;
- custom onboarding.

## Add-ons

| Add-on | Recommended price | Why it sells |
|---|---:|---|
| Managed Launch / Pilot | $3k–8k | teams need help turning repo chaos into governance |
| Production Migration | $10k–25k | agencies/enterprises need rollout help |
| Custom Policy Pack | $2k–15k + subscription | domain-specific governance |
| Memory Governance Add-on | $199–999/mo | provider drift/license/audit/fleet status |
| GitHub App Automation | included Team+ / add-on | PR comments/checks/labels |
| Sovereign Deployment | enterprise | compliance/data residency |

## GTM motion

### Motion 1 — Open-core proof

Target:

- senior/staff engineers;
- solo builders;
- small agent-active teams.

CTA:

```txt
Install .knowledge locally. Build the Inspector. See what your agents should trust.
```

Proof assets:

- README demo;
- local Inspector screenshot;
- benchmark `B1 Repo Orientation`;
- benchmark `B2 Trust/Freshness`;
- benchmark `B10 No-cloud`.

### Motion 2 — PR Impact wedge

Target:

- tech leads;
- engineering managers;
- platform leads.

CTA:

```txt
Review agent-assisted PRs by trust, freshness and critical-path impact.
```

Proof assets:

- PR Impact demo;
- repair queue closure demo;
- policy warning before merge;
- GitHub PR comment preview.

### Motion 3 — Team Mode / multi-agent coordination

Target:

- teams using multiple agents/runtimes;
- agencies;
- platform teams.

CTA:

```txt
Multi-agent worktrees without shared dirty state.
```

Proof assets:

- Team Mode self-test video;
- state isolation logs;
- locks/events explorer;
- worktree compare screenshot.

### Motion 4 — Enterprise governance

Target:

- DevEx;
- security;
- AI governance;
- regulated engineering.

CTA:

```txt
Agent-neutral knowledge governance with policy gates, audit and private deployment path.
```

Proof assets:

- audit export;
- memory provider SBOM/license report;
- policy pack demo;
- no-cloud/local-first proof.

## Website messaging

### Hero

```txt
A repo-local knowledge governance layer for AI coding agents.
```

Subheadline:

```txt
Route agents to the right context, show what knowledge is trusted or stale, turn repair debt into actions, and review PR impact through a local Inspector.
```

CTA:

```txt
Try the free local core
Join Pro Inspector preview
```

### Against competitors

```txt
Not an AI IDE.
Not a review bot.
Not a memory dump.
.knowledge is the repo-local trust layer that survives whichever agent runtime you use.
```

## Launch claims to avoid until benchmarks pass

Do not claim:

```txt
best in market
unique multi-agent worktrees
guaranteed safe agents
replaces code review
eliminates hallucinations
10x faster
enterprise-ready
```

Use only measured claims:

```txt
In B1, agents opened X% fewer files before first plan.
In B2, stale summaries were detected with X precision/Y recall.
In B8, two worktrees completed without state contamination in N runs.
```

## Recommended first commercial offer

```txt
30-day Knowledge Governance Pilot
```

Deliverables:

- install `.knowledge` in 3–5 repos;
- build free Inspector;
- configure Mem0/Pinecone optional status;
- run PR Impact on selected PRs;
- create Repair Board;
- enable Team Mode in one multi-worktree scenario;
- generate benchmark/report;
- deliver Pro Inspector preview dashboard.

Price:

```txt
$3k–8k fixed pilot
```

Conversion:

```txt
Pilot → Inspector Team / Scale / Enterprise
```
