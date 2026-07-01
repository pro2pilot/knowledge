# Cookbook

The cookbook is a set of short, operational recipes for using `.knowledge` in real agent workflows.

It is not conceptual documentation. Each cookbook page answers:

```txt
When should I use this?
What files should the agent read first?
What commands should it run?
What output should it update?
What should be checked before trusting the result?
```

## Why it exists

`.knowledge` has several layers: routing bundle, module cards, wiki, search, doctor, PR summaries, external memory, and agent integrations. The cookbook turns those layers into repeatable maintenance patterns so an agent does not improvise every time.

## Recipes

- `01-new-project.md` — initialize `.knowledge` in a new repository.
- `02-existing-project.md` — migrate or merge an existing knowledge base.
- `03-agent-handoff.md` — prepare state for the next agent/session.
- `04-wiki-graph.md` — maintain typed wiki links and graph health.
- `05-pr-review.md` — create a review-facing summary.
- `06-external-memory.md` — use optional Pinecone/external archive safely.

- `07-team-worktree-pr.md` - coordinate multi-worktree agent PR work.
- `08-connect-another-agent.md` - add another agent runtime to an existing `.knowledge` repo.
- `09-mem0-live-memory.md` - set up Mem0 OSS as advisory-only external memory with one guided flow.

For install semantics, receipt/runtime distinction, and repo-local Mem0 paths, see `../mem0-install.md`.

## Relationship to Quick-Start

- `Quick-Start.md` is the single canonical onboarding prompt for any agent.
- The cookbook is the follow-up operating manual for recurring tasks.
- README points users to Quick-Start first, then to cookbook recipes for specific workflows.
