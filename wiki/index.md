# Knowledge Wiki Index

This wiki is the human-readable long-form layer for `.knowledge/`.

Use it for explanations, architecture notes, runbooks, concepts, migration notes, and lessons learned. Do not treat wiki pages as source of truth when they conflict with current code or tests.

## First rule

```txt
code > tests > evidence JSON > module cards > decisions > wiki > sessions
```

## Sections

- `architecture/` — durable architecture notes and system boundaries.
- `runbooks/` — operational procedures and repeatable workflows.
- `concepts/` — glossary-like explanations of domain concepts.
- `log.md` — append-only narrative of important knowledge maintenance events.

## Maintenance

After adding or editing wiki pages, run:

```bash
node .knowledge/tools/build-search-index.js
node .knowledge/tools/build-routing-bundle.js
node .knowledge/tools/doctor.js
```
