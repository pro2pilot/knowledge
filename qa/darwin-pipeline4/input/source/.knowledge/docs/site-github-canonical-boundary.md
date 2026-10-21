# Site And GitHub Canonical Boundary

This document defines where public `.knowledge` information belongs for the 3.3.0 release line.

Principle:

```txt
The website explains.
The GitHub repository proves, installs, and reproduces.
The release asset is what users install.
```

## Boundary Table

| Topic | Canonical owner | Website responsibility | GitHub repository responsibility |
|---|---|---|---|
| What `.knowledge` is | Website | Human-readable product and standard explanation. | Short README summary and link map. |
| Install and Quick Start | GitHub | Short install card and release-asset warning. | Release asset, Quick-Start, updater flow, exact commands. |
| Trust model | Split | Explain why code/tests outrank summaries and memory. | Formal source-of-truth order, trust states, schemas, CLI behavior, tests. |
| Source-of-truth order | GitHub | Human explanation and examples. | Formal order, validation behavior, generated reports. |
| Shipped vs generated artifacts | Split | Plain table for users: what ships, what appears after import/release. | Release manifest, package scripts, artifact validator, technical docs. |
| Benchmarks | Split | Methodology, limitations, summary, what is and is not proven. | Scripts, fixtures, raw or sanitized outputs, reproduction commands. |
| Agent integrations | Split | Overview and per-agent guide pages. | Adapter templates, install commands, integration tests. |
| Compatibility and conformance | Split | Explain compatible release/spec status in human language. | Schemas, fixtures, conformance checks, versioned specs. |
| Visual Inspector | Split | Product explanation, screenshots, free vs Pro boundary. | Local launch/build commands, generated output contracts, tests. |
| Inspector Pro | Website | Waitlist, buyer-facing capability explanation. | Short README link and free/pro guardrails. |
| Embedding `.knowledge` in apps | Website first | Guide app builders through CLI, JSON/Markdown outputs, local API, and trust rules. | Existing CLI/API reference and later optional examples or schemas. |
| FAQ and comparisons | Website | Market explanation: RAG, AGENTS.md, CLAUDE.md, agent memory, code review. | Short links only, not long essays. |
| License | GitHub | Short Apache-2.0 core note. | LICENSE, NOTICE, third-party notices, file-level notes. |

## README Rule

README should help a user understand in 30 to 60 seconds:

- what `.knowledge` is;
- why it exists;
- how to install it;
- that it is local-first, Apache-2.0, and telemetry-free by default;
- where to go for deeper human-readable docs.

README should not become the full product manual.

## Website Rule

The website should feel like documentation and a technical field guide, not a replacement GitHub repository.

Each important website page should include implementation references back to GitHub:

- release asset;
- schema or manifest;
- CLI file;
- reproduction command;
- raw or sanitized report location.

## GitHub Rule

GitHub must remain the source for:

- install artifacts;
- schemas;
- CLI and implementation behavior;
- templates and adapter files;
- fixtures and tests;
- release validation;
- raw or sanitized reproducible evidence.

## 3.3.0 Link Map

| User goal | Public URL |
|---|---|
| Product/docs hub | `https://pro2pilot.com/knowledge/` |
| Trust model | `https://pro2pilot.com/knowledge/docs/trust-model/` |
| Shipped vs generated | `https://pro2pilot.com/knowledge/docs/shipped-vs-generated/` |
| Benchmarks | `https://pro2pilot.com/knowledge/docs/benchmarks/` |
| Integrations | `https://pro2pilot.com/knowledge/docs/integrations/` |
| Compatibility | `https://pro2pilot.com/knowledge/docs/compatibility/` |
| Embed in your app | `https://pro2pilot.com/knowledge/docs/embed-knowledge-in-your-app/` |
| Inspector Pro | `https://pro2pilot.com/inspector/` |
