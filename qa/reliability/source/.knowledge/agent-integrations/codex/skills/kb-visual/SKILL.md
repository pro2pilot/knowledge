---
name: kb-visual
description: Build and inspect the local .knowledge Visual Inspector dashboard.
---

Run:

`node .knowledge/tools/build-visual-inspector.js`

Then open `.knowledge/inspector/index.html`.

Use it to inspect:

- trust buckets and quality score;
- module confidence and why trust is low;
- repair queue and stale items;
- critical/important files;
- wiki graph;
- applied templates;
- external-memory status;
- copyable maintenance commands.

The inspector is read-only. Current source code and tests remain source of truth.
