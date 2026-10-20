---
name: kb-search
description: Search .knowledge without loading the full wiki or all module cards.
disable-model-invocation: true
---

Run `node .knowledge/tools/search-knowledge.js "<query>"`.

If the index may be stale, run `node .knowledge/tools/build-search-index.js` first.

Use returned snippets only to choose which `.knowledge` files and source files to open. Do not treat snippets as source of truth.
