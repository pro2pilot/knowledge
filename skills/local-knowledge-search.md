# Local Knowledge Search

Use when the task needs context but loading the full wiki would waste tokens.

Steps:

1. Run `node .knowledge/tools/build-search-index.js` if index may be stale.
2. Run `node .knowledge/tools/search-knowledge.js "<query>"`.
3. Open only the matching wiki/module/evidence files that are relevant.
4. Treat snippets as routing hints, not truth.
