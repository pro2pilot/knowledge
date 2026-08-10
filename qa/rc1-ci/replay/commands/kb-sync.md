kb-sync
Run `node .knowledge/tools/sync-tracked.js` in a project that already has `.knowledge/`.
This updates tracked-file freshness and trust metrics without a full rescan.

Use `node .knowledge/tools/sync-tracked.js --scan` to rebaseline the current curated scope.

Use `node .knowledge/tools/sync-tracked.js --scan --discover` only when intentionally looking for new important files.
