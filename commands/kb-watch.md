kb-watch
Run `node .knowledge/tools/watch-maintenance.js` from repo root.
What it does:
- watches the repository recursively except ignored high-noise paths
- debounces file changes
- runs the impact-aware maintenance core automatically
- updates freshness, trust report, repair queue, stale items, and automation status

Use when you want live self-maintaining behavior during active coding.

For a bounded smoke test, run `node .knowledge/tools/watch-smoke.js`.
