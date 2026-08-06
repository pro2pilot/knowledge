# Evaluation Harness

Run:

```bash
node .knowledge/tools/evaluation-harness.js
```

Output:

```txt
.knowledge/evaluation/results/latest.json
```

Use the separate agent test prompt to run a full in-the-wild evaluation and fill GitHub-facing metrics.

The harness parses each command's JSON result in addition to checking its exit
code. A child `ok: false`, failure status, non-empty failure list, or unexpected
semantic failure counter makes that check fail even when the process exits 0.
The report also records p50/p95 command latency, trust-layer health, and the
local routing-bundle token estimate. Token values remain approximate and are
not tokenizer-verified claims.
