# Metrics and Benchmarks

`.knowledge` includes local metrics so users can measure their own repository instead of trusting generic claims.

Collect metrics:

```bash
node .knowledge/tools/collect-metrics.js
```

Outputs:

```txt
.knowledge/metrics/baseline.json
.knowledge/metrics/README.md
```

## Token estimator

All installed local context estimates use one deterministic estimator:

```txt
words = text.match(/\S+/g).length
chars = text.length
tokens_approx = max(ceil(words * 1.33), ceil(chars / 4))
```

This is an order-of-magnitude estimate, not a tokenizer-verified production benchmark.

## Safe benchmark language

Good:

```txt
On a synthetic SaaS-shape fixture, `.knowledge` reduced the orientation path from 14 files to one routing bundle.
Token estimates are local and order-of-magnitude.
```

Avoid:

```txt
Always saves X% tokens.
Guarantees agent correctness.
Replaces code review.
```

## What to measure per repository

- Routing bundle size.
- Baseline orientation files and estimated tokens.
- Assisted orientation files and estimated tokens.
- Doctor status and score.
- Wiki graph node/edge counts.
- Search index document count.
- Visual Inspector availability.
- Maintenance flow latency.

## Recommended local evidence command

```bash
node .knowledge/tools/flow.js release --no-color
```

## Signed context delta

The metrics report keeps a signed token delta separate from the non-negative
`estimated_tokens_saved` field. A negative delta is reported as estimated
overhead, not mislabeled as savings. Small repositories can legitimately show
overhead; release claims require the representative baseline/assisted benchmark.
