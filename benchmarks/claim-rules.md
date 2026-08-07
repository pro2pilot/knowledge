# Claim Rules

Allowed claim statuses:

- `measured`
- `measured-on-fixture`
- `estimated`
- `diagnostic`
- `preview`
- `planned`
- `failed`

Only `measured` and `measured-on-fixture` may be used in public marketing.

Forbidden wording:

- eliminates hallucinations
- guarantees safe PRs
- zero-risk agent work
- always faster
- enterprise-ready
- beats Cursor/Sourcegraph/Greptile/Qodo/CodeRabbit/Devin
- external memory is trusted

Safe wording pattern:

```txt
In benchmark fixture <name>, .knowledge <measured behavior>, with raw logs and reproduction scripts.
```
