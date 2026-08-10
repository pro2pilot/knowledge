# Hard accuracy study — `.knowledge` 3.4.0 RC1

Candidate SHA-256: `44085f441946ca08905bacdd329ff5c7a68aeefeb25b04389bf3c2cdb4de961a`

This is a preregistered 32-pair / 64-decision study of exact first-pass repository decisions under the same maximum first-read budget.

The suite removes the answer-label leakage found in R3: no input says `owns`, `key file`, `direct dependency`, `target module`, or `correct answer`. Both conditions contain all gold strings. The workspace-wide condition requires joining active wiring, opaque aliases, file aliases and imports across current and legacy decoys. The task-scoped condition presents the candidate's selected route plus the same relevant source evidence.

## Run

Use `tools/run-github-models.mjs` with a GitHub token that has `models: read`:

```bash
GITHUB_TOKEN=... node tools/run-github-models.mjs
```

Or use the included GitHub Actions workflow on an audit-only branch.

No result exists until all 64 model decisions complete. Do not publish an accuracy-improvement claim from the preflight package alone.
