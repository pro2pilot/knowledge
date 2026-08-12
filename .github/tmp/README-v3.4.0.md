# .knowledge by Pro2Pilot

> **A repo-local trust layer for AI coding agents: task-scoped routing, physical evidence, freshness, bounded repair, PR review, Field Reports, and a local Inspector.**

Current code and tests remain the source of truth. External memory stays advisory.

<p align="center">
  <img src="assets/knowledge-trust-gate-light-readme.svg" alt=".knowledge trust gate: code, tests, agents, memory, and PR review pass through the local trust layer" width="100%">
</p>

## Why this exists

AI coding agents often fail for reasons that are hard to audit later:

- they read too much irrelevant repository context;
- stale summaries outrank current code and tests;
- verification evidence is disconnected from the final claim;
- repair may look successful even when recertification did not hold;
- unrelated debt disappears behind one green summary;
- multi-agent repos accumulate runtime-specific glue and drift.

`.knowledge` keeps trust decisions **inside the repository** and makes them reviewable.

## What 3.4.0 changes

Version **3.4.0** adds one integrated task-bound workflow:

```text
meaningful task
→ exact task route
→ content-addressed first read
→ primary verification
→ native evidence
→ one exact safe repair reuse
→ reviewable final state
```

### `agent-task begin`

For meaningful scoped work, start with:

```bash
node .knowledge/tools/agent-task.js begin \
  --task="Update the orders route and its shared mapping" \
  --scope-module=orders_app \
  --scope-path=apps/orders/ \
  --json
```

`begin` creates a canonical task snapshot and returns the exact current `first-read.md` body, relative path, SHA-256 and byte count before broad exploration.

### `agent-task finish`

Finish with an explicit, repository-contained request:

```json
{
  "schema_version": "knowledge-agent-task-finish-request.v1",
  "route_first_read_sha256": "<from begin>",
  "changed_files": ["src/orders.js"],
  "source_files": ["src/orders.js", "tests/orders.test.js"],
  "tests_to_run": [
    {
      "argv": ["node", "tests/orders.test.js"],
      "cwd": ".",
      "timeout_ms": 120000
    }
  ],
  "run_release_flow": true
}
```

```bash
node .knowledge/tools/agent-task.js finish \
  --workflow-id=<ATW-id> \
  --request=finish.json \
  --json
```

`finish` runs primary verification once, records content-addressed native evidence, and may reuse that evidence for **one exact safe Repair-on-touch closure**. Unknown side effects, unsupported repair classes, path escapes and unsustained recertification fail closed.

[Read the integrated task workflow](docs/agent-task-workflow.md)

## Verified evidence snapshot

| Evidence block | Result |
|---|---:|
| Windows / Ubuntu / macOS × Node 18 / 20 / 22 | **9 / 9 PASS** |
| Shipped self-test executions across that matrix | **243 / 243 PASS** |
| Agent integration bridges exercised in every matrix cell | **12** |
| Exact upgrades `3.2.11 → 3.4.0` on Node 22 | **3 / 3 PASS** |
| Candidate-bound deterministic routing cases | **48 / 48 claim-eligible** |
| False omissions | **0** |
| High-risk silent omissions | **0** |
| Workspace modules → selected modules | **3,584 → 96** |
| Corrected median local first-read byte reduction | **90.77%** |
| Byte-weighted aggregate reduction | **91.14%** |

> Routing percentages are deterministic local UTF-8 first-read bytes on synthetic fixtures. They are **not** provider-reported tokens, cost, latency or model accuracy.

## Supported agent runtimes

Codex, Claude Code, OpenCode, OpenClaw, Hermes, Gemini CLI, GitHub Copilot, Devin, Windsurf, Continue, Roo Code, Aider, and others.

In 3.3.0+ the shared repository guidance is coordinated through one managed `AGENTS.md` block, while vendor-specific files stay isolated where needed.

## Install the release asset

> Do **not** use GitHub **Code → Download ZIP** as the install package.

Download the uploaded release asset named `knowledge-vX.Y.Z.zip`, extract it so the target repository contains `.knowledge/`, and tell the active agent:

```txt
Read `.knowledge/Quick-Start.md` and execute it for this repository.
```

### Manual setup

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime codex
node .knowledge/tools/flow.js import
node .knowledge/inspector.js
```

Replace `codex` with the active runtime. Install another runtime later without replacing the existing `.knowledge/` state.

<details>
<summary><strong>Supported installer runtimes</strong></summary>

```txt
codex
claude
opencode
openclaw
hermes
gemini
copilot
devin
windsurf
continue
roo
aider
```

</details>

## What ships

A normal installed repository contains:

- `.knowledge/Quick-Start.md`
- `.knowledge/docs/`
- `.knowledge/tools/`
- `.knowledge/schemas/`
- `.knowledge/agent-integrations/`
- `.knowledge/templates/`
- `.knowledge/config/`
- `.knowledge/inspector.js`
- the managed runtime integration files required for the selected agents

Maintainer-only release and benchmark tooling stays out of installed repositories.

## Core trust model

`.knowledge` is built around a few simple rules:

1. **Current code and tests outrank memory.**
2. **Task scope should be explicit before broad exploration.**
3. **Verification evidence should stay attached to the final result.**
4. **Repair may close only exact, eligible, sustained findings.**
5. **Global health and task outcome should remain separate.**
6. **Unrelated debt must stay visible.**

That is why the system keeps distinct outputs for:

- primary engineering verification;
- task routing;
- Doctor health;
- Task Readiness;
- KVE/KVR evidence and repair state;
- deferred debt;
- provider usage, only when a real provider receipt exists.

## Inspector

Run the local Inspector to review repository state:

```bash
node .knowledge/inspector.js
```

The Inspector provides a local, human-reviewable view of current evidence, route state, Doctor status, readiness, repair state and change impact.

## Field Reports

`.knowledge` also supports a structured **Field Report** workflow so real users can publish results from real repositories without turning their repo into a public dump of internals.

You can create a Field Report in two ways:

- **manually**, by filling the template yourself;
- **semi-automatically**, by letting the local `field-report` workflow collect observable task facts, ask for the missing human answers and prepare a draft for your review.

Field Report is designed as a **local reviewable workflow**:

- collection happens locally;
- review, redaction and approval happen before publication;
- sensitive project details can be removed or generalized;
- public drafts are meant to share outcomes and observations, not repository secrets.

[How Field Reports work](https://github.com/pro2pilot/knowledge/discussions/4) · [Technical workflow](docs/field-report.md)

Starter command:

```bash
node .knowledge/tools/field-report.js start --new --json
```

## Useful local commands

### Import and refresh generated state

```bash
node .knowledge/tools/flow.js import
```

### Check installer/runtime consistency

```bash
node .knowledge/tools/install-check.js --json
```

### Start a Field Report

```bash
node .knowledge/tools/field-report.js start --new --json
```

### Launch the Inspector

```bash
node .knowledge/inspector.js
```

## Upgrades

Users of **3.2.11** can upgrade directly to **3.4.0**.

A conservative upgrade path is:

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/flow.js import
node .knowledge/inspector.js
```

Then run a small real task through `agent-task begin` / `agent-task finish`.

## Benchmarks and claim boundary

`.knowledge` can support public benchmark work, but the project is intentionally conservative about claims.

Supported public claims today:

- the integrated task-bound workflow exists and is reviewable;
- the release line passed the reported compatibility and shipped self-test checks;
- the candidate-bound routing suite reduced deterministic local first-read byte scope on the published fixtures;
- exact safe evidence reuse for one Repair-on-touch closure is implemented.

Unsupported claims today:

- `.knowledge` makes the base model intrinsically smarter;
- `.knowledge` improved model accuracy by a validated published percentage;
- `.knowledge` reduced provider tokens or API cost unless you independently measure that with provider receipts.

## Project links

- **Homepage:** `https://pro2pilot.com/knowledge/`
- **Field Reports explained:** [How Field Reports work](https://github.com/pro2pilot/knowledge/discussions/4)
- **3.4.0 Discussion:** https://github.com/pro2pilot/knowledge/discussions/5
- **GitHub Discussions:** use Discussions for release notes, Field Reports and benchmarks
- **Release Notes:** [`RELEASE_NOTES.md`](RELEASE_NOTES.md)
- **Workflow details:** [`docs/agent-task-workflow.md`](docs/agent-task-workflow.md)

## License

Apache-2.0.
