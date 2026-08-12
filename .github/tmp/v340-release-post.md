# `.knowledge` 3.4.0 is out: a task-scoped workflow, a 9-cell compatibility matrix, and a 48-case routing stress test—without invented claims

AI coding agents do not always fail because they lack context.

Often, the opposite is true: they receive too much context, its freshness is unknown, evidence is separated from the final result, and repository knowledge remains in an ambiguous state even after a test passes.

`.knowledge` 3.4.0 connects those pieces into one repo-local workflow:

```text
task
→ exact task route
→ content-addressed first read
→ physical verification
→ evidence reuse
→ bounded repair
→ reviewable final state
```

## What is new in 3.4.0

### `agent-task begin`

Before broad repository exploration, the agent receives the current task snapshot and the exact `first-read.md`:

```bash
node .knowledge/tools/agent-task.js begin \
  --task="Update the orders route and its shared mapping" \
  --scope-module=orders_app \
  --scope-path=apps/orders/ \
  --json
```

The response binds the task, scope, first-read body, SHA-256, and byte count.

### `agent-task finish`

After the code change, the workflow physically executes the requested checks, stores native verification evidence, and may reuse that evidence for one exact, safe Repair-on-touch closure:

```text
primary verification
→ content-addressed KVE
→ exact scoped KVR
→ sustained lifecycle closure
```

A test is not rerun merely to produce a more attractive repair counter. If the evidence, lifecycle, or final recertification does not hold, the repair remains open.

### Recovery and fail-closed boundaries

`finish` uses a durable journal and lock-serialized recovery. Repeating the same request is idempotent; changing the request is rejected. An unknown side effect is not guessed at or silently repeated.

Request files and test working directories must remain inside the repository boundary. Symlink, junction, hardlink, and traversal escapes are rejected.

## What the tests showed

| Evidence block | Result |
|---|---:|
| Windows / Ubuntu / macOS × Node 18 / 20 / 22 | **9 / 9 PASS** |
| Shipped self-test executions across the matrix | **243 / 243 PASS** |
| Agent integration bridges | **12 in every cell** |
| Exact `3.2.11 → 3.4.0` upgrades on Node 22 | **3 / 3 PASS** |
| Deterministic routing cases | **48 / 48 claim-eligible** |
| False omissions | **0** |
| High-risk silent omissions | **0** |
| Workspace modules → selected modules | **3,584 → 96** |
| Corrected median local first-read byte reduction | **90.77%** |
| Byte-weighted aggregate reduction | **91.14%** |
| Mean / range | **89.65% / 81.64–94.69%** |

> Routing percentages measure deterministic local UTF-8 first-read bytes on synthetic, candidate-bound fixtures. They are not provider-reported tokens, API cost, latency, or model accuracy.

The 48-case suite covered ownership routing, direct dependencies, active-versus-legacy paths, feature and configuration indirection, migrations, critical-path incidents, generated mirrors, and API boundaries. Every route was current, ready, and complete; every required dependency was selected.

## Supported agent runtimes

Codex, Claude Code, OpenCode, OpenClaw, Hermes, Gemini CLI, GitHub Copilot, Devin, Windsurf, Continue, Roo Code, Aider, and others.

## Why the failed tests matter too

Since 3.2.11, we have blocked our own release candidates and studies several times:

- routing estimates could be artificially inflated with padding;
- a route could appear ready while a required source was missing;
- a stale or ineligible report could retain a positive raw assessment;
- early accuracy suites produced ceiling effects;
- later hard studies stopped before scoring when infrastructure or pre-model integrity failed the protocol.

We did not delete those outcomes or convert them into marketing claims.

That is why we are **not claiming** that `.knowledge` made the model intrinsically smarter or improved model accuracy by X%. We do not yet have a valid final model-level proof for that statement.

The strongest supported conclusion is different:

> `.knowledge` makes task scope, first read, physical evidence, trust transitions, and remaining debt explicit, content-addressed, and reviewable.

## What that changes in practice

- the agent starts from an exact task route instead of an uncontrolled repository crawl;
- code and tests remain above summaries and memory in the trust hierarchy;
- verification evidence can be reused without rerunning the test;
- repair closes only the exact verified finding;
- unrelated debt stays visible;
- Doctor, Task Readiness, the primary outcome, and provider usage are not merged into one green score;
- one repository-local trust model can support Codex, Claude Code, OpenCode, OpenClaw, Hermes, Gemini CLI, GitHub Copilot, Devin, Windsurf, Continue, Roo Code, Aider, and others.

## Field Reports

The most useful contribution to the project right now is a **real Field Report from a real repository**.

A Field Report can be prepared in two ways:

- **manually**, using the template;
- **semi-automatically**, through the local `field-report` workflow, where the agent collects observable facts, asks for the missing human context, prepares a draft, and leaves publication under your control.

Field Report is designed as a **local, reviewable workflow**, not as an automatic export of repository internals:

- only observable task-level facts and user-provided answers are collected locally;
- review, redaction, and approval happen before publication;
- publication should not proceed from a dirty final Git snapshot;
- sensitive details can be removed or generalized before anything is shared;
- the public draft describes results, process, and limitations—not project secrets.

Read the full explanation: **[How Field Reports work]({{FIELD_REPORT_DISCUSSION_URL}})**.

Publish your own report in the **Field Reports** category.

## Try it

Install the **release asset** `knowledge-v3.4.0.zip`, not GitHub's generated source archive. After import, start a meaningful task with `agent-task begin` and finish it with `agent-task finish` plus physical tests.

The next public benchmark should be built around real repository patterns. Which scenario should we test first: monorepo ownership, stale documentation, generated source-of-truth, PR impact, or multi-agent handoff?

---

### Evidence boundary

- Compatibility and release evidence apply to the 3.4.0 release line.
- The 48-case routing stress suite was bound to the exact final RC artifact before the stable repack.
- These numbers do not imply any model-accuracy, provider-token, API-cost, or guaranteed-speed claim.
