# Release Notes

## v3.4.4 RC5 — Linux containment and fenced native recovery

Audit revision: `independent-audit.20261020.windows.4.posix-recovery.1`.
This continues the exact supplied windows.4 runtime and source. Version 3.4.4
and candidate label RC5 are unchanged; the new handoff SHA identifies the bytes.
The full release gate and publication have not been performed.

Linux verification now uses private user/PID namespaces, pidfd process identity,
a pre-exec work gate and native init reaping. A real prerequisite probe precedes
project admission. Native recovery durably fences the former owner before any
termination; concurrent recovery is serialized and failed recovery cannot
restore the right to issue PASS. Descriptor-bound cleanup receipts survive a
crash between kernel cleanup and the final state commit.

KVF/ACK v3 pins the new implementation and platform proof. Historical Windows
v2 exact16 and v1 exact8/exact10 evidence keeps its original reader contract.
The supplied post-freeze Inspector portability test correction is included.
Generous work, meaningful-progress and cleanup profiles are preserved.

macOS still requires a suitable kernel or delegated backend. The changed
Windows native recovery helper requires fresh Windows kernel verification.
Legacy descriptorless claims and abrupt loss of the last Windows Job handle
without a durable empty receipt remain explicit recovery limitations. The
historical second ownerless-lock creator remains unknown. See the
[execution contract](docs/verification-execution-contract.md) and audit handoff.

The following entries are historical and refer to their own pinned artifacts.

## v3.4.4 RC5 — work and cleanup contract

Audit revision: `independent-audit.20261020.windows.4`. Unpublished; full release
gate not run. Work, meaningful progress and cleanup have separate configurable
limits. Cancellation and timeout cannot become late PASS; unconfirmed cleanup
keeps a durable claim. New ACK/KVF v2 records bind the separate timing budgets,
while historical v1 evidence remains readable under its original rules.

The resource guard also serializes currency issuance, repair application and
recertification with verification admission. Doctor reports the retained claim
as an operational blocker separately from content trust.

The updater now admits the shipped verification policy as a managed system
file. Synthetic privacy fixtures construct their test tokens explicitly; no
provider credential is included. The preceding windows.3 artifact and its
failed update checks remain separate audit evidence.

The former millisecond caller-return requirement was superseded by the user.
Historical measurements remain evidence for their own source bytes. POSIX
containment, general recovery after lost kernel ownership and the historical
second ownerless lock creator remain open. See the [execution contract](docs/verification-execution-contract.md).

The entries below describe earlier revisions. Their test results do not certify
this revision.

## v3.4.4 RC5 вЂ” Windows authority watchdog

Audit revision: `independent-audit.20261019.windows.2`. Unpublished; full release
gate not run. This continuation preserves the supplied 14-path follow-up and
adds an independent watchdog around native preparation, key generation,
receipt readback and signing. Both command and authority Jobs must complete
before acceptance leaves the runner. The transport no longer adds 7000 ms.
Caller admission checks the original deadline and bounds property names and
JSON escaping before serialization. Physical Windows regressions exercise
synchronous stalls, authority/watchdog interruption and detached descendants.

Historical eight-pin native batches remain readable; new producers pin all ten
implementation files, and current currency includes the watchdog authority.
Upgrading can require factual currency revalidation without rewriting history.
Linux/macOS native remains unavailable. New cross-platform runs, live providers,
full release gate and publication are deferred. See [the current audit contract](docs/audit-3.4.4-rc5-windows-watchdog.md).

## v3.4.4 RC5 вЂ” follow-up to the Windows reaudit

Audit revision: `independent-audit.20261019.windows.1.followup.1`. This candidate continues
the exact 448-file Windows source. Worktree Status now applies the supported
`KNOWLEDGE_DISABLE_GIT_DISCOVERY=1` setting consistently with workspace
registration, retaining repository/workspace composite selection and explicit
`--repo-id` behavior. Regression tests cover actual Git repositories.

The handoff separately fixes and tests its evidence collector: retained raw
logs, input identity failures and scoped reruns must remain individually
verifiable. Historical Windows results belong to their pinned parent source;
this derivative is checked on Linux. Native verification remains unavailable
on Linux/macOS. The original caller wall-return requirement for `timeout_ms`
is still open: rejecting late acceptance does not bound a blocked synchronous
call. No full release gate, publication or live-provider certification is
claimed. See [the follow-up contract](docs/audit-3.4.4-rc5-windows-followup.md).

## v3.4.4 RC5 вЂ” Windows reaudit candidate

Audit revision: `independent-audit.20261019.windows.1`. This unpublished candidate integrates the
October 19 mechanism audit and adds fixes for canonical ZIP file/directory
conflicts, portable names in the standalone ZIP helper, repository-bound Team
status and Windows Inspector launcher paths. The native Doctor regression now
checks reopening after a new source change while preserving the original KVR.

The exact candidate handoff contains fresh Windows results and their limits.
Linux/macOS native verification remains unavailable; no new POSIX run, live
provider certification, full release gate or publication is claimed. See the
[current audit contract](docs/audit-3.4.4-rc5-windows-reaudit.md). Older sections below describe
their own historical artifacts.

## v3.4.4 RC5 audit.1 - Native acceptance and Team completion

Audit revision: `independent-audit.1`. This unpublished derivative uses the
supplied RC5 as its base. It is distributed separately as
`candidate/knowledge-v3.4.4.zip` inside the audit.1 handoff; identify it by its
audit revision and new SHA, not by the shared runtime basename.
Native verification refuses on Linux/macOS before launching any probe because
the prior process-group backend could miss detached descendants. POSIX native
execution remains unavailable. Doctor now detects unsafe reserved layout
parents and dangling links; public native inputs reject active caller data.
See [the audit revision](docs/audit-3.4.4-rc5-audit1.md) for behavior, tests and
remaining limitations. The full release gate has not been run. New KVE v2 batches require a signed
parent acceptance after confirmed Windows teardown. Team final status is derived
from per-attempt finalization records; old command-only KVE remains readable
but cannot authorize new closure or issuance.

## v3.4.4 RC5 - Operational locks and bounded native verification

**Status: unpublished candidate; full release gate not run.** Package/config/
install-manifest version: 3.4.4. Candidate label: `RC5`. Archive:
`knowledge-v3.4.4.zip`.

RC5 strengthens lock ownership and native verification on the RC4 base.
Doctor exposes unsafe state/project locks as operational blockers; team status
also inspects its registry lock. Cleanup uses the directory identity and owner
bytes captured by the current acquisition. Flow finalization preserves the
primary result and starts optional Inspector onboarding only after release.

Native verification uses one monotonic batch budget, including setup, sequential
checks, receipt publication and owned-process teardown. Windows assigns the
worker to a Job Object before commands start. Expiry, incomplete teardown and
transport failures cannot produce a successful batch. See
[RC5 operational changes and limits](docs/audit-3.4.4-rc5.md).

RC4 replaces raw Inspector JSON parser messages with a stable diagnostic, so
parser excerpts cannot bypass masking of child output. Source regression tests
also handle Windows path separators and native termination results explicitly.
Team Doctor failure diagnostics preserve the inner flow log and child identity,
with checks that reject paths outside the selected state root and linked parents.
Windows audit results and historical evidence recovery are recorded in the
separate original handoff. Those Windows results apply to the base RC5, not
this derivative. Incoming Linux results remain historical. The updated handoff
contains the new Windows results and exact byte identities. POSIX native
execution is unavailable; Linux/macOS execution is deferred.

RC3 adds the following corrections to the RC2 feature set:

- Doctor and sync use the same validated module ownership and preserve exact
  queue read guards. Ignored-card cleanup debt remains visible on later syncs.
- Readiness rejects malformed comparison inputs and unproven lifecycle closure.
  A typed file boundary covers that file only.
- Currency recovery independently reconstructs receipt, index and operation
  bytes. Public currency, native KVE and recording inputs use bounded inert-data
  admission; public recording output uses an explicit masked projection.
- Inspector, Restore Trust, native verification, workflow and updater child
  boundaries reject transport failures. JSON-required steps reject empty or
  invalid output; bounded capture supports reports up to the shared limit.
- Inspector and Restore Trust reject linked or escaping evidence destinations
  before starting child actions. Inspector journal appends use a short lock.
- Update post-checks may append only committed, exactly guarded sync/Doctor
  queue journals. Existing evidence remains byte-pinned, including factual
  currency and recording state when optional manifest lists are empty.

See [RC3 audit corrections and limits](docs/audit-3.4.4-rc3.md). The following
features remain part of the 3.4.4 candidate:

- Limits freshness certification to successful exact lifecycle closures.
  Protected context files remain pending after ordinary scoped verification.
- Requires an immediate chat notice describing blocked recording and its
  reason, with secret values masked and the notice in the user's language.
- Adds Inspector's Blocked recording panel and local `recording-blockers.js`
  CLI. An explicit user classification can cover one task or an exact existing
  repository path in this project, and can be revoked. It cannot override a
  secret-key field or a user write boundary.
- Fixes the `sk`/`pk` matcher that treated ordinary `skills/...` paths as keys.
- Adds review-bound factual currency receipts using v3 requests, exact-input
  batches and native KVE records. This projection reports current factual
  coverage for routing; it does not close lifecycle findings or application
  risks.
- Separates `knowledge_maintenance` from the primary engineering result in
  `agent-task finish`, including a user-language chat notice and next action
  when maintenance is blocked, requires review, or is deferred.
- Compares readiness over the same finding cohort and occurrences; reports
  additional current debt separately instead of inventing a score regression.
- Unifies typed registry/card ownership for routing and factual review, with
  conditional dependencies and physical directory scope handling.
- Preserves sync history by default and commits the lifecycle queue pair with
  exact byte guards. No destructive history-cleanup command is added.
- Captures large child JSON within a bounded limit and rejects spawn failures.

See [candidate details](.release-notes/v3.4.4.md) and
[upgrade notes](docs/upgrade-3.4.4.md). The prior release's gate evidence does
not certify this candidate.

See [Factual currency](docs/factual-currency.md) for supported commands,
request and review fields, and the one-unit batch workflow.

The explicit `sync-tracked.js --preserve-history` flag selects the same safe
preservation policy used by default. See candidate details for its scope.

## v3.4.3 - Covered recheck recovery

Fixes related stale-recheck closure, invalid-evidence rebinding, shared KVR
budget/telemetry accounting and durable file-fact coverage. Detects and safely
migrates the obsolete root gate, and authenticates extension signatures.
Also fixes Windows lock transitions, watcher shutdown, repeated updates,
fail-closed import, live Mem0 Unicode handling, and oversized Inspector requests.
See the [full change list](.release-notes/v3.4.3.md) and
[upgrade notes](docs/upgrade-3.4.3.md).

## v3.4.1 - Documentation and release-contract corrections

- Makes the integrated `agent-task` begin/finish workflow the only normal
  meaningful-task entrypoint in Quick Start. Direct `task-routing` commands
  are documented for advanced diagnostics and recovery.
- Replaces the hand-maintained update path inventory with
  `install-manifest.json`, the machine-checked system-path contract. This
  removes the obsolete `prompts/` path and keeps shipped paths aligned.
- Corrects the shipped configuration reference to `config.yaml`.
- Clarifies the stable v3.4.0 release notes without changing runtime behavior.

## v3.4.0 - Integrated task routing and evidence reuse

Adds the integrated `agent-task` begin/finish workflow so task-specific routing
is consumed before broad exploration and physical verification can be reused
for one exact safe Repair-on-touch closure. The release also binds finish to a
content-addressed first-read acknowledgement, rejects request/test-cwd path
escapes, and makes release packaging deterministic. It makes no comparative
speed, accuracy, error-rate, or model-token-savings claims.

## v3.3.0 - Safer local knowledge maintenance and task-scoped routing

Users of v3.2.11 can directly upgrade to v3.3.0.

- Agent integrations now coexist safely: Codex, OpenClaw, Hermes, and Devin share one runtime-neutral `AGENTS.md` managed block, while Devin and Windsurf use separate `.devin/rules/knowledge.rules` and `.windsurf/rules/knowledge.md` vendor files.
- Finding-specific repair and bounded Repair-on-touch preserve relevant
  verification while keeping unrelated maintenance visible.
- Doctor global health and task readiness are distinct outputs.
- Task-scoped routing reports a deterministic local first-read estimate as
  narrowing, overhead, neutral, or unavailable/not comparable; it is not
  provider-reported model-token usage.
- Field Report keeps local collection, translation, claim validation, approval, redaction, and optional publication state separate. Public drafts are English, retain an auditable question catalog, and now lead with an evidence-bound engineering-task table rather than internal counters. Task checks are content-addressed, overall outcome is derived from outcome-relevant rows, `.knowledge` health is shown separately, dirty final Git snapshots block GitHub publication, Discussion titles use a structured task title, and Repair-on-touch telemetry is classified as current, stale, invalid, or unavailable before any metrics are shown.
- Install, update, and release safety checks preserve curated knowledge and
  keep generated runtime state and maintainer material out of installed files.
- Installed agent integrations use the same four-state local-context estimate contract; maintainer benchmark and release-preparation tooling remain source-only.

The release contains focused approval, redaction, translation, publication
state, routing, repair, and update-safety regression coverage. It makes no
comparative speed, accuracy, error-rate, or model-token-savings claims.
