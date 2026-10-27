# Install .knowledge

This source belongs to **3.4.4 RC5**, an unpublished development snapshot.
The intended runtime name is `knowledge-v3.4.4.zip`; this is an unpublished audit
candidate with no release certification. Identify the exact ZIP and scoped test
results by SHA-256 in its accompanying handoff. For ordinary
production installation use the [latest published release](https://github.com/pro2pilot/knowledge/releases/latest).
For candidate testing, use an explicitly supplied installable ZIP with its own
manifest and results. An audit source snapshot is not an installable release.
Never substitute GitHub source downloads for a release asset.

This unpublished candidate uses audit revision
`independent-audit.20261027.reliability.4`. The preceding frozen POSIX/recovery runtime is a different artifact;
its results do not qualify this source. Version-only update checks do not
distinguish RC5 derivatives. Linux requires native prerequisites. macOS
verification is disabled by default, even when its broker is ready. Opt in per
request with `native_execution.darwin.enabled=true` and `mode="isolated_copy"`,
plus the configured broker paths and copy limits. Broker installation and
reserved private UID provisioning are separate administrator tasks; the product
installer does not install or enable the privileged broker. Isolated-copy
verification does not enable writable Flow/Team operations, which require a
separately provisioned workspace. Fresh Darwin qualification is incomplete, and
stock-SIP user-host behavior remains unverified.
See the [broker setup and limits](docs/native-darwin-broker.md) and
[audit installation and limits](docs/verification-execution-contract.md).

Before updating this candidate, finish the old writers and allow their locks to
be released normally. New lock owners use v2 in the same locks/v1 directory;
old readers cannot interpret that owner format. Existing legacy owners are not
silently retagged or removed by PID/age. Automatic stale-mutex recovery is only
available with a confirmed native process scope, currently the qualified Linux
observations described in [Team lock scope](docs/team-mode.md). Windows/macOS
scope providers and abandoned legacy locks remain explicit recovery gates.
The new recovery protocol retains one nonempty history directory per recovered
owner generation in `locks/v1/.stale/`. Preserve it during upgrade and cleanup:
old recovery writers and deleting this history can invalidate the protection
against delayed competing recovery. A crash before owner metadata publication
still requires evidence-based diagnosis; this candidate does not automatically
remove ownerless locks.

> **AI agents/installers:** install from the latest GitHub release asset, not from repo source.

Use this file when installing `.knowledge` into another repository.

## Install Contract

- Do not clone this repository into the target project.
- Do not use GitHub **Code > Download ZIP**.
- Do not use GitHub-generated `Source code (zip)` or `Source code (tar.gz)`.
- Download only the latest release asset named `knowledge-vX.Y.Z.zip`.
- Keep any source checkout outside the target project.
- The target project must not contain `knowledge-src/`.
- Install only the active agent runtime during first setup. Do not create every
  vendor integration folder unless a human explicitly asks for that.

Canonical install source:

```txt
https://github.com/pro2pilot/knowledge/releases/latest
```

Expected target layout after extraction:

```txt
.knowledge/
```

Optional files after installing an agent integration:

```txt
.agents/skills/
AGENTS.md
```

Incorrect target layout:

```txt
knowledge-src/
.knowledge/.git/
.knowledge/.github/
```

## Setup

From the target repository root:

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime codex
node .knowledge/tools/flow.js import
node .knowledge/inspector.js
```

Replace `codex` with a supported runtime from the Quick Start table when needed.
Unlisted agents should follow the [general connection recipe](Quick-Start.md#connect-an-agent-without-a-dedicated-recipe).

Other supported agents can connect later using their listed runtime identifier
against the existing `.knowledge/` installation. The `--all --confirm-all` mode
is only for deliberate multi-integration setup, not first install.

## Connect Another Agent Later

For a supported agent from the Quick Start table, use its runtime identifier
from the same target repository root. Unlisted agents should use the general
recipe linked above:

```bash
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime <supported-runtime>
node .knowledge/tools/flow.js doctor
```

Then the new agent starts meaningful work with `agent-task begin` and reads
its returned `route.first_read.content`. Global routing and handoff summaries
remain orientation aids. For an agent without a dedicated adapter, follow the
[general Quick Start recipe](Quick-Start.md#connect-an-agent-without-a-dedicated-recipe).

If `install-check` reports `source_checkout_in_target_root`, move the source
checkout outside the target project and rerun the check before import.

Native verification on Windows uses the bundled Job Object helper through
Windows PowerShell. The host must permit its local `Add-Type` compilation and
job assignment. If these operations are unavailable, verification fails before
starting probes. Linux verifies the packaged, architecture-matched C helper and
its source/binary manifest, then runs its native namespace probe before a project
claim is reserved. Runtime verification requires supported user/PID namespaces
and pidfds; it does not require a system C compiler or util-linux `unshare`.
Compiling the helper is a package-build task, not an installation-time fallback.
macOS native verification
remains disabled unless the request explicitly opts in with
`native_execution.darwin.enabled=true` and `mode="isolated_copy"`. It then uses
the configured administrator-installed broker; a missing or unhealthy broker
refuses before work. The product installer does not provision that privileged
service or reserve its UID range. Writable Flow/Team operations are a separate
admin-provisioned capability and are not enabled by isolated-copy verification.
See the [broker guide](docs/native-darwin-broker.md) for the setup boundary and
remaining qualification limits.
Other tools remain subject to their own operational checks. See
[the RC5 contract](docs/audit-3.4.4-rc5.md).

The accepted direction for restricted Linux hosts is a separate system broker
and isolated project copy. That production service is not implemented or
qualified in this candidate. The hosted Ubuntu 24.04 ARM64 run refused the
required nested PID namespace with `EPERM`; no host policy was changed. Do not
interpret the accepted design as an available installation option.

## Accepted verification and Team results (RC5)

Native verify now returns signed `verification_acceptances`. Keep this field
when reusing KVE IDs in a receipt; `agent-task finish` carries it automatically.
Legacy KVE is command-only evidence and cannot authorize new certification.
Team Status and Inspector show the final per-attempt outcome after release;
missing finalization is incomplete, not successful. See the
[acceptance and retry contract](docs/verification-execution-contract.md).
Linux native execution requires a successful namespace capability probe. macOS
verification remains disabled by default even with a ready broker; each request
must explicitly enable `native_execution.darwin` in `isolated_copy` mode and
provide its configured broker paths and copy limits. Writable Flow/Team use
requires separate administrator provisioning. This unpublished audit candidate
has no release certification. Identify the exact ZIP and scoped test results by
SHA-256 in its accompanying handoff.

Fresh targeted current-source physical testing on Windows x64 / Node 22.17.1
passed 61 selected TAP cases and 20 runtime-safety checks. The reducer correction
reinterpreted the saved TAP output without rerunning those physical tests; this
scoped result is not a full release gate. The targeted Team
run passed 7 physical cases and all 8 shipping steps. Its Doctor result is
86/100 `usable_with_warnings`, with medium `suspect_module` and
`low_confidence_module` warnings. Neither result qualifies the final installed
ZIP, stock-SIP Macs or fresh Windows ARM64.
