# Install .knowledge

This source belongs to **3.4.4 RC5**, an unpublished development snapshot.
The intended runtime name is `knowledge-v3.4.4.zip`; this is an unpublished audit
candidate with no release certification. Identify the exact ZIP and scoped test
results by SHA-256 in its accompanying handoff. For ordinary
production installation use the [latest published release](https://github.com/pro2pilot/knowledge/releases/latest).
For candidate testing, use an explicitly supplied installable ZIP with its own
manifest and results. An audit source snapshot is not an installable release.
Never substitute GitHub source downloads for a release asset.

This is audit revision `independent-audit.20261021.darwin-pipeline.4`.
The preceding frozen POSIX/recovery runtime remains a different artifact;
do not use its PASS results to qualify this source. Version-only update checks
do not distinguish RC5 derivatives. Linux requires native prerequisites; macOS
verification remains unsupported and refuses before work. The [native broker prototype](docs/native-darwin-broker.md)
does not install or enable itself and is not connected to common verification, KVE
or ACK finalization. See
[audit installation and limits](docs/verification-execution-contract.md).

The separately invoked [Darwin diagnostic](docs/darwin-diagnostic-pipeline.md)
requires an administrator-initialized diagnostic service and an explicit isolated
copy. It does not install or enable a broker and cannot certify this candidate.

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
starting probes. Linux uses the bundled C helper and requires system C compiler,
util-linux `unshare`, user/PID namespaces and pidfds. Actual preparation and a
namespace probe run before a project claim is reserved. macOS native verification
remains unsupported and returns `verification_containment_unavailable` before
starting a worker or probe. The separate broker is an experimental diagnostic
component; this install guide does not expose a supported setup command. Its
M3c7 five-second autonomous monitor requires independent slow/load qualification;
targeted CI results do not establish stock-SIP qualification or common pipeline
integration. See its [development note](docs/native-darwin-broker.md) for
administrator prerequisites.
Other tools remain subject to their own operational checks. See
[the RC5 contract](docs/audit-3.4.4-rc5.md).

## Accepted verification and Team results (RC5)

Native verify now returns signed `verification_acceptances`. Keep this field
when reusing KVE IDs in a receipt; `agent-task finish` carries it automatically.
Legacy KVE is command-only evidence and cannot authorize new certification.
Team Status and Inspector show the final per-attempt outcome after release;
missing finalization is incomplete, not successful. See the
[acceptance and retry contract](docs/verification-execution-contract.md).
Linux native execution requires a successful namespace capability probe; macOS
remains unsupported and refuses before work. This unpublished audit candidate has
no release certification. Identify the exact ZIP and scoped test results by
SHA-256 in its accompanying handoff.
