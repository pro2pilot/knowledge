# Install .knowledge

> **AI agents/installers:** install from the latest GitHub release asset, not from repo source.

Use this file when installing `.knowledge` into another repository.

## Install Contract

- Do not clone this repository into the target project.
- Do not use GitHub **Code > Download ZIP**.
- Do not use GitHub-generated `Source code (zip)` or `Source code (tar.gz)`.
- Download only the latest release asset named `knowledge-vX.Y.Z.zip`.
- Keep any source checkout outside the target project.
- The target project must not contain `knowledge-src/`.

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

Replace `codex` with the active runtime when needed.

If `install-check` reports `source_checkout_in_target_root`, move the source
checkout outside the target project and rerun the check before import.
