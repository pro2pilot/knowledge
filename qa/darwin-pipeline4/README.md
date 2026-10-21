# Darwin pipeline4 physical QA harness

This directory is reserved for the independently pinned pipeline4 QA build and its physical-host controller. It must never consume the historical `qa/darwin-broker/SOURCE_RECEIPT.json`, `COPY_SOURCE_RECEIPT.json`, or old matrix candidate receipts.

The workflow runs on manual dispatch or a push to the explicitly scoped matrix branch when this QA directory or workflow changes. It uses separate shipping-source and QA-binary pins. A passing compile, CLI diagnostic, or launchd observation is infrastructure evidence only; it does not qualify native capability or trusted OS origin. Artifacts are built from an allowlist of public hashes, booleans, exit codes, platform/architecture and bounded stage names. Raw logs, request/response frames, run IDs, socket paths, protected fixture configuration, root receipts and node/workspace contents stay on the private runner.

`KNOWLEDGE_DARWIN_QA_IO` and the launchd-activated `KnowledgeQAPersistenceGate` are QA-only. The compile macro is absent from the shipping binary. A gate run must delay a real file persistence boundary and report it as a QA persistence gate, never as an OS scheduling or kernel-I/O stall. The QA-only `birth-observer.c` helper observes exact process births without signaling them; the runner uses it to verify command and authority exit around the active stop case.

The public evidence directory contains only `PINS.json`, `summary.json`, `native-proofs.json`, `compiler-diagnostics.json`, and `runtime-binaries.json`. The workflow uploads those exact files and a duplicate summary. It excludes private command output, request/configuration files, registry state, raw reports and persistence-gate frames. The summary records the typed `csrutil status` observation and its stdout digest; this does not qualify the hosted runner's physical hardware or filesystem.

The stable native and JS pin manifest is staged in this QA workspace. The runner still needs review and a user initiated manual workflow dispatch on the intended Intel and ARM hosts. No native compile or physical run has been performed while authoring these files.
