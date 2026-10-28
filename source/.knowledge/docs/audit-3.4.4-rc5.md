# 3.4.4 RC5 reliability audit status

Current source revision: `independent-audit.20261028.reliability.8`. Package
version remains `3.4.4`, candidate label remains `RC5`, and the intended runtime
asset remains `knowledge-v3.4.4.zip`. This is an unpublished candidate. Its full
release gate is the maintainer's final local check. Exact final source/ZIP hashes,
installed-candidate results and retained failures are in the accompanying audit
handoff; a successful component does not qualify a different artifact.

## Implemented continuation

The explicit [native Linux service](native-linux-service.md) now connects the
protected native broker to the public verification API. Its ordinary-user
preparer compiles and pins the fixed native runtime; the administrative script
runs fixed OS utilities and native code. Project Node/Python never runs as host
root. The production service uses private UIDs, isolated source import, fresh
A after importer drainage, typed nested W commands, durable UID history and
separately enrolled storage S actors.

OPEN is gated until its descriptor is durably bound. Failure, cancellation and
timeout start storage drainage immediately inside the original cleanup epoch.
Success requires physical native closure, immutable KVE/KVF readback, signed
acceptance, final CAS, final storage closure and native-client EOF. An overdue
live writer blocks new admission. Lost custody preserves a fence and cannot
be replaced with PID absence, a timer or a late receipt.

Windows QA now uses the existing owned-command/Job path, including held pipes,
actual pending named-pipe reads/writes and cancellation before the work permit.
Team cancellation uses that same native ownership path. Native lock owner v3
and the existing Windows scope provider support exact crash recovery; unknown
legacy owners still require independent evidence. There is no added generic
supervisor or new Windows native module.

## Source-bound physical checkpoints

These are observed checkpoints; later source and package changes need their own
binding. The final installed-candidate matrix and artifact manifest are supplied
separately, so this page does not contain a self-referential ZIP digest.

| Checkpoint | Observed scope |
| --- | --- |
| [Windows source run 40679517087](https://github.com/pro2pilot/knowledge/actions/runs/40679517087) | x64 and ARM64: 32 applicable source assertions with two exact Linux-only exclusions (including six physical custody cases and two actual Team CLI crash/recovery cases), plus normal Team workflow and forced cancellation after two native scopes. |
| [Linux source run 40685710431](https://github.com/pro2pilot/knowledge/actions/runs/40685710431) | x64 and ARM64: seven public KVE/KVF/ACK and failure/reuse cases, five native cases, actual protocol mutations, reader/client regression tests and 56 native boundary checks. |
| [Linux fault run 40686349420](https://github.com/pro2pilot/knowledge/actions/runs/40686349420) | Both architectures repeat the public/native cases, add actual controller death with retained-handle observation and a fenced public claim, and observe a real delayed-read D state across its original deadline. Its device-fixture retirement returned EBUSY; that FAIL is preserved and is not relabeled as a complete successful lane. |

The isolated native cases include cancellation before PERMIT (zero admitted
commands) and cancellation while the native broker's main process is stopped.
The latter observes exact keeper/init/storage exits while the broker remains
stopped; native terminal and storage receipts are required after it resumes.
The public positive probe also admits a detached descendant that retains output
pipes. A parent exit or root-worker exit alone cannot produce acceptance.

## Platform and recovery limits

The unprivileged [Linux namespace backend](linux-native-backend.md) retains its
own prerequisites. Hosted Ubuntu 24.04 ARM64 previously denied nested setup;
that refusal is historical evidence for that backend. The explicit root-native
service supplies a different administrator-provisioned path without changing
AppArmor or globally enabling unprivileged namespaces. It does not silently
replace general Flow/Team command execution.

The macOS production path remains explicitly configured and disabled by default.
Broker provisioning and writable workspace provisioning are separate tasks.
Observed hosted macOS prerequisite probes reported SIP disabled; they do not
qualify stock-SIP behavior. The maintainer must include required macOS hosts in
the final local platform/release checks. No SIP or security-policy downgrade
was performed to manufacture a passing result.

Kernel-uninterruptible I/O can outlive cancellation. The original deadline stays
fixed; custody and durable fences survive, and late physical exit cannot
produce an in-budget successful receipt. Broker loss with unresolved durable
state remains quarantined. There is no history reset, UID recycling, age-based
unlock, or automatic adoption of an unknown ownerless lock.

The historic second ownerless-lock creator remains unknown. Modern controlled
crash/recovery tests do not identify that historical actor. Old FAIL files,
Doctor warnings and scope restrictions remain part of the handoff history.

## Final local release check

Use the exact supplied candidate ZIP and its checksum. Its accompanying source
snapshot and QA scripts reproduce the engineering checks. The full canonical
release gate is run locally by the maintainer as the final pre-release step;
no result in this document asserts that it already ran. Publishing the release
is separate from preparing and testing the candidate.

The prior reliability.5 checkpoint remains in the previous committed source
and retained audit artifacts. The earlier operational discussion is preserved
in [the historical 2026-10-19 audit](historical/audit-3.4.4-rc5-operational-20261019.md).
