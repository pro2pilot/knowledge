# Linux native verification backend

The separate administrator-installed service remains an unadmitted production
path. Its new root-native UID history and the exact remaining integration
boundary are documented in [Linux native service history](linux-native-service-history.md).
That persistence component does not change the namespace backend described here.

## Contract and supported environment

`linux_pid_namespace` creates a separate user namespace and PID namespace for each owned verification boundary. A small C program is the namespace init and an outside C keeper owns its exact pidfd. The public watchdog uses an outer boundary for the authority; that authority creates an inner boundary for command execution. A detached process, `setsid`, reparenting, or a further descendant PID namespace does not leave the ancestor PID namespace.

This is a guarantee about descendants of the admitted process. It is **not a filesystem, network, resource-limit, or hostile-code sandbox**. Commands retain ordinary access to project files and networking. A request to an existing external daemon can create work outside the descendant boundary, just as with other process-tree containment mechanisms; that work is not covered by this proof.

Runtime requires a Linux kernel with usable user/PID namespaces and pidfds,
readable native process identity through procfs, a permitted UID/GID map, and
the packaged native helper for the current architecture. The runtime checks the
helper's manifest, source and binary hashes, byte count, and executable bit; the
`--probe` operation then tests actual namespace setup and cleanup. A passing
capability probe reports `requires_runtime_setup`: it is not itself successful
verification admission. Runtime does not compile the helper or invoke
`/usr/bin/unshare`. Helper compilation belongs to package build time. There is no
host cgroup modification, privileged service installation, or global mount
operation. If admission fails, native verification is unavailable before
workload execution. Doctor and read-only diagnostics remain separate from
native verification capability.

The runtime package carries the C source, JavaScript adapter, architecture-matched
prebuilt executable, and `verification-linux-namespace.manifest.json` under
`tools/lib/native/linux-<arch>/`. `preparePackagedHelper()` verifies the packaged
source and executable against the manifest. Production invocation uses the
isolated preparer's private executable snapshot passed through fixed trusted IPC;
the snapshot has a private directory and executable mode, and its inode and
contents are checked after writing. Standalone maintainer entrypoints may verify
the packaged executable directly. There is no runtime compile fallback or
caller-UID compiler cache. Descriptor hashes bind the exact helper bytes used;
a changed helper is not silently accepted for recovery of an older descriptor.

Capability is checked in the environment in which verification will actually
execute. A Linux VM or container is Linux evidence, not macOS native evidence.
This PID-namespace backend is Linux-only. The product's separate Darwin
isolated-copy pipeline is opt-in and disabled by default; see the
[macOS broker guide](native-darwin-broker.md) for its request flags,
administrator-installed broker and UID provisioning. Linux namespace results do
not qualify the separate Darwin execution path.

## Admission and work gate

The adapter is `tools/lib/verification-linux-namespace.js`. The native source is the adjacent `.c` file.

```js
const { worker, job } = spawnLinuxContainedWorker(
  process.execPath,
  [workerScript],
  { stdio: ['pipe', 'pipe', 'ignore', 'ipc'] },
  { lifetimeMs, onFailure, trustedAuthority: false }
);

await job.ready;
// Persist job.descriptor in the owned attempt before any permit.
job.permit();
await job.started;
// The pinned Node worker can now receive its IPC run request.
```

`ready` means that native namespace init and the inert pre-exec worker exist and their birth identities have been observed. The requested Node program has **not** executed. The keeper accepts `permit` once. A closing or cancelled job cannot later be permitted. `started` confirms successful exec before the controller sends verification work. The outer watchdog persists the containment descriptor before permitting authority execution; the inner worker is also gated and is already covered by the outer namespace.

The `worker` object is the Node `ChildProcess` handle for the outside keeper; its IPC channel is inherited by the actual contained Node worker. Its `.pid` must not be confused with the contained worker identity. Use `job.identities.worker`. Identities contain both `pid` in the observer's PID namespace and `proc_pid` in the inherited procfs view. These differ for a nested boundary. Birth comparison uses boot identity, process start ticks and namespace identity; the ISO `os_creation_time` exists for compatibility and is not the sole recovery identity.

The descriptor includes the boot ID, observer namespace and procfs identity, init/worker/controller/keeper births, helper hashes, capability profile, and the actual procfs mode. The control layer binds the complete descriptor digest to an immutable attempt generation and its reserved spawn records.

## Capability separation and procfs

The keeper does not mount or replace host procfs. The tested environment denied a fresh procfs mount inside a new mount/user/PID namespace because of its inherited procfs restrictions. The backend therefore declares `procfs_mode: inherited_ancestor_view`. Some process metadata remains visible. A private procfs or full container-isolation claim is not made.

The trusted init retains the capabilities of its new user namespace. A command worker drops its permitted, effective, inheritable and ambient capabilities, sets `no_new_privs`, and locks the securebits that prevent root exec from restoring capabilities. No native control fd, parent pidfd, or procfs directory fd is inherited by the execed worker. Only stdin, stdout, stderr and the intended Node IPC channel are passed through.

The pinned outer authority uses a separate, explicit `trustedAuthority: true` setting in the watchdog implementation. It retains only **CAP_SETFCAP inside its own newly created user namespace**, with matching inheritable/ambient state. Linux's rules for mapping parent UID 0 require this when creating the inner user namespace. This does not grant a host capability. The setting is not a verification-request option. The command worker always receives the zero-capability profile. Physical tests check both profiles after Node exec and verify denial of access to init/controller memory, environment, namespace handles and private control fds.

Before native helper calls, `nativeEnv()` removes `LD_*` dynamic-loader
overrides; it does not launch a compiler or construct a compiler environment.
The capability `--probe-nested` subprocess has a 20-second caller timeout. Its
original native 15-second deadline encloses both namespace levels and both
drains. Ordered outer-ready, inner-ready, inner-closed and outer-closed receipts
must bind the actual caller, keeper, boot, procfs and nested births; both closures
require zero active processes and reaped namespace init. The fixed outer
canary self-execs a fixed native controller mode, preserving the mapped helper
inode and the trusted-authority capability profile. That controller forks the
same mapped helper with `--probe` and waits for that exact child. This preserves
the real authority-to-helper parent relationship: capability-full namespace init
is deliberately not used as the inner helper's readable controller. The inner
zero exit is required before the outer pidfd drain. No Node or project command runs in this probe.
Legacy `--probe` remains a one-level component operation and cannot satisfy the
exported capability check by itself. `job.close()` uses
a 30-second default cleanup allowance unless the caller supplies another
budget; it latches an unconfirmed result when the allowance expires. Other
observer operations use their own explicit bounded timeouts. These are
observation/cleanup budgets, not guarantees that kernel I/O or an uninterruptible
task returns by a wall-clock deadline.

## Capability depth and refusal

The public `runVerificationTests` path first creates the ordinary command
ownership namespace (level 1). Its owned supervisor then performs the nested
prerequisite probe before `beginAttempt`: the probe's authority-profile level 2
and zero-capability worker level 3 match the later watchdog authority and its
command worker. A direct host capability call creates two new levels from the
caller's current namespace; it does not qualify the complete three-level public
Node pipeline. Actual work still performs its own admission and native cleanup.

A host can permit a first user namespace while denying a nested creation. The
legacy one-level probe cannot establish this prerequisite. The new capability
check refuses an incomplete nested transcript, a changed birth, nonzero inner
exit, or missing drain. It does not change AppArmor policy or retry with weaker
containment. Unavailable capability is a refusal result, never release evidence.

## Cleanup proof

Closing a job sends a stop request to the outside keeper. The keeper signals its already held init pidfd, then waits for that exact init process. Linux completes namespace teardown before making the namespace init finally exited. A successful regular proof additionally requires the keeper's own actual exit and its authenticated `closed` message:

```json
{
  "status": "completed",
  "method": "linux_pid_namespace",
  "active_processes": 0,
  "namespace_drained": true,
  "init_exit_observed": true,
  "init_reaped": true,
  "worker_exited": true,
  "keeper_exited": true
}
```

The proof also includes the exact descriptor digest and helper binary hash. Sending a signal, observing the command worker's exit, or finding no process-group members is insufficient.

The trusted init arms `PR_SET_PDEATHSIG` after setup. It also checks an inherited exact keeper pidfd, closing the race in which the keeper died before the signal was armed. `getppid()` is not used for this check because it can be zero inside the child PID namespace. The keeper has its own parent-death protection. The init and keeper never transfer those handles to command code.

If a keeper is stopped, an OS operation is stuck, or a cleanup readback is missing, `job.close` returns an unconfirmed result after its cleanup budget. The result is latched: a later exit cannot upgrade the same close operation to success. Kernel-uninterruptible I/O can still prevent prompt exit; no process supervisor can honestly replace an unobserved exit with a wall-clock guarantee. The resource claim remains quarantined until valid native recovery.

## Native recovery

`recoverContainer(descriptor, { cleanup_timeout_ms })` is the native operation underneath control-layer recovery. The control layer must first fence the attempt, reserve recovery ownership, and forbid ACK release. Recovery never creates a successful verification result.

Recovery first resolves the exact init identity and, when still live, obtains its pidfd, checks the anchored proc directory again, signals that pidfd and waits for final exit. It then resolves the outside controller and keeper. The order preserves direct init-exit evidence before parent-death handling could remove the init. A worker's exit is derived from the bound namespace drain proof; outside processes require their own exact evidence.

An already finished init has a separate proof branch. The same boot, observer PID namespace and procfs identity must match the retained descriptor. A procfs `ENOENT` alone is not accepted: the native helper also calls `pidfd_open` in the saved observer namespace. If that PID still exists but procfs cannot identify it, the result is unconfirmed. Only an actual kernel `ESRCH`, or an anchored, positively observed different birth, can support an old-init finality inference. A replacement process is never signalled. A matching birth with a different namespace is rejected.

Direct pidfd evidence and historical finality inference are explicitly distinguished:

| Evidence | Result fields |
| --- | --- |
| Exact init pidfd finally exited | `init_exit_observed: true`, `init_exit_basis: linux_pidfd_exit` |
| Exact old init no longer exists | `init_exit_inferred: true`, `init_exit_basis: linux_boot_birth_absent` |
| The numeric PID now has another birth | `init_exit_inferred: true`, `init_exit_basis: linux_boot_birth_replaced` |

`init_reaped` is true only for directly observed reaping: regular `waitpid` or native pidfd hangup. Absence/replacement uses `init_release_inferred: true` instead. A zombie with the matching birth can still yield a valid final-exit pidfd proof even when its procfs namespace symlink has already disappeared. None of these branches uses a lease age or PID disappearance alone as a generic process-tree proof.

`currentProcessIdentity()` and read-only `verifyProcessExit()` support exact recovery-owner takeover. An active recovery owner is not replaced because a TTL elapsed.

## Verification and limits

This page's current source revision is
`independent-audit.20261027.reliability.5`. Earlier physical results apply only
to their pinned historical source. The fresh audit5 matrix is in progress at
this documentation checkpoint; see [audit status](audit-3.4.4-rc5.md). No final
passing outcome for the new source is asserted here.

The accepted separate native system broker with isolated project import,
protected Node authority, KVE/ACK, nested ownership and durable restart recovery
is **not implemented or production-qualified**. The reliability.5 component
fault mini-matrix does not close those integration requirements or the full
production fault matrix. Its held private pipes do not simulate a hung disk or
kernel D-state. Separate QA actors/receipts are not shipping production APIs.

Run `node tools/self-test-linux-namespace.js` on an actually supported Linux
host. An unavailable capability returns `BLOCKED` and a nonzero exit code, not
PASS. The physical suite covers pre-permit work denial, native IPC/birth
identity, protected handles, detached/reparented children, actual double-fork
plus nested PID namespaces, nested authority/worker capability profiles,
compiler-related environment injection against the pinned packaged helper, keeper
crash, cleanup-budget exhaustion, current-owner observation, old-birth safety,
live recovery, post-controller-crash recovery, and boot/namespace mismatch. The
nested-descendant fixture invokes `/usr/bin/unshare` for its synthetic child
namespace; this is a self-test prerequisite, not a runtime backend dependency.

A historical reliability.4 fixed-native-actor system-service experiment reported
[`PASS_SCOPED_QA` in run 40548260744](https://github.com/pro2pilot/knowledge/actions/runs/40548260744):
21 named QA check groups passed, alongside six socket-parser checks, six memory/FD
denials each for C and W, and a four-attempt UID lifecycle. It did not execute
Node commands in isolated copies or integrate with this KVE verification backend;
the result explicitly leaves production-backend and release qualification false.

The later reliability.4 Node component [run
40566572410](https://github.com/pro2pilot/knowledge/actions/runs/40566572410)
accepted its readonly import/authority/worker slice after two retained failed
attempts. That result also remains bound to the earlier source; it did not
implement or qualify the production service or its full fault matrix.

The old-birth test uses an explicitly synthetic historical birth against a real current process. It does not claim to force kernel PID-number recycling. A stopped-keeper fault uses a deliberately short test-only budget; it does not change production budget defaults. Kernel D-state is handled fail-closed but is not manufactured by dangerous host-I/O fault injection. Linux x64 physical evidence does not certify other architectures, Windows, macOS, or all distributions.

Regular successful finalization requires the regular full proof. Only a reserved native-recovery operation may use the separate historical-init inference union. Unknown spawn history without a trustworthy bound descriptor, another boot/observer namespace, changed helper pins, denied identity access, or incomplete cleanup stays unconfirmed.

## Primary references

- [Linux PID namespace contract](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html): namespace membership, descendant visibility, init termination and prevention of new processes after init death.
- [Linux `zap_pid_ns_processes`](https://github.com/torvalds/linux/blob/master/kernel/pid_namespace.c) and [exit ordering](https://github.com/torvalds/linux/blob/master/kernel/exit.c): namespace tasks are drained before init final-exit notification.
- [pidfd API](https://man7.org/linux/man-pages/man2/pidfd_open.2.html): exact process handles, final thread-group exit notification and hangup after reaping.
- [Parent-death signal contract](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html): parent-thread semantics, setup race and credential transitions.
- [User namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html): UID mapping and namespace capabilities, including the parent-UID-0 mapping condition.
- [Procfs documentation](https://docs.kernel.org/filesystems/proc.html): procfs visibility and namespace relationships.
