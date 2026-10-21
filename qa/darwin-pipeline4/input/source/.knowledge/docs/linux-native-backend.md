# Linux native verification backend

## Contract and supported environment

`linux_pid_namespace` creates a separate user namespace and PID namespace for each owned verification boundary. A small C program is the namespace init and an outside C keeper owns its exact pidfd. The public watchdog uses an outer boundary for the authority; that authority creates an inner boundary for command execution. A detached process, `setsid`, reparenting, or a further descendant PID namespace does not leave the ancestor PID namespace.

This is a guarantee about descendants of the admitted process. It is **not a filesystem, network, resource-limit, or hostile-code sandbox**. Commands retain ordinary access to project files and networking. A request to an existing external daemon can create work outside the descendant boundary, just as with other process-tree containment mechanisms; that work is not covered by this proof.

The backend requires a Linux kernel with usable user/PID namespaces and pidfds, readable native process identity through procfs, and a permitted one-user UID/GID map. At the first build it also requires a working system `/usr/bin/cc` or `/usr/bin/gcc`, `/usr/bin/unshare` supporting the flags used by the bootstrap, and the current Node executable. There is no package download, host cgroup modification, daemon installation, privileged service, or global mount operation. If admission fails, native verification is unavailable before workload execution. Doctor and read-only diagnostics remain separate from native verification capability.

The runtime ZIP carries C source and the JavaScript adapter. The native executable is compiled for the actual host and cached in a private directory scoped by the caller UID and user namespace. A build manifest records the source hash, executable hash, architecture, compiler hash and bootstrap hash. A reused cached executable must match its manifest and current source. A changed helper is not silently accepted for recovery of an older descriptor.

Capability is checked in the environment in which verification will actually execute. A Linux VM or container is Linux evidence. It is not macOS native evidence. The Darwin backend remains explicitly unavailable until a separately implemented and physically tested containment mechanism is provided.

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

Helper startup removes dynamic-loader injection variables. The compiler runs with a minimal fixed environment: a system executable path, `LANG=C`, `LC_ALL=C` and its own temporary directory. User compiler prefixes, include paths and library paths do not affect the native build. The compiler is itself executed inside a temporary PID namespace with a fixed Node PID1 driver and a 60-second build budget. Driver exit causes kernel cleanup of compiler descendants; the outer bootstrap has a separate 75-second transport guard. A failure of that outer guard is an unavailable/unconfirmed admission, not successful cleanup. Bootstrap timing is not a hard realtime caller-return promise.

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

Run `node tools/self-test-linux-namespace.js` on an actually supported Linux host. An unavailable capability returns `BLOCKED` and a nonzero exit code, not PASS. The physical suite covers pre-permit work denial, native IPC/birth identity, protected handles, detached/reparented children, actual double-fork plus nested PID namespaces, nested authority/worker capability profiles, compiler-environment injection, keeper crash, cleanup-budget exhaustion, current-owner observation, old-birth safety, live recovery, post-controller-crash recovery, and boot/namespace mismatch.

The old-birth test uses an explicitly synthetic historical birth against a real current process. It does not claim to force kernel PID-number recycling. A stopped-keeper fault uses a deliberately short test-only budget; it does not change production budget defaults. Kernel D-state is handled fail-closed but is not manufactured by dangerous host-I/O fault injection. Linux x64 physical evidence does not certify other architectures, Windows, macOS, or all distributions.

Regular successful finalization requires the regular full proof. Only a reserved native-recovery operation may use the separate historical-init inference union. Unknown spawn history without a trustworthy bound descriptor, another boot/observer namespace, changed helper pins, denied identity access, or incomplete cleanup stays unconfirmed.

## Primary references

- [Linux PID namespace contract](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html): namespace membership, descendant visibility, init termination and prevention of new processes after init death.
- [Linux `zap_pid_ns_processes`](https://github.com/torvalds/linux/blob/master/kernel/pid_namespace.c) and [exit ordering](https://github.com/torvalds/linux/blob/master/kernel/exit.c): namespace tasks are drained before init final-exit notification.
- [pidfd API](https://man7.org/linux/man-pages/man2/pidfd_open.2.html): exact process handles, final thread-group exit notification and hangup after reaping.
- [Parent-death signal contract](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html): parent-thread semantics, setup race and credential transitions.
- [User namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html): UID mapping and namespace capabilities, including the parent-UID-0 mapping condition.
- [Procfs documentation](https://docs.kernel.org/filesystems/proc.html): procfs visibility and namespace relationships.
