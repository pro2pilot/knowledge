# Linux native service: durable UID custody and integration boundary

Status: **native persistence component implemented; production broker admission remains unavailable**.

`tools/lib/verification-linux-uid-history.c` and its header implement the root-only
UID burn journal needed by a separate Linux native broker. The component does
not execute a command, establish a mount/PID namespace, validate a KVE result,
or turn an external assertion into native cleanup proof. The public command
runner must not infer service availability from these files or their QA results.

## Implemented persistence contract

The administrator supplies an installation ID, host ID, fixed reserved UID/GID
interval, and two distinct existing root-owned `0700` directories. Every path
component must be physical, root-owned, non-writable by other users, and free of
POSIX access/default ACLs. Runtime callers cannot choose these values.

The anchor directory contains an immutable genesis marker and latest head. The
separate journal directory contains a singleton lock and append log. All files
are root:root `0600`, regular, single-link, and opened without following symlinks.
The genesis binds the installation, host, range, format, policy, and actual
journal/lock device and inode. Replacing either file with byte-identical content
while retaining the old marker is rejected on restart.

Records are fixed 256-byte SHA-256-chained frames. A reservation burns the next
two UIDs, appends and fsyncs the log, publishes and fsyncs the new head, then
replays the complete protected chain before returning success. A process crash
between log and head publication leaves an inconsistent installation which
refuses admission. No tail truncation, silent reset, age-based repair, nonce
reuse, or UID reuse is implemented. A valid pending reservation may be opened
for inspection or exact native recovery, but cannot admit another reservation.

Initialization is an explicit administrator operation. It requires both
directories to be empty. Exclusive files fence a partial initialization; a
restart never repeats initialization automatically. A held `flock` prevents a
second lifecycle owner from opening the same history.

SHA-256 uses OpenSSL EVP with configuration loading disabled before the first
digest operation. The source requires the system OpenSSL development package
and `-lcrypto`. This is a native build dependency, not a project-supplied module.

## Closure is an internal native operation

`kv_linux_uid_record_closed` is deliberately not a public transport operation.
Its reservation and digest must come from the native lifecycle actor after that
actor has independently established all required process, output, and containment
facts. The caller must enforce its original cleanup endpoint before persistence,
after persistence/readback, and before publishing a terminal result. A late
durable record is diagnostic history; it is not an in-budget completion claim.

The QA composition in
`qa/reliability/linux-admin-service-27/service.c` enables the journal only under
`QA_DURABLE_HISTORY`. It calls the close operation only after the retained
keeper pidfd and wait result, exact init wait receipt, output EOF, and live
`cgroup.events` agree under the original cleanup deadline. The digest binds the
installation, host, boot, attempt nonce, allocation pair, exact native actor
observations, wait statuses, output count, and that deadline. No caller packet
can supply a proof digest or request a CLOSED journal transition.

This composition uses fixed native QA actors. It is not the public product
service. Its explicit initialization, real closed-attempt restart, next UID
pair, and pending-attempt restart fence are independently checkable without
changing the production availability flag.

## Exact production integration still required

The existing service-copy QA already demonstrates an isolated low-UID importer,
a sealed input memfd, full importer-namespace drain, a readonly source mount,
and separate authority/worker UIDs. Its input and command are fixed fixtures.
Connecting it to the public service requires the following concrete boundaries.

| Boundary | Required production behavior |
| --- | --- |
| Administrative installation | Root-protected native daemon, fixed native client, pinned runtime/entrypoints, reserved account range, explicit journal initialization, and a system-manager unit. No root interpreter or root project command. |
| Public transport | Fixed versioned `SOCK_SEQPACKET` frames for HELLO, OPEN, STOP and OBSERVE; exact per-connection ordinal and nonce; initial `SO_PEERCRED`/`SO_PEERPIDFD` retained; per-message `SCM_CREDENTIALS` matched to that original live controller. Unknown ancillary data, unexpected descriptors and truncated frames are rejected. |
| Source transfer | OPEN may carry exactly one bounded regular memfd with WRITE/GROW/SHRINK/SEAL seals already present. Root checks descriptor metadata and seals only. The isolated importer parses opaque bytes. It must use explicit-position reads: seals do not stop the sender from changing a shared open-file-description offset. |
| Source custody | Native code creates fresh protected paths. The importer runs without root IDs/capabilities and never opens caller-selected source paths. All importer descendants and writable aliases must be gone before the native readonly mount and fresh authority process are admitted. |
| Runtime custody | A and W execute only after native UID/GID/capability/descriptor checks. A loads its installed trusted entrypoint; project code runs under W. Nested W launches use a bounded typed native request, never an arbitrary root command or shell string. |
| Public command/KVE result | The caller controller verifies the installed capability, attempt binding, immutable source manifest, typed authority result, original work/cleanup epoch, ACK sequence and final CAS. The root daemon does not parse or sign arbitrary project JSON as trusted result. |
| Restart/recovery | Durable pending state fences admission. Positive recovery requires exact native custody that survived or independently proves closure. A journal hash, stale PID, missing cgroup, elapsed lease age or an external QA observation cannot close a pending attempt. |

There is no public CLOSE, caller-selected UID, caller-selected privileged path,
`force` admission flag, or caller-supplied cleanup digest in this design.
Journal and native process-custody integration must precede activation of the
public service backend. Passing the journal or fixed-copy component tests alone
does not satisfy that requirement.

## Evidence scope and reproducible checks

The root filesystem driver
`qa/reliability/linux-service-history-27/run-history-qa.py` builds the exact source
with strict C warnings and checks real files, separate processes, lock ownership,
restarts, inode substitution, corrupt records, UID/nonce exhaustion, and injected
publication faults. Its independent Python SHA-256 replay checks the binary
record chain and inode bindings. `CRASH` in this driver means an injected
userspace `_exit(88)`, not power loss, a kernel I/O stall, or a storage-device
durability qualification. It records the host architecture, compiler command,
compiler version, UID and exact source/binary hashes.

The separate native lifecycle composition is invoked on an ordinary Linux
runner with `prepare --history`, followed by the fixed root controller
`run --history`. It preserves the older non-history QA path and accepts native
x86-64 and ARM64 only. The root controller installs one unique temporary system
service, reserves only its fixed QA interval, records exact history evidence,
and removes only the installation and reservation it created after confirming
cleanup. Production history has no deletion/reset operation.

The component detects inconsistent or substituted independently anchored state.
It does not attest a coherent rollback of every root-controlled checkpoint, or
compromise of the administrator/kernel. Such attestation would require an
additional monotonic trust anchor outside this filesystem design.
