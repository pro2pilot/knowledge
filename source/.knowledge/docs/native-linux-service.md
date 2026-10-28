# Native Linux verification service

The Linux service runs the public verification pipeline through an administrator
installed native broker. The caller, its storage processes, the source importer,
the authority, and project commands have distinct roles. Project JavaScript is
never executed with host root privileges. Linux x64 and ARM64 use the same source
and protocol.

## Install a fixed candidate

Run preparation as the ordinary account that will invoke verification. The
installer binds that numeric UID, the selected Node executable, the trusted
runtime files, and the native sources into the broker. Node **22.17.1** is the
qualified runtime. Preparation requires Python 3, GCC, binutils, OpenSSL static
development libraries, `getent`, and the usual fixed Linux administration tools.
The host must provide systemd, a writable delegated cgroup v2 hierarchy,
`cgroup.kill`, pidfds including `SO_PEERPIDFD`, mount/PID/network/IPC namespaces,
and sealed nonexecutable memfds. The service creates its namespaces as native
root; it does not require enabling unprivileged user namespaces.

```sh
python3 .knowledge/tools/install-linux-native-service.py \
  --node "$(command -v node)" \
  --out "$HOME/native-service-install"
```

The output directory must be fresh. Review its `prepare.json`,
`stage/installation.json`, `SHA256SUMS`, and `install-native.sh`, then install:

```sh
sudo /bin/sh "$HOME/native-service-install/install-native.sh"
systemctl status knowledge-linux-native-v1.service
```

Python, the compiler, Node, and source processing run as the ordinary account.
The administrator script uses fixed OS utilities to create the protected
installation, copies the prepared bytes, verifies the native executable again,
initializes native history, and starts the service. Root executes the fixed
native executable. `Type=notify` reports readiness only after the broker has
validated the protected installation and opened its transport.

The default emits and enables a persistent systemd unit. Disposable
qualification can request `--service-lifetime-seconds 14400`; values from 1 to
14400 create a bounded transient unit. This option is not needed for normal
installation. Neither mode disables AppArmor or changes global namespace policy.

The protected root is `/var/lib/knowledge-linux-native-v1`; the public native
client is its `broker --client` mode. The default reserved UID/GID range is
1590000000 through 1590009999. Preparation checks system identities,
subordinate ranges, and prior permanent service claims. The administrator must
keep this range exclusively reserved. Each attempt consumes a new A/W pair;
completion never returns a pair to a free list. An exclusive creation of the
fixed installation root serializes concurrent first-install attempts.
The default range therefore permits 5000 allocations. For a longer-lived
installation, the administrator can reserve a larger exclusive range with
`--uid-first` and `--uid-last` during initial preparation. Exhaustion refuses
new work and preserves the history.

The installer refuses an existing installation and never resets a journal or
removes a prior identity reservation. A failed installation must be diagnosed
as that installation; repeatedly running preparation is not a history reset or
an upgrade procedure.

## Select the public backend

The verification request selects the fixed service explicitly:

```json
{
  "nativeExecution": {
    "linux": {
      "enabled": true,
      "mode": "isolated_copy",
      "broker_path": "/var/lib/knowledge-linux-native-v1/broker",
      "copy": {}
    }
  }
}
```

The caller verifies the native capability and its source/runtime pins before
creating storage authority. The candidate making the request must match the
installed trusted source manifest. Mutable project maintenance state is
excluded from this manifest by the importer's explicit top-level allowlist.
A source update requires a corresponding reviewed installation; it cannot
silently execute through an older protected authority.

The current bounded contract permits at most 64 verification commands. The
default and maximum imported source budget is 32 MiB in total and per file;
the encoded transfer is bounded separately. Private copied source and authority
state live on a 128 MiB tmpfs with 65536 inodes. The public authority result is
bounded to 128 KiB, inside the existing immutable finalization format. Large
command output and oversized result metadata are refused, rather than truncated
into a successful record. These limits are acceptance conditions, not promises
that arbitrary projects fit the isolated copy.

## Execution and acceptance order

1. The native client authenticates the root broker; the broker retains exact
   client and original controller pidfds. Every request also checks the actual
   sending process credentials. A source descriptor is sealed, nonexecutable,
   and read with explicit positions so another holder cannot change its offset.
2. Storage S is enrolled with its exact birth identity and private cgroup before
   it receives permission to touch attempt state. The native guardian retains
   S, controller, client, and broker identities independently of JavaScript.
3. `OPEN` reserves a fresh private UID pair and creates the gated native scope.
   The caller durably records the containment binding before `PERMIT` allows
   the importer, authority, or any project command to execute.
4. The unprivileged importer validates the exact source envelope and writes its
   isolated copy. Its complete PID namespace drains before a fresh authority
   reads the copy back. The authority sees read-only source and private state;
   workers use a different UID and cannot read that authority state.
5. The authority requests typed Node commands. A fresh nested worker PID
   namespace contains each command and descendants, including detached children
   that retain output pipes. A command reply requires exact native reaping and
   both output EOF observations.
6. The independent native keeper starts cleanup once and latches its original
   monotonic endpoint. It tightens all registered storage guardians to that
   endpoint. Cancellation, timeout, or native failure also stops S immediately;
   a normally completed authority leaves S time to persist finalization.
7. Private authority/worker closure requires retained pidfd exits, exact init
   and keeper reaping, result EOF, and the live private cgroup becoming empty.
   The root UID-history close is durable and checked again against the same
   endpoint. It proves the private scope only; storage closure is separate.
8. Public validators bind the raw native receipt, authority result, source and
   runtime identities, KVE/KVF records, and attempt generation. The storage
   actor that persists these records must exit and produce its exact native
   `writer_closed` receipt. A fresh enrolled storage actor performs the final
   compare-and-swap. Its own native closure and the native client's complete
   exit and output EOF must then be observed before the caller receives ACK.

The installed root checks file ancestry, ownership, permissions, absence of
POSIX ACLs, physical file identities, and hashes. The broker does not parse or
sign project JSON. Cancellation uses a native pipe with a separate public open
file description, so caller changes to its descriptor flags cannot make a root
broker write block.

## Failure, timeout, and retained history

Killing a process is a request, not proof that it has exited. A process blocked
in uninterruptible kernel I/O may remain alive after cancellation. Its original
deadline is never extended to manufacture a successful cleanup receipt. The
guardian continues to retain that exact process and cgroup until physical exit;
late exit is diagnostic and cannot produce an in-budget ACK.

A surviving broker can use its retained exact init pidfd and subreaper custody
when a keeper dies. When the broker itself loses custody, independent keepers
and storage guardians stop their actors. A subsequent broker startup finds
unresolved UID-history or writer records and remains quarantined. Missing
cgroups, elapsed time, a new PID with the same number, or a newer boot are not
accepted as proof of the old attempt's closure.

Do not delete `anchor`, `journal`, writer records, or permanent identity claims
to clear a quarantine. Preserve service logs and the installation/source pins
for diagnosis. This version intentionally has no automatic history-erasing
restart, same-boot quarantine bypass, or UID recycling operation.

## Qualification evidence

The shipping installer is the sole implementation. The audit fixture's
`prepare_service.py` only invokes it. Native transport/admission tests, actual
isolated execution, public KVE/KVF acceptance, and destructive last-only fault
tests are separate evidence lanes. A pass in a native component does not imply
that the public acceptance path or an unavailable host configuration passed.

The exact native wire definition is in `tools/lib/verification-linux-service.h`;
the service implementation defines native event bytes. Public consumers apply
strict validators and preserve the raw terminal receipt for its proof hash.
