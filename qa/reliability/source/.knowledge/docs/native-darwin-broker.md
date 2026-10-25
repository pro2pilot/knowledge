# Darwin broker development status

This reliability worktree starts from
`independent-audit.20261025.darwin-prototype.3.audit.2`. Its exact delivery
manifest identifies the resulting derivative. The pipeline4 actor/reference
source at repository commit `4303ef4dea1520cb556a30036612842287ed2386` was read as
an explicit implementation reference; it was not silently substituted for that
base. Historical green diagnostic jobs do not test the changes described here.

Stop guards reject new reservation/admission at observed shutdown boundaries,
including after UID history and preparation I/O. Consumed UIDs remain consumed.
An already spawned child retains its exact tracking and unresolved spawn intent;
shutdown does not manufacture a no-child cleanup result. A partial reservation
that cannot prove resource exclusion remains unconfirmed. A single lifecycle
actor owns mutable registry/history state. Its disk I/O is separate from the
nonblocking transport reactor, immutable stop observer and independent root
guardian process. A blocked durable writer never becomes a successful commit.

This source includes an experimental native broker, a bounded project-copy
planner, capability client and asynchronous production-session facade. The
facade requires a qualified shipping descriptor; it cannot turn diagnostic
success into accepted verification/finalization. Ordinary macOS native
verification remains closed until that contract is qualified. The broker's source constant
`kCapabilityQualified` is false; diagnostic observations cannot issue a production
cleanup confirmation or a Knowledge ACK.

The selected design requires an administrator-installed native service and an
explicit isolated project copy. It does not change the original project's owner,
mode or ACL, and does not copy outputs back automatically. A trusted ordinary-user
controller reads source bytes; the root service receives bounded relative names
and bytes. Only command descendants run with a reserved private UID/GID. The
ordinary authority must separately exit before cleanup facts can be confirmed.

The private UID has no login account. Credential checks read actual kernel
supplementary groups; Darwin's account-default group lookup is a different API
and cannot certify `setgroups`. Commands that require passwd/account metadata
may need explicit support; there is no fallback to the original user's UID.
An administrator must supply a complete protected runtime. Copying only a
Homebrew Node launcher omits its separate `libnode` dependency; the physical
smoke uses a complete Node distribution with only OS library dependencies.

The diagnostic child also requires its protected root broker to be an actual
creation child of PID 1, with a fresh root `/sbin/launchd` identity. An orphan
whose current parent is PID 1 fails this check. This kernel lineage check does
not attest a LaunchDaemon configuration: a protected administrator-installed
SYSTEM job remains a prerequisite. The inherited OS task-access policy endpoint
belongs to the trusted OS; no caller port imports or general Mach service access
are supported. This is not a claim about every possible direct OS-service RPC.
The command is launched by a separate small C-only image. That image remains a
root guardian and forks a command child; only the command child enters the
private credentials and sandbox. The child clears bootstrap,
registered and exception slots and removes foreign SEND-only namespace rights.
Its reviewed single-thread/no-port-import path preserves its own empty runtime
RECEIVE rights, including guarded ports; it never destroys or unguards those
rights. Unknown right types, queued messages or failed observations refuse the
launch. It drops all user/group credentials and checks a freshly acquired usable
ordinary host port plus the exact privileged-query denial before exec. It does
not change SIP or call a host-port setter. This C-only argument must not be
applied to an arbitrary Foundation/XPC process.

The broker and C stub are a protected pair. The broker embeds the C source hash;
the C binary embeds the actual compiled broker hash and both source hashes.
The immutable v2 descriptor records both binary/source pins, KVS2 wire version,
KVR2 guardian protocol and a fresh 64-hex daemon epoch.
Startup checks a bounded `--describe` reply; this is consistency checking, not
build attestation. Trusted installation and quiescent updates are still required.
Recovery refuses to rebind old descriptors silently to a different pair.
Structurally valid v1/KVS1 and prior-epoch v2 records remain cleanup-only after
their durable allocation tuple is revalidated. They never admit new commands
or satisfy current execution predicates.

The fixed-endian KVS2 configuration has a 1 MiB aggregate bound, independent
field/count limits, strict UTF-8, no embedded NUL, unique safe environment keys,
and exact frame/EOF checks. It binds the attempt, epoch, never-reused allocation,
runtime digest, cleanup budget, actual admission/workspace descriptor inodes,
and exact ordinary controller/authority births. The same admission open-file
description stays locked until private credentials are kernel-visible.

Two-phase birth registration protects the root phase of command setup. The
forked child first closes every inherited setup-channel writer and waits for
`S`. The guardian publishes an 88-byte KVB2 birth record. Only after the broker
has published/persisted the exact root child and its observer acknowledges that
birth can the broker send `B`; the guardian relays `S`. A guardian death before
that point yields EOF before the child can begin filesystem, Mach, sandbox or
credential setup. Private readiness then produces the separate KVR2 record.
The broker persists the same child's private identity, refreshes its allocation,
waits for the observer acknowledgment and sends the final `G` exec permit.
Both `B` and `G` writes share the same short mutex as the stop latch, use a
nonblocking descriptor and recheck the original deadline/clock-failure flag.
An unresolved birth, partial/duplicate record or spawn intent remains unconfirmed.

The guardian checks daemon, controller and authority births independently. It
continues after daemon death and can stop work when an authority dies while the
daemon is wholly paused. It owns/reaps the direct child and repeatedly enumerates
the fresh private RUID population, including detached grandchildren, signaling
only current pidversion-bound identities. Normal command exit is not complete
until actual direct-child reap and a subsequent full zero-membership scan.
Clock errors, unknown identities, enumeration failure and cleanup expiry retain
the enforcer; they never mean process death. The observer provides an independent
UID/exact-root-child stop path if the guardian dies while the actor is blocked.
No collection of user-space observers can claim immediate cleanup when all
enforcers are killed or prevented from running; startup recovery must establish
fresh closure before reclaiming the attempt.

Native finalization is being split into two phases. `drain_commands` closes
command admission, stops the private-UID tree and persists a separately typed
command-drain receipt while the exact registered authority remains alive. The
resource stays active and the admission open-file description stays locked
through readback/finalization. Terminal close stops the authority and persists
the terminal proof before releasing that barrier. A drain receipt is never a
terminal cleanup receipt or ACK. Explicit stop can interrupt a pending drain;
an occupied response waiter must not postpone that stop.

Both phases share one persisted cleanup start/deadline. Later calls and restart
may shorten it and cannot reset it. Owner loss, storage failure or expiry
escalates to terminal cleanup. Later physical recovery may establish resource
closure; it cannot make the stopped verification pass. The terminal proof keeps
`cleanup_budget_exceeded` separate from physical cleanup facts. Consuming that
distinction is mandatory in the common finalization contract.

Terminal publication rechecks the cleanup clock after receipt/index writes and
fresh status readback. A late observation creates a new content-addressed receipt
with the expired flag; it never rewrites the old receipt. Failure to make that
revision durable, or loss of current registry/allocation health, retains the
active claim and admission barrier with `cleanup_unconfirmed`. These native
changes still require macOS qualification. A raw receipt is a point-in-time
observation: the common facade must independently guard its final deadline,
stop fence and durable commit before returning any ACK.

An owner/nonce pair cannot allocate a second reservation after its first attempt
closes. Lookup searches the complete recorded history; ambiguous matching entries
refuse. Restart and late retries must use the original recorded reservation.

The copy planner strips original ownership and metadata, rejects links and special
files, preserves empty directories, applies configured entry/byte limits and checks
source identities and hashes again before transfer. Known credential/agent state
and `.knowledge` runtime state are excluded. These exclusions are heuristics, not
a guarantee that arbitrary source files contain no secrets. Required excluded
inputs fail closed. Canonical portable NFC filenames are required; decomposed
names, aliases and collisions are not silently renamed. The entry limit counts
files and directories. The design does not promise a hermetic read-only system
environment or preservation of original absolute paths/inodes.

The local copy plan now binds the physical source root, its ancestors and each
directory with exact device/inode identities. Transfer verifies the complete
plan before the first RPC and again before sealing, including added/removed files
and modes. A replaced parent directory cannot borrow an unchanged leaf's identity.
The snapshot root must be physical; a root symlink is refused. Nonblocking source
opens prevent a regular-file-to-FIFO substitution from hanging the controller.
Root/parent bindings are local read guards, not part of the portable wire manifest.
Remote workspace readback and the common finalization pipeline remain separate
requirements; this does not make a mutable filesystem an atomic snapshot.

The standalone JS client validates explicit inert configuration and probes a
protected installed broker. The public repair/agent-task request boundary now
preserves `native_execution` in its normalized request and replay hash; the camel
alias is accepted only when the snake alias is absent. Conflicting aliases,
accessors, proxies and malformed settings refuse before execution. Explicitly
requesting enabled Darwin execution currently returns
`verification_containment_unavailable` before a claim or work is created. It
cannot silently use the host Windows/Linux backend or old accepted evidence.
The broker client does not install a service or request sudo. This remains a
development interface without production Darwin admission until qualification.

`verification-darwin-session.js` provides asynchronous probe/open/attach,
copy/authority/permit/run, source snapshot/readback, drain, close and stop methods.
Its private binding/token crosses only trusted private IPC. Commands are limited
to the exact protected runtime whose bytes match the controller's Node runtime;
there is no arbitrary argv[0] fallback. Source planning and after-drain readback
retain the sealed-copy contract; generated-output import is unsupported.

Cancellation closes local admission immediately and starts native fast stop
without awaiting durable common storage. Setup hashing has a separate logical
cancel/deadline fence before native reservation; a blocked read may still exist,
but its late result cannot create work. Open handles remain finally-owned until
the syscall returns. The monitor's bootstrap-process scope must account for any
physically unfinished I/O worker. Native output uses separate data stdout/stderr
and typed fd3 control. A helper exit, a final monotonic deadline check and current
typed predicates are all required before acceptance. Exit 0 with native stop,
timeout or closed-admission flags is rejected. Proof times must fall inside the
recorded cleanup epoch, and prior daemon epochs remain history only.

Native diagnostic requests use the same numeric limits as the common timing
policy: positive integer work/command budgets up to 60,000,000,000 ms and cleanup
budgets up to 3,600,000 ms. Invalid values are rejected; valid large values are
not silently shortened. The work clock starts before UID reservation and covers
preparation, copying and commands. Cleanup has its own clock and cannot extend
an active cleanup by repeated close requests. These are configuration limits,
not recommended defaults or a promise of millisecond API return. The common
profile, progress, cancellation and finalization integration is still pending.

Diagnostic startup pair inspection allows 30 seconds for work and a separate
30 seconds for stopping/reaping its own native child. Unknown wait ownership
never authorizes a signal by PID alone; unconfirmed cleanup is reported and
serving does not start. C setup has a 60-second bootstrap ceiling and also obeys
the command deadline once decoded. These generous prototype ceilings cover
setup that has been much shorter in CI; they still require slow/load/fault
qualification before becoming production profiles. Parser-only tests use a
separate five-second input limit. None is a millisecond API-return guarantee.

## Incremental transport and ordinary helper lifetime

The broker and ordinary client use the same pinned C transport header. Reads
assemble partial frames; writes retain partial progress and handle `EAGAIN`
through polling. Each turn has byte/syscall bounds; at most one complete request
is dispatched per broker turn. A slow or disconnected peer cannot occupy a
blocking receive/send loop. Buffered frames are limited to 12 MiB, queued output
to 16 MiB, and concurrent transports to 16. The helper rechecks its exact parent,
monotonic lifetime and final output completion before returning success.

The default transport stall budget is 30,000 ms and the default ordinary helper
lifetime is 120,000 ms. The JS capability probe passes those values explicitly
and no longer imposes the old 20,000 ms outer ceiling. Native diagnostic clients
accept `--transport-timeout-ms` and `--lifecycle-timeout-ms`; the `--serve` values
govern the service, while `--request`/`--run` values govern that separate client.
Increasing only a client limit cannot extend an admitted command deadline.
For an accepted run the service derives its transport lifetime from that original
command deadline plus its existing cleanup/transport allowance, rather than
aborting a valid long silent command at the generic 120-second RPC default.
A command helper derives its default total lifetime from the original start,
work budget, cleanup and transport allowance. Output bytes and heartbeat messages
do not restart its lifetime or the verification work clock.

These changes separate socket/pipe responsiveness and stop enforcement from the
single storage actor. History scans, file hashing and durable sync can still
stall that actor, preventing positive persistence/cleanup proof. The observer
and guardian do not await those operations to stop admitted work. Compile-time
QA holds demonstrate scheduling boundaries, not a genuinely stalled kernel
filesystem operation. Production admission remains disabled pending current
common control/KVE/ACK integration and exact native load/fault acceptance.

Native UID history is wired as an unqualified development component. Its
independent marker/head and consumed-UID hashchain must agree with the actual
registry checkpoint before a candidate can be inspected or used. This replaces
the registry-only counter. Every inspected candidate is consumed, including
busy kernel-membership candidates; restart never resets the counter. Missing/torn/mismatched
history quarantines allocation and never automatically reconciles or adopts a
UID. Checked F_FULLFSYNC, directory sync and readback are required; unsupported
storage fails closed. This is not rollback-proof storage or OS attestation:
coherent rollback/loss of all root records remains outside that guarantee.

Explicit root maintenance must initialize existing empty, protected directories
before the service starts. There is no serve-time ENOENT initialization and no
legacy fresh-mode exception. Production paths are fixed sibling directories:

| Directory under `/Library/PrivilegedHelperTools` | Required mode |
| --- | --- |
| `KnowledgeVerification-anchors` (install.json, uid-head.json, account-policy.json) | root0755 |
| `KnowledgeVerification-allocator` (consumed.journal and daemon.lock) | root0700 |
| `KnowledgeVerification-state` (registry.json and admission/receipts) | root0700 |
| `KnowledgeVerification-workspaces` | root0711 |
| `KnowledgeVerification-control` (broker.sock) | root0755 |

All ancestors and files must satisfy native root ownership/ACL/nofollow checks.
No command creates these directories or chmods their ancestors. An administrator
must reserve UID/GID interval `[1000000000,1900000000)` across all account
providers and keep it unavailable to accounts and other services for the entire
installation lifetime. This is an explicit administrator prerequisite, not an
OS-enforced reservation or a guarantee from a negative lookup. Runtime admission
does not query account directories. Initialization creates no
accounts and changes no project permissions or global account policy.

The canonical root-only administrator initialization invocation is:

```text
broker --init-install --runtime=/protected/runtime/node --confirm-reserved-uid-range=1000000000:1900000000 --account-policy=admin_reserved_interval_no_runtime_nss.v1 --allow-owner=501
```

`--allow-owner` repeats for each explicitly approved numeric ordinary UID (1 to
999999999, canonical decimal, no duplicates; maximum 64). No default/current-user
admission exists. This initializer validates the protected broker/C-stub pair and
resolves those existing owners and their ACL UUIDs through directory services
before registering history. Lookup/UUID errors refuse init. These administrative
calls can block; init runs only during quiescent maintenance, outside the serving
daemon loop, with no active attempt. It then creates an initializing marker and
genesis journal/head, writes account-policy.json with O_EXCL, persists the exact
external registry checkpoint and only
then finalizes the ready marker. The service must be quiescent. Existing or partial
history is never overwritten; interrupted init requires explicit administrator
recovery rather than retry/reset. No root JavaScript or automatic sudo/install
path exists. Normal service startup uses the existing singleton lock without
O_CREAT and requires actual system creation lineage outside diagnostic mode.

Own CI fixtures require **both** root `--qualification-mode` and explicit
`--registry=/physical/root-fixture/state`, `--allocator=/physical/root-fixture/allocator`,
`--anchors=/physical/root-fixture/anchors`, `--workspaces=/physical/root-fixture/workspaces`
and `--socket=/physical/root-fixture/control/broker.sock` on init and serve.
Init still requires the range confirmation, literal account policy and approved
owner flags. Serve rejects those init-only flags. Qualification mode requires all
five paths to be explicitly supplied and outside every production sibling; it
rejects canonical paths, including inherited defaults. Canonical production
paths are accepted only without qualification mode and retain normal production
root/creation-lineage requirements. Mixed, nested or ancestor
references to production state are rejected before native preflight. Custom
server state/socket paths without diagnostic mode are rejected. Ordinary `--request`, `--run` and
`--print-profile` clients retain their custom protected socket interface and do
not open or initialize global history.

Build the broker with the additional native translation unit
`verification-darwin-uid-history.m`, and define the exact lower-case hex SHA256
macros `KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA` and
`KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA` for its `.h` and `.m`, alongside existing
broker/stub source pins. The included `verification-darwin-transport.h` must also
be pinned by `KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA`; an unpinned build refuses.
Descriptors, startup checks and probe replies carry `transport_header_sha256`.
The client compares it with the actual bundled header. Compile the broker first, then compile the C stub against
that actual broker binary hash. No self-reported source string is build
attestation. Old descriptors lacking these pins/allocation fields are not migrated.

The immutable root0600, single-link, nofollow `account-policy.json` uses canonical
sorted JSON without escaped slashes, with exactly this schema:

```json
{"schema":"knowledge-darwin-account-policy.v1","id":"admin_reserved_interval_no_runtime_nss.v1","installation_id":"<64 lower-case hex>","uid_first":1000000000,"uid_last_exclusive":1900000000,"range_admin_asserted":true,"owners":{"501":"<canonical lower-case nonzero UUID>"}}
```

The registry binds its ID and SHA256 under `account_policy`; descriptors and
drain/terminal receipts bind `account_policy_id` and `account_policy_sha256`.
Policy creation checks file sync, F_FULLFSYNC, parent directory sync and exact
protected readback. Missing, malformed, changed or unbound policy becomes sticky
unhealthy until service restart and valid administrative recovery; runtime never
creates/repairs it. Existing/partial installs are never reset or automatically
migrated. Adding users/changing providers requires a separately reviewed
quiescent maintenance procedure; init is not an update command.

Serving uses validated cached UUID bytes for `acl_set_qualifier`, never
`getpwuid`, `getgrgid` or `mbr_uid_to_uuid`. Unknown owners cannot prepare work.
This removes explicit broker directory calls; it does not promise that filesystem
authorization or durable I/O returns within hard milliseconds. Administrative
UID/UUID bindings must remain valid; account/provider changes must preserve the
reserved interval and require maintenance revalidation before support resumes.
The broker does not enforce remote directory administration or detect every
violation of this prerequisite.

Probe/status includes `account_policy` with fields `id`, `healthy`, uppercase
`reason`, trusted known `sha256` (or null), `configured_owner_count` (0..64), and
`runtime_directory_lookups:false`. After a fault, hash/count can describe the last
validated policy; `healthy:false` means those cached values authorize no new work.

Descriptors now include installation_id, allocation_seq/allocation_sha256 and
both UID-history source pins. Mutating copy/seal/permit/run transitions require
healthy account policy, healthy history and the exact current tuple. Probe/status distinguishes cached
health from an attempted disk refresh. Entry-store failure and allocator failure
are separate: independently valid owner-scoped entries retain status/lookup and
close/recover access. Unhealthy history or account policy never grants a new UID
ticket or a positive whole-boundary proof. An already armed observer/guardian
ticket may continue negative-only stopping of its durably reserved, never-reused
UID even while the actor cannot reread history; this is necessary for independent
stop enforcement. Without such a ticket only recorded exact-birth stopping and
read-only RUID observation remain available. The active claim stays reserved
when cleanup is unconfirmed. A fresh tuple is required again before exec permit
and every positive drain/terminal receipt. Physical negative qualification of
these paths remains pending.

An active reservation also schedules a full entry-store, account-policy and
UID-history observation after five seconds without depending on another RPC.
This timer is separate from work/progress and does not extend either work or
cleanup. Known owner loss, cancellation, unhealthy state and budget expiry take
priority over that scan. The next scan is scheduled from completion; missed
intervals do not cause catch-up bursts. A storage fault starts terminal cleanup
with exact recorded identities only and cannot confirm the whole UID boundary.
The five-second interval is a storage-health detection cadence, not a stop SLA:
history can be 64 MiB, registry can be 12 MiB and durable I/O can stall the
lifecycle actor. Maximum-size, slow-disk and loaded qualification is still
required. Fresh transition/cleanup guards are never replaced by this observation.

The entry store also has a fresh byte guard: normal persistence requires the
actual protected registry to match the last successfully durable bytes, both
before writing and before rename. Live deletion, replacement, mode/ACL damage
or different bytes poison persistence and are preserved. Only the explicit
initialization call can create an absent registry. Cached exact identities
remain available for targeted stop; a previously armed UID ticket retains only
negative stop authority. Neither authorizes rebuilding a lost entry store or a
positive cleanup proof. Root maintenance
must remain quiescent: these checks are not an atomic filesystem CAS against
concurrent root changes.

Before production support: qualify host-wide UID allocation/history protection,
native crash/timeout/recovery qualification, all required copy/cwd readback checks,
common watchdog/control/recovery integration and a new versioned authority-pin
and finalization contract. Do not add these files to the legacy v3 authority list
and treat old signatures as proof of the new backend. Then test the exact installed
artifact on supported macOS architectures and rerun Windows/Linux regressions.

Full release acceptance and publication remain blocked by those requirements.
