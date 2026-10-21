# RC5 Windows authority watchdog

Historical evidence. The millisecond caller-return criterion below was
superseded by the [work/progress/cleanup contract](verification-execution-contract.md)
in `independent-audit.20261020.windows.4`. Measurements retain their original scope.

Revision: `independent-audit.20261019.windows.2`. Version **3.4.4 RC5**;
unpublished. The exact ZIP SHA and fresh results belong to the accompanying
handoff. The final release gate and publication remain deferred.

## Deadline and process ownership

The native batch starts one monotonic clock before request admission. Inert
admission checks the budget incrementally; property names and worst-case JSON
escaping count toward the transport bound. Getters, proxies and serialization
hooks remain rejected without execution.

The synchronous facade sends a small timing header and opaque request to a
watchdog. The watchdog assigns an idle authority process to a Windows Job
before starting it. That process performs preparation, key generation and the
native pipeline. Its command supervisor separately contains the command worker
and descendants. Blocking receipt readback or signing cannot stop the external
watchdog. Neither process grants a new timeout to a later stage.

The private signing key exists only in the authority process. The command
worker and watchdog never receive it. The signed candidate travels through a
private pipe; the watchdog releases it only after its authority Job reports
zero active processes and its keeper exits successfully. The facade checks the
original deadline again before returning. Command and authority teardown are
separate facts in the returned budget.

The transport no longer adds 7000 ms. Physical Windows tests interrupt
preparation, receipt readback, signing and receipt I/O, and measure the public
API return against `timeout_ms + 100 ms`. The 100 ms is an explicit measured
test tolerance, not extra time in which an ACK may be accepted. Late results
remain rejected. A stopped OS scheduler or an arbitrarily blocked caller
JavaScript intrinsic, including a single `Reflect.ownKeys` operation, is outside
a hard real-time guarantee. Structural limits and checkpoints bound subsequent
admission work; the original unrestricted wall-return requirement must not be
called an absolute guarantee on that basis.

An outer timeout can return before cleanup is independently confirmed. It then
reports `unconfirmed` and no acceptance. Kernel Job ownership, control-channel
EOF and helper lifetime continue cleanup; an external PID check is evidence of
observed exit, not a fabricated completed teardown receipt. Partial KVE/KVF may
remain diagnostic evidence without returned IDs or usable authority.

## Compatibility and audit scope

New native receipts pin ten implementation files, including the watchdog and
inert admission. Readers retain the exact historical eight-file layout; mixed,
missing, duplicated or reordered layouts are rejected. Historical signed
evidence stays distinct from current factual currency: the latter additionally
pins the watchdog and can require reverification after upgrade.

The supplied Team fix for `KNOWLEDGE_DISABLE_GIT_DISCOVERY=1` is retained, along
with repository/workspace composite selection and explicit repo IDs. Native
finish/currency crash/resume has its own physical supplemental scenario; it
does not establish every possible crash point. Lock diagnostics do not identify
the unknown creator of the historical second ownerless lock. Upgrading does not
authorize deleting that lock or rewriting historical evidence.

Linux/macOS native verification still refuses before worker or probe creation.
New POSIX runs, live providers and the full release gate are not certified by
this Windows audit. Read the handoff for exact source/runtime pins, raw failures,
replays, controlled fault adapters and remaining independent-audit questions.
