# Darwin diagnostic lifecycle (RC5 pipeline.4)

Audit revision: `independent-audit.20261021.darwin-pipeline.4`.
This is an unpublished, uncertified development candidate. Production macOS
verification still refuses before work starts. `capability_qualified=false`
is unchanged. This diagnostic command does not create accepted KVE, KVF or ACK,
perform repair/currency, import outputs, release a production resource claim or
qualify a native backend.

## What the diagnostic runs

An ordinary monitor forks an ordinary controller. The controller records a
private durable reservation intent in the original project's selected
`.knowledge/maintenance/darwin-diagnostics/DGD-*/` before native `prepare`.
The nonce is reused only for lookup/stop after an ambiguous reply; recovery
does not allocate again, execute again or generate acceptance evidence.

The controller transfers a bounded physical project plan to the explicitly
installed broker, seals it, registers a direct authority child and grants
permit. Only that authority requests one canonical Node command through the
broker's gated C stub and private UID. The command's typed fd3 result includes
the attempt, descriptor, command digest, ordinal and allocation tuple. Helper
exit0 and command stdout are not command PASS. Output is consumed and hashed;
it is not copied into the diagnostic records.

The authority drains private commands while it remains alive. The controller
checks the actual original tree and the actual complete native workspace before
permit, after drain, and after terminal close. Native readback walks nofollow
directory FDs and hashes actual files, including entry counts/modes, rather
than trusting the sealed manifest in memory. Changed/missing/extra files,
nonphysical parents or unsupported entries fail closed. Terminal close stops
the exact authority; native facts require its exit, and the controller also
waits its direct child handle before exiting. The outer monitor waits the
controller handle and rechecks the
original tree. This is a series of observed checks, not an atomic filesystem
snapshot or a promise of future immutability.

Diagnostic schemas and records are separate from production evidence. A
`diagnostic_completed` observation is never an authorization to use KVE/KVF/ACK
or to certify cleanup. A report written before cancellation may remain as
historical observation; it is not a production acceptance receipt. Full native
drain and terminal proof bodies and their indexed digests are retained in the
private diagnostic record, alongside ordinary child exit observations.

## Explicit invocation

An administrator must first install and initialize the protected broker,
standalone protected Node runtime, reserved UID/GID interval and numeric owner
allowlist as described in [native broker setup](native-darwin-broker.md).
The command never installs a service, changes original project ownership or
imports command outputs. Use a disposable project for audit scenarios.

Write a private request file, replacing all example paths:

```json
{
  "report_only": true,
  "repoRoot": "/Users/example/fixture",
  "stateRoot": "/Users/example/fixture/.knowledge",
  "test": {"argv": ["node", "--test", "sample.test.js"], "cwd": ".", "timeout_ms": 30000},
  "sourceFiles": ["sample.test.js"],
  "nativeExecution": {"darwin": {
    "enabled": true, "mode": "isolated_copy",
    "broker_path": "/Library/KnowledgeVerification/bin/broker",
    "broker_socket": "/Library/KnowledgeVerification/control/broker.sock",
    "copy": {}
  }},
  "verificationPolicy": {"work_budget_ms": 300000, "cleanup_budget_ms": 60000, "no_progress_ms": 0}
}
```

```sh
node .knowledge/tools/diagnose-darwin-verification.js /absolute/private-request.json
```

Run as the explicitly allowed ordinary user, not root. The original selected
stateRoot must be exactly `<repoRoot>/.knowledge`; the first diagnostic slice
does not introduce another state root. Accepted logical commands are exactly
`node relative.js` or `node --test relative.test.js` (also `.cjs`/`.mjs`), with
one entry, a physical relative cwd and no extra flags/arguments/env overrides.
Generators, arbitrary commands, automatic output import and production
finalization are outside this slice. Request admission rejects accessors,
proxies, unknown fields and implicit opt-in.

## Timing and stop observations

| Limit | Purpose | Diagnostic behavior |
| --- | --- | --- |
| Work budget | Probe, planning, transfer, registration, permit and command result | Expiry fences work and starts terminal stop; no later result becomes successful work. |
| Per-command budget | Actual native command, bounded by remaining work | Independently observed by the native exact-stop observer. |
| No-progress budget | Requires a trusted semantic progress source | Must explicitly be `0` in this slice; nonzero values are rejected. Silence/stdout/heartbeats are not treated as meaningful progress. |
| Cleanup budget | Drain, readbacks, ordinary exits and terminal proof | Separate monotonic epoch after command completion; it does not extend work. Late or unconfirmed cleanup fails. |
| Helper lifecycle / emergency | Bound protocol waiting and failed helper exit observation | An emergency returns `exit_observed:false`; it cannot confirm resource release. |

The example's 300 s / 30 s / 60 s values are conservative diagnostic inputs,
not newly qualified production defaults. Preserve measured work, cleanup and
return durations per host/load in the audit evidence before selecting production
profiles. Existing Windows/Linux profiles and exact legacy authority pin lists
are unchanged. There is no strict millisecond API-return criterion.

SIGINT/SIGTERM to the monitor requests cancellation; controller loss, work or
command expiry independently latches native stop. Native fast `observe`/`stop`
returns cached/unconfirmed state without waiting for the durable writer. It
does not issue a proof or claim resources are free. Helper creation and its own
protected-image checks can still wait on the host; no end-to-end hard stop SLA
is claimed.

## Independent native stop and remaining limitations

The reactor handles bounded transport and cached diagnostics. One lifecycle
actor owns all mutable registry/history/receipt state and durable I/O. A
separate observer uses immutable C snapshots and a monotonic stop latch; it
does not read history, write proof or signal by cached private UID. Birth is
published before post-spawn persistence. The observer follows the same process
lifetime across exec, using a fresh kernel signal token when signaling.

While the actor is blocked, only already known exact stub/command/authority
births can be stopped. Unknown detached descendants require a fresh actor-owned
allocation/history/exclusion sweep; until then cleanup is unconfirmed. The
daemon does not start a second writer after a timeout. Startup diagnostics
become available only after singleton lease acquisition; before registry replay,
historical exact births are unknown. Pre-lease prerequisites can still block.

The audit-only build can enable a root-authenticated, launchd-activated
persistence gate at selected read/fsync/F_FULLFSYNC boundaries. Probe reports
`qa_persistence_gate` and `qa_build_id`, and receipts bind the distinct binary
hash. This is injected waiting before a syscall, not evidence of actual kernel
D-state or APFS failure. Shipping builds have no enabled gate. Neither build
can change `capability_qualified=false`.

Production common-control/KVE-v3/KVF/ACK-v4 integration, durable finalization and
replay remain open. Planned terminal teardown and abort need distinct acceptance
fences before production integration. OPEN-L2 Windows/macOS common-lock recovery,
OPEN-L3 atomic initial owner publication, reboot/unknown-scope recovery, fresh
installed platform qualification and SIP-enabled macOS checks remain open.
The historical second ownerless-lock cause remains unknown. Hosted GitHub
diagnostics do not substitute for those gates or authorize publication.
