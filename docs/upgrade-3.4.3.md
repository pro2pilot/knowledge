# 3.4.3 upgrade and verification notes

Knowledge 3.4.3 includes the trust recovery and runtime fixes developed and
audited since 3.4.0. Upgrade existing installations through the system updater
so local configuration and evidence retain their normal protection. A version
number or focused runtime test does not certify a release by itself.

## Recover covered historical rechecks

Use the normal `agent-task begin` / `agent-task finish` workflow. Direct
`repair-on-touch receipt` / `apply` remains available for explicit diagnostics.
The primary selected finding must be `verify_on_touch` in scoped or Extended
mode. Related tracked-file records must belong to that module, have compatible
predicates and completed required checks, and contain actual source paths in
the primary KVR snapshot. `.knowledge/freshness.json` is only the tracking
witness. Verifying that witness without the source cannot close a recheck.

Open covered records and closed records with invalid provenance can be resolved
together. Valid prior closures are preserved. Closure evidence binds the exact
lifecycle occurrence, primary finding, source hashes, KVE/KVR and committed
transaction. Every related closure is checked before shared KVR budget usage is
deduplicated. Critical, security, dedicated/manual-review and excluded records
keep their existing workflows. Deleted/replaced paths are not auto-certified.

For `uncovered_important_files`, update the module card and file facts using
current source and relevant tests, and include both the source and
`.knowledge/evidence/file_facts.json` in the KVR source snapshot. Each covered
fact needs `file` and `evidence.source_sha256` matching that source. A test pass
without this register does not remove the reason. No file facts are invented
automatically. Run sync after apply to confirm the current coverage persists.

## Retire the known obsolete root gate

The updater reports `legacy_release_gate` without changing arbitrary project
tooling. Inspect or migrate the known historical entrypoint explicitly:

```text
node .knowledge/tools/migrate-legacy-release-gate.js
node .knowledge/tools/migrate-legacy-release-gate.js --apply
```

Only the exact known 3.2.0 script is replaced, with its original bytes saved as
`tools/release-gate.js.pre-3.4.3.bak`. Custom scripts and unsafe paths are untouched.
The replacement forwards argv and exit status to `.knowledge/tools/release-gate.js`.
Release tooling is maintainer-only and is deliberately absent from runtime ZIPs;
without it, the redirect returns `maintainer_release_gate_unavailable`, exit 2.
It never substitutes `flow release` or reports release readiness from missing
checks. The migration itself does not execute a gate.

Focused coverage uses current APIs: `self-test-inspector-actions.js` and
`self-test-inspector-ui.js` cover Inspector behavior, `self-test-export-privacy.js`
covers snapshot redaction, and `self-test-extension-verification.js` separately
covers current entitlement gating and actual signature verification. The
legacy-gate regression uses a stub gate only; it does not launch certification.

## Authenticated extension manifests

Locally managed `extensions/trusted-keys.json` contains a `keys` object mapping
publisher key IDs to Ed25519 public keys in PEM format. No publisher key is
trusted by default. The bundle's companion JSON manifest contains:

```json
{
  "extension_id": "example",
  "version": "1.0.0",
  "channel": "stable",
  "core_versions": ["3.4.3"],
  "entitlements_required": ["extension_base"],
  "key_id": "publisher-key-id",
  "sha256": "<SHA-256 of bundle bytes>",
  "signature": "ed25519:<base64 detached signature>"
}
```

The signed bytes are UTF-8 canonical JSON of every manifest field except
`signature`: recursively sorted object keys, array order preserved, no
whitespace. Use `signingPayload` from `tools/lib/extension-verification.js` to
obtain the exact bytes. Changing metadata or bundle bytes invalidates acceptance.
The bundle bytes written to installation are the same bytes authenticated.

An active local entitlement requires `extension_base` (legacy `pro_base` is
accepted as a compatibility alias). The explicit development flag
`KNOWLEDGE_EXTENSION_DEV_ENTITLEMENT=1` grants development entitlements only;
it never bypasses publisher authentication. Local entitlements are not a remote
license-verification service. Old `dev-signed:` manifests and prefix-only
signatures must be replaced with genuinely signed manifests.
