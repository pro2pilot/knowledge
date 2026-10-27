'use strict';

// Versioned critical-source provenance for the whole invocation boundary.
// These are observed source bytes, not a claim of hermetic process attestation.
// Native provider manifests and exact kernel closure remain separate proofs.
const PROFILE = 'knowledge-runtime-authority.reliability.v1';
const INVOCATION_PATHS = Object.freeze([
  'tools/lib/runtime-authority-profile.js',
  'tools/lib/command-runner.js',
  'tools/lib/command-sync-driver.js',
  'tools/lib/command-worker.js',
  'tools/lib/command-cli-worker.js',
  'tools/lib/command-runtime-prepare.js',
  'tools/lib/command-scope-proof.js',
  'tools/lib/command-scope-query-client.js',
  'tools/lib/command-scope-relay.js',
  'tools/lib/command-holder-channel.js',
  'tools/lib/command-windows-bootstrap.js',
  'tools/lib/command-windows-custody.js',
  'tools/lib/command-windows-guard.js',
  'tools/lib/command-windows-holder.js',
  'tools/lib/command-windows-native.js',
  'tools/lib/command-windows-observe-holder.js',
  'tools/lib/command-windows-protocol.js',
  'tools/lib/command-windows-query.js',
  'tools/lib/command-windows-receipts.js',
  'tools/lib/command-windows-retire.js',
  'tools/lib/command-windows-runtime.js',
  'tools/lib/command-windows-scope.js',
  'tools/lib/verification-invocation.js',
  'tools/lib/verification-cancel-observer.js',
  'tools/lib/lock-publication.js',
  'tools/lib/lock-owner-schema.js',
  'tools/lib/stable-file.js',
  'tools/lib/contained-artifact.js',
  'tools/lib/semantic-json.js',
  'tools/native/lock-publication.c',
  'tools/native/command-windows-job.c'
]);

module.exports = Object.freeze({ PROFILE, INVOCATION_PATHS });
