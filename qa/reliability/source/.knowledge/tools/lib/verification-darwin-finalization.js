'use strict';

// Read-only validation of the native facts sealed into a Darwin batch.
// A successful run/exit code cannot replace current command and terminal
// cleanup proofs. The caller additionally verifies the batch signature/KVE.
const wire = require('./verification-darwin-session-protocol');
const { copyInertData } = require('./inert-data');
const SCHEMA = 'knowledge-verification-finalization.darwin.v1';
const ACK_SCHEMA = 'knowledge-verification-acceptance.darwin.v1';
const IMPLEMENTATION_PATHS = Object.freeze([
  'tools/lib/verification-darwin-production.js',
  'tools/lib/verification-darwin-store.js',
  'tools/lib/verification-darwin-finalization.js',
  'tools/lib/verification-darwin-session.js',
  'tools/lib/verification-darwin-session-protocol.js',
  'tools/lib/verification-darwin-client.js',
  'tools/lib/verification-darwin-broker.m',
  'tools/lib/verification-darwin-stub.c',
  'tools/lib/verification-darwin-transport.h',
  'tools/lib/verification-darwin-uid-history.h',
  'tools/lib/verification-darwin-uid-history.m',
  'tools/lib/verification-isolated-copy.js',
  'tools/lib/verification-control.js',
  'tools/lib/verification-finalization.js',
  'tools/lib/verification-execution.js',
  'tools/lib/verification-supervisor.js',
  'tools/lib/repair-on-touch.js',
  'tools/lib/inert-data.js',
  'tools/lib/verification-policy.js',
  'tools/lib/contained-lock-manager.js',
  'tools/lib/lock-policy.js',
  'tools/lib/lock-publication.js',
  'tools/native/lock-publication.c',
  'schemas/verification-execution-v2.schema.json'
]);
function invalid() { throw Object.assign(new Error('Darwin batch lacks current native finality'), { code: 'verification_finalization_required' }); }
function validate(record) {
  try {
    record = copyInertData(record, null, 256 * 1024);
    const d = record?.darwin;
    if (record?.schema_version !== SCHEMA || record.backend !== 'darwin_private_ruid' || !d ||
        !d.binding || !d.capability || !d.plan || !Array.isArray(d.readbacks) || d.readbacks.length < 3 ||
        !Array.isArray(d.command_results) || d.command_results.length !== record.executions.length ||
        !Array.isArray(d.commands) || d.commands.length !== d.command_results.length ||
        d.authority_exit?.exit_observed !== true || !Number.isSafeInteger(d.authority_exit.pid) ||
        d.authority_exit.pid < 1 || d.authority_exit.signal !== 'SIGKILL') invalid();
    const binding = d.binding, descriptor = binding.descriptor;
    if (!descriptor || descriptor.schema !== 'knowledge-darwin-private-ruid-descriptor.v2' ||
        descriptor.backend !== 'darwin_private_ruid' || descriptor.capability_qualified !== true ||
        descriptor.qualification_mode !== false || descriptor.stub_wire_version !== 'KVS2' ||
        descriptor.guardian_protocol !== 'KVR2' || !wire.hex(binding.attempt_id) ||
        descriptor.attempt_id !== binding.attempt_id || wire.digest(descriptor) !== binding.descriptor_sha256 ||
        descriptor.daemon_epoch !== d.capability.daemon_epoch || !wire.hex(descriptor.daemon_epoch)) invalid();
    const drain = wire.validateProof(d.command_drain_reply, binding, d.capability, false);
    const terminal = wire.validateProof(d.terminal_reply, binding, d.capability, true);
    if (terminal.authority_identity?.pid !== d.authority_exit.pid ||
        terminal.command_drain_sha256 !== wire.digest(drain) ||
        terminal.writer_generation < drain.writer_generation ||
        record.teardown?.descriptor_sha256 !== binding.descriptor_sha256 ||
        record.teardown?.native_terminal_sha256 !== wire.digest(terminal) ||
        record.teardown?.controller_excluded_from_boundary !== true ||
        record.teardown?.guardian_exit_confirmed !== true || record.teardown?.root_child_exit_confirmed !== true) invalid();
    for (let i = 0; i < d.commands.length; i++) {
      const command = wire.validateCommand(d.command_results[i], binding, d.capability, d.commands[i], i + 1);
      if (command.exit_code !== 0 || command.signal !== null) invalid();
    }
    if (!wire.hex(d.plan.manifest_sha256) || !wire.hex(d.plan.directories_sha256) ||
        !Array.isArray(d.plan.files) || !Array.isArray(d.plan.directories) ||
        !Number.isSafeInteger(d.plan.total_bytes) || d.plan.total_bytes < 0) invalid();
    const phases = ['sealed', 'commands_drained', 'closed'];
    if (!phases.every(phase => d.readbacks.some(row => row.phase === phase))) invalid();
    for (const readback of d.readbacks) wire.validateReadback(readback, binding, d.plan, readback.phase);
    return { binding, command_drain: drain, terminal };
  } catch { invalid(); }
}
module.exports = { SCHEMA, ACK_SCHEMA, IMPLEMENTATION_PATHS, validate };
