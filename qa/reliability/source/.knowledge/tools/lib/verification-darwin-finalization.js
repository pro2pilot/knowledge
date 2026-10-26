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
  'tools/lib/verification-darwin-authority.js',
  'tools/lib/verification-darwin-store.js',
  'tools/lib/verification-darwin-storage-guardian.js',
  'tools/lib/verification-darwin-finalization.js',
  'tools/lib/verification-darwin-session.js',
  'tools/lib/verification-darwin-session-protocol.js',
  'tools/lib/verification-darwin-preparation.js',
  'tools/lib/verification-darwin-preparer.js',
  'tools/lib/verification-darwin-scope.js',
  'tools/lib/verification-darwin-control.js',
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
  'tools/lib/lock-owner-schema.js',
  'tools/lib/lock-publication.js',
  'tools/lib/stable-file.js',
  'tools/lib/json-store.js',
  'tools/lib/verification-recovery.js',
  'tools/native/lock-publication.c',
  'schemas/verification-execution-v2.schema.json'
]);
function invalid() { throw Object.assign(new Error('Darwin batch lacks current native finality'), { code: 'verification_finalization_required' }); }
function planSummary(plan) {
  return { manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256,
    physical_binding_sha256: plan.physical_binding_sha256, files: plan.files.length,
    directories: plan.directories.length, total_bytes: plan.total_bytes, no_writeback: true };
}
function readbackPlan(summary) {
  if (!summary || Object.keys(summary).sort().join(',') !== 'directories,directories_sha256,files,manifest_sha256,no_writeback,physical_binding_sha256,total_bytes' ||
      !['manifest_sha256', 'directories_sha256', 'physical_binding_sha256'].every(key => wire.hex(summary[key])) ||
      !['files', 'directories', 'total_bytes'].every(key => Number.isSafeInteger(summary[key]) && summary[key] >= 0) ||
      summary.files > 50000 || summary.directories > 50000 || summary.total_bytes > 2147483648 || summary.no_writeback !== true) invalid();
  return { files: { length: summary.files }, directories: { length: summary.directories },
    total_bytes: summary.total_bytes, manifest_sha256: summary.manifest_sha256, directories_sha256: summary.directories_sha256 };
}
function same(a, b) { return wire.canonical(a) === wire.canonical(b); }
function validateExecution(record, execution, index) {
  try {
    const d = record.darwin, command = d.commands[index], stream = d.streams[index], argv = execution.command_argv;
    if (!Array.isArray(argv) || !['node', 'node.exe'].includes(argv[0]) || !Array.isArray(command.argv) ||
        execution.status !== 'pass' || execution.exit_code !== 0 || execution.signal !== null || execution.timed_out !== false ||
        execution.runtime_binding !== 'process_exec_path' || execution.runtime_sha256 !== d.capability.runtime_sha256 ||
        execution.environment_profile !== 'sanitized_node' || command.argv[0] !== d.capability.runtime_path ||
        command.cwd !== execution.cwd || !same(execution.source_snapshot, d.source_snapshot) ||
        !same(execution.source_snapshot_before, d.source_snapshot) ||
        !['stdout_bytes', 'stderr_bytes', 'stdout_sha256', 'stderr_sha256'].every(key => execution[key] === stream[key])) invalid();
    const scriptIndex = argv[1] === '--test' ? 2 : 1;
    const script = require('./verification-isolated-copy').relativeName(argv[scriptIndex]);
    const expected = [...argv];expected[0] = d.capability.runtime_path;
    expected[scriptIndex] = require('node:path').posix.join(d.binding.descriptor.workspace_path, script);
    if (!same(expected, command.argv)) invalid();
  } catch { invalid(); }
}
function validate(record) {
  try {
    record = copyInertData(record, null, 256 * 1024);
    const d = record?.darwin;
    if (record?.schema_version !== SCHEMA || record.backend !== 'darwin_private_ruid' || !d ||
        !d.binding || !d.capability || !d.plan_summary || !Array.isArray(d.readbacks) || d.readbacks.length !== 3 ||
        !Array.isArray(d.command_results) || d.command_results.length !== record.executions.length ||
        !Array.isArray(d.commands) || d.commands.length !== d.command_results.length ||
        !Array.isArray(d.streams) || d.streams.length !== d.commands.length ||
        !Array.isArray(d.source_snapshot) || !d.source_snapshot.length ||
        d.source_snapshot.some(row => !row || !wire.hex(row.sha256) || typeof row.path !== 'string') ||
        new Set(d.source_snapshot.map(row => row.path)).size !== d.source_snapshot.length ||
        d.authority_exit?.exit_observed !== true || !Number.isSafeInteger(d.authority_exit.pid) ||
        d.authority_exit.pid < 1 || d.authority_exit.signal !== 'SIGKILL') invalid();
    const binding = d.binding, descriptor = binding.descriptor;
    if (!descriptor || descriptor.schema !== 'knowledge-darwin-private-ruid-descriptor.v2' ||
        descriptor.backend !== 'darwin_private_ruid' || descriptor.capability_qualified !== true ||
        descriptor.qualification_mode !== false || descriptor.stub_wire_version !== 'KVS2' ||
        descriptor.guardian_protocol !== 'KVR2' || !wire.hex(binding.attempt_id) ||
        descriptor.attempt_id !== binding.attempt_id || wire.digest(descriptor) !== binding.descriptor_sha256 ||
        descriptor.daemon_epoch !== d.capability.daemon_epoch || !wire.hex(descriptor.daemon_epoch) ||
        !require('./verification-darwin-scope').validateCommandScope(d.scope) || !same(d.scope.binding, binding) ||
        !['source_sha256', 'stub_source_sha256', 'stub_binary_sha256', 'transport_header_sha256',
          'uid_history_header_sha256', 'uid_history_source_sha256', 'installation_id', 'account_policy_id',
          'account_policy_sha256', 'host_id', 'boot_id'].every(key => descriptor[key] === d.capability[key]) ||
        descriptor.broker_binary_sha256 !== d.capability.binary_sha256 ||
        descriptor.allowed_runtimes[d.capability.runtime_path] !== d.capability.runtime_sha256 ||
        record.runtime_sha256 !== d.capability.runtime_sha256) invalid();
    const drain = wire.validateProof(d.command_drain_reply, binding, d.capability, false);
    const terminal = wire.validateProof(d.terminal_reply, binding, d.capability, true);
    if (terminal.authority_identity?.pid !== d.authority_exit.pid ||
        terminal.command_drain_sha256 !== wire.digest(drain) ||
        terminal.writer_generation < drain.writer_generation ||
        record.teardown?.native_descriptor_sha256 !== binding.descriptor_sha256 ||
        record.teardown?.native_terminal_sha256 !== wire.digest(terminal) ||
        record.teardown?.controller_excluded_from_boundary !== true ||
        record.teardown?.guardian_exit_confirmed !== true || record.teardown?.root_child_exit_confirmed !== true) invalid();
    for (let i = 0; i < d.commands.length; i++) {
      const command = wire.validateCommand(d.command_results[i], binding, d.capability, d.commands[i], i + 1);
      const stream = d.streams[i];
      if (command.exit_code !== 0 || command.signal !== null ||
          !stream || !['stdout_sha256', 'stderr_sha256'].every(key => wire.hex(stream[key])) ||
          !['stdout_bytes', 'stderr_bytes'].every(key => Number.isSafeInteger(stream[key]) && stream[key] >= 0 && stream[key] <= 16 * 1024 * 1024) ||
          stream.helper?.exit_observed !== true || stream.helper.exit_code !== 0 || stream.helper.signal !== null) invalid();
    }
    const plan = readbackPlan(d.plan_summary);
    const phases = ['sealed', 'commands_drained', 'closed'];
    if (!phases.every((phase, index) => d.readbacks[index].phase === phase)) invalid();
    for (const readback of d.readbacks) wire.validateReadback(readback, binding, plan, readback.phase);
    if (!d.readbacks.every(row => same(row.workspace_identity, d.readbacks[0].workspace_identity))) invalid();
    // These timestamps all come from the same native monotonic clock. Do not
    // compare them with the controller's separate Node clock epoch.
    const order = [descriptor.work_started_monotonic_ms, d.readbacks[0].observed_monotonic_ms,
      drain.observed_monotonic_ms, d.readbacks[1].observed_monotonic_ms,
      terminal.observed_monotonic_ms, d.readbacks[2].observed_monotonic_ms];
    if (order.some((value, index) => !Number.isSafeInteger(value) || value < 0 ||
        index > 0 && value < order[index - 1]) ||
        order.at(-1) >= terminal.cleanup_deadline_monotonic_ms) invalid();
    return { binding, command_drain: drain, terminal };
  } catch { invalid(); }
}
module.exports = { SCHEMA, ACK_SCHEMA, IMPLEMENTATION_PATHS, planSummary, validate, validateExecution };
