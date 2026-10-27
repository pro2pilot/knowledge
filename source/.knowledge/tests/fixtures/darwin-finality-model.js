'use strict';
// Synthetic protocol values only. These are not native process observations
// and must never be reported as macOS or production execution qualification.
const wire = require('../../tools/lib/verification-darwin-session-protocol');
const bridge = require('../../tools/lib/verification-darwin-control');
const final = require('../../tools/lib/verification-darwin-finalization');
function model() {
  const hex = n => String(n).repeat(64);
  const capability = { source_sha256: hex('1'), binary_sha256: hex('2'), daemon_epoch: hex('3'),
    stub_source_sha256: hex('5'), stub_binary_sha256: hex('6'), transport_header_sha256: hex('7'),
    uid_history_header_sha256: hex('8'), uid_history_source_sha256: hex('9'), installation_id: hex('a'),
    account_policy_id: 'admin_reserved_interval_no_runtime_nss.v1', account_policy_sha256: hex('b'),
    host_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', boot_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    runtime_path: '/protected/node', runtime_sha256: hex('c'), capability_qualified: true, qualification_mode: false };
  const id = hex('4');
  const descriptor = { ...capability, schema: 'knowledge-darwin-private-ruid-descriptor.v2', backend: 'darwin_private_ruid',
    broker_binary_sha256: capability.binary_sha256, mode: 'isolated_copy', attempt_id: id, boundary_id: id,
    attempt_nonce: hex('d'), task_ruid: 1000000000, task_gid: 1000000000, owner_uid: 501,
    stub_wire_version: 'KVS2', guardian_protocol: 'KVR2', allocation_seq: '1', allocation_sha256: hex('e'),
    workspace_path: '/protected/work/' + id, scratch_path: '/protected/work/' + id + '.scratch', scratch_policy: 'private_uid_sibling.v1',
    allowed_runtimes: { '/protected/node': capability.runtime_sha256 }, work_started_monotonic_ms: 100,
    work_budget_ms: 100000, work_deadline_ms: 100100, cleanup_budget_ms: 60000 };
  const binding = { attempt_id: id, descriptor_sha256: wire.digest(descriptor), descriptor };
  const scope = { schema_version: 'knowledge-command-scope.v1', backend: 'darwin_uid_guardian', binding,
    broker_path: '/protected/broker', broker_socket: '/private/tmp/model.sock' };
  const birth = (pid, unique, parent) => ({ pid, start_sec: 100, start_usec: 1, ruid: 501,
    unique_id: String(unique), parent_unique_id: String(parent), pidversion: 1 });
  const identity = value => ({ schema: 'knowledge-darwin-process-identity.v1', host_id: capability.host_id,
    boot_id: capability.boot_id, owner_uid: 501, birth: value });
  const controller = identity(birth(40, 100, 1)), authority = identity(birth(41, 101, 100));
  const controlDescriptor = bridge.descriptor({ scope, controller_identity: controller, authority_identity: authority });
  const common = { attempt_id: id, descriptor_sha256: binding.descriptor_sha256, daemon_epoch: capability.daemon_epoch,
    writer_generation: 7, proof_current: true, capability_qualified: true };
  const command = { argv: [capability.runtime_path, descriptor.workspace_path + '/run.js'], env: {}, cwd: '.', timeout_ms: 90000 };
  const result = { ...common, ok: true, schema: 'knowledge-darwin-command-result.v1', command_ordinal: 1,
    command_sha256: wire.digest(command), guardian_protocol: 'KVR2', guardian_reaped: true, permit_observed: true,
    timed_out: false, stop_latched: false, admission_closed: false, exit_code: 0, signal: null };
  for (const key of ['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq', 'allocation_sha256', 'host_id', 'boot_id']) result[key] = descriptor[key];
  const proofBase = { ...common, uid_history_tuple_verified: true, kernel_membership_zero: true, admission_closed: true,
    spawn_exclusion_acquired: true, spawn_intents_resolved: true, guardian_exit_confirmed: true, root_child_exit_confirmed: true,
    cleanup_started_monotonic_ms: 1000, cleanup_deadline_monotonic_ms: 61000, observed_monotonic_ms: 1100,
    abort_latched: false, authority_identity: authority.birth, controller_identity: controller.birth };
  for (const key of ['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq', 'allocation_sha256',
    'host_id', 'boot_id', 'account_policy_id', 'account_policy_sha256', 'task_ruid']) proofBase[key] = descriptor[key];
  const drain = { ...proofBase, schema: 'knowledge-darwin-command-drain-proof.v1', terminal_cleanup: false,
    native_command_drain_facts_confirmed: true, command_drain_confirmed: true,
    registered_authority_alive: true, spawn_exclusion_held_until_terminal: true };
  const terminal = { ...proofBase, writer_generation: 8, schema: 'knowledge-darwin-private-ruid-proof.v1', terminal_cleanup: true,
    observed_monotonic_ms: 1300, native_cleanup_facts_confirmed: true, cleanup_confirmed: true,
    registered_authority_exited: true, cleanup_budget_exceeded: false, planned_terminal: true,
    command_drain_sha256: wire.digest(drain) };
  const replyBase = { ...common, ok: true, cleanup_only: false, allocation_tuple_verified_current: true,
    registry_healthy: true, cleanup_budget_exceeded: false, abort_latched: false };
  const drainReply = { ...replyBase, state: 'commands_drained', stop_reason: 'commands_complete',
    command_drain_proof: drain, command_drain_sha256: wire.digest(drain) };
  const terminalReply = { ...replyBase, writer_generation: 8, state: 'closed', planned_terminal: true, stop_reason: 'close_requested',
    proof: terminal, proof_sha256: wire.digest(terminal) };
  const authorityExit = { pid: 41, process_nonce: '1'.repeat(32), method: 'process_handle_signaled', exit_observed: true };
  const teardown = bridge.normalProof({ descriptor: controlDescriptor, terminalReply, capability, authorityExit });
  const plan = { manifest_sha256: hex('f'), directories_sha256: hex('0'), physical_binding_sha256: hex('1'),
    files: [{ path: 'run.js', sha256: hex('2') }], directories: [], total_bytes: 1 };
  const readbacks = ['sealed', 'commands_drained', 'closed'].map((phase, index) => {
    const body = { schema: 'knowledge-darwin-copy-readback.v1', attempt_id: id, descriptor_sha256: binding.descriptor_sha256,
      phase, manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256,
      workspace_identity: { device: '1', inode: '2' }, files: 1, directories: 0, bytes: 1,
      verified_current: true, allocation_tuple_verified_current: true, observed_monotonic_ms: 900 + 250 * index,
      capability_qualified: true };
    return { ...body, readback_sha256: wire.digest(body), ok: true };
  });
  const stream = { stdout_bytes: 0, stderr_bytes: 0, stdout_sha256: wire.sha(''), stderr_sha256: wire.sha(''),
    helper: { pid: 42, exit_observed: true, exit_code: 0, signal: null } };
  const source = [{ path: 'run.js', sha256: hex('2') }];
  const record = { schema_version: final.SCHEMA, backend: 'darwin_private_ruid', runtime_sha256: capability.runtime_sha256,
    executions: [{ execution_id: 'KVE-' + hex('3') }], teardown,
    darwin: { binding, scope, capability, plan_summary: final.planSummary(plan), source_snapshot: source,
      readbacks, commands: [command], command_results: [result], streams: [stream],
      command_drain_reply: drainReply, terminal_reply: terminalReply,
      authority_exit: { ...authorityExit, ipc_closed: true, signal: 'SIGKILL', exit_code: null } } };
  const execution = { command_argv: ['node', 'run.js'], status: 'pass', exit_code: 0, signal: null, timed_out: false,
    runtime_binding: 'process_exec_path', runtime_sha256: capability.runtime_sha256, environment_profile: 'sanitized_node',
    cwd: '.', source_snapshot: source, source_snapshot_before: source, stdout_bytes: 0, stderr_bytes: 0,
    stdout_sha256: stream.stdout_sha256, stderr_sha256: stream.stderr_sha256 };
  return { record, execution, plan, controlDescriptor, authority, controller, binding, capability };
}
module.exports = { model };
