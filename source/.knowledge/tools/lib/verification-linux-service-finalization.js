'use strict';

// Read-only admission of a Linux service batch. Native A/W finality and the
// ordinary controller's storage-writer custody are separate observations.
// The controller withholds external ACK until both storage writers close.
const crypto = require('node:crypto');
const { copyInertData } = require('./inert-data');
const isolated = require('./verification-isolated-copy');
const SCHEMA = 'knowledge-verification-finalization.linux-service.v1';
const ACK_SCHEMA = 'knowledge-verification-acceptance.linux-service.v1';
const METHOD = 'linux_native_service';
const NATIVE_SCHEMA = 'knowledge-linux-native-service.v1';
const AUTHORITY_SCHEMA = 'knowledge-linux-service-authority-result.v1';
const HEX = /^[a-f0-9]{64}$/;
const HEX16 = /^[a-f0-9]{32}$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_AUTHORITY_BYTES = 128 * 1024;
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const stable = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
const same = (a, b) => stable(a) === stable(b);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const integer = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= min && value <= max;
const ns = value => typeof value === 'string' && DECIMAL.test(value) && BigInt(value) <= 18446744073709551615n;
function invalid() { throw Object.assign(new Error('Linux service batch lacks current native finality'), { code: 'verification_finalization_required' }); }
function need(value) { if (!value) invalid(); }
function inert(value, maximum = 256 * 1024) {
  const result = copyInertData(value, null, maximum * 32);
  need(Buffer.byteLength(JSON.stringify(result)) <= maximum);
  return result;
}
function rawObject(raw, maximum) {
  need(typeof raw === 'string' && Buffer.byteLength(raw) > 0 && Buffer.byteLength(raw) <= maximum);
  const result = inert(JSON.parse(raw), maximum);
  // This also rejects duplicate keys, alternate numbers and trailing bytes.
  need(JSON.stringify(result) === raw);
  return result;
}
function relative(value, cwd = false) {
  need(typeof value === 'string' && isolated.relativeName(value, cwd) === value);
  return value;
}
const CAPABILITY_KEYS = ['schema_version', 'event', 'status', 'installation_id', 'host_id', 'boot_id', 'daemon_epoch',
  'source_sha256', 'runtime_sha256', 'native_source_sha256', 'trusted_runtime_manifest_sha256', 'trusted_source_manifest_sha256', 'node_sha256',
  'broker_binary_sha256', 'client_pid', 'controller_pid', 'controller_uid', 'controller_birth_ticks', 'busy'];
const OPENED_KEYS = ['schema_version', 'event', 'status', 'nonce', 'allocation_sequence', 'authority_uid', 'worker_uid',
  'keeper_pid', 'init_pid', 'work_deadline_ns', 'cleanup_budget_ms'];
const PROVENANCE_KEYS = ['installation_id', 'host_id', 'boot_id', 'daemon_epoch', 'native_source_sha256',
  'trusted_runtime_manifest_sha256', 'trusted_source_manifest_sha256', 'node_sha256', 'broker_binary_sha256'];
const TERMINAL_KEYS = ['schema_version', 'event', 'status', ...PROVENANCE_KEYS, 'nonce', 'allocation_sequence', 'authority_uid', 'worker_uid',
  'keeper_pid', 'init_pid', 'authority_namespace_pid', 'authority_pid', 'authority_birth_ticks', 'authority_pidfd_exit_observed',
  'work_deadline_ns', 'cleanup_budget_ms', 'cleanup_started_ns',
  'cleanup_deadline_ns', 'observed_ns', 'importer_drained', 'source_readonly', 'authority_readback', 'manifest_sha256',
  'directories_sha256', 'files', 'directories', 'source_bytes', 'commands', 'commands_drained', 'authority_exited',
  'authority_status', 'init_exit_observed', 'init_reaped', 'keeper_exited', 'output_eof', 'cgroup_empty', 'cgroup_scope',
  'journal_closed', 'cleanup_confirmed', 'result_bytes', 'result_sha256', 'proof_sha256'];
const PHYSICAL_FIELDS = ['init_exit_observed', 'init_reaped', 'keeper_exited', 'output_eof',
  'cgroup_empty', 'journal_closed', 'cleanup_confirmed'];
function validateCapability(input) {
  try {
    const value = inert(input, 8192);
    return exact(value, CAPABILITY_KEYS) && value.schema_version === NATIVE_SCHEMA && value.event === 'capability' &&
      value.status === 'ready' && value.busy === false &&
      ['installation_id', 'host_id', 'boot_id'].every(key => HEX16.test(value[key])) && HEX.test(value.daemon_epoch) &&
      ['source_sha256', 'runtime_sha256', 'native_source_sha256', 'trusted_runtime_manifest_sha256', 'trusted_source_manifest_sha256',
        'node_sha256', 'broker_binary_sha256'].every(key => HEX.test(value[key])) &&
      value.source_sha256 === value.native_source_sha256 && value.runtime_sha256 === value.trusted_runtime_manifest_sha256 &&
      ['client_pid', 'controller_pid'].every(key => integer(value[key], 2, 2147483647)) &&
      value.client_pid !== value.controller_pid && integer(value.controller_uid, 1, 2147483647) &&
      ns(value.controller_birth_ticks) && BigInt(value.controller_birth_ticks) > 0n;
  } catch { return false; }
}
function validateOpened(input) {
  try {
    const value = inert(input, 4096);
    return exact(value, OPENED_KEYS) && value.schema_version === NATIVE_SCHEMA && value.event === 'opened' &&
      value.status === 'starting' && HEX.test(value.nonce) && integer(value.allocation_sequence, 1) &&
      integer(value.authority_uid, 65536, 4294967294) && integer(value.worker_uid, 65536, 4294967294) && value.worker_uid === value.authority_uid + 1 &&
      ['keeper_pid', 'init_pid'].every(key => integer(value[key], 2, 2147483647)) && value.keeper_pid !== value.init_pid &&
      ns(value.work_deadline_ns) && BigInt(value.work_deadline_ns) > 0n && integer(value.cleanup_budget_ms, 1, 3600000);
  } catch { return false; }
}
function validateTerminal({ capability, terminalReply, terminalRaw, opened, successful = true }) {
  try {
    need(validateCapability(capability));
    const value = rawObject(terminalRaw, 8192);
    need(same(value, terminalReply) && exact(value, TERMINAL_KEYS) && value.schema_version === NATIVE_SCHEMA &&
      value.event === 'terminal' && ['completed', 'cancelled', 'timed_out', 'failed'].includes(value.status) &&
      HEX.test(value.nonce) && integer(value.allocation_sequence, 1) && integer(value.authority_uid, 65536, 4294967294) &&
      integer(value.worker_uid, 65536, 4294967294) && value.worker_uid === value.authority_uid + 1 && value.authority_uid !== capability.controller_uid &&
      value.worker_uid !== capability.controller_uid && ['keeper_pid', 'init_pid'].every(key => integer(value[key], 2, 2147483647)) &&
      value.keeper_pid !== value.init_pid && integer(value.authority_namespace_pid, 0, 2147483647) &&
      integer(value.authority_pid, 0, 2147483647) && value.authority_pid !== 1 && ns(value.authority_birth_ticks) &&
      typeof value.authority_pidfd_exit_observed === 'boolean' && typeof value.authority_exited === 'boolean' &&
      PROVENANCE_KEYS.every(key => value[key] === capability[key]) &&
      ['work_deadline_ns', 'cleanup_started_ns', 'cleanup_deadline_ns', 'observed_ns'].every(key => ns(value[key])) &&
      integer(value.cleanup_budget_ms, 1, 3600000) && PHYSICAL_FIELDS.every(key => value[key] === true) &&
      ['importer_drained', 'source_readonly', 'authority_readback'].every(key => typeof value[key] === 'boolean') &&
      value.cgroup_scope === 'private_authority_and_workers' && integer(value.authority_status, -1, 255) &&
      ['manifest_sha256', 'directories_sha256', 'result_sha256', 'proof_sha256'].every(key => HEX.test(value[key])) &&
      integer(value.files, 0, 50000) && integer(value.directories, 0, 50000) && value.files + value.directories <= 50000 &&
      integer(value.source_bytes, 0, 32 * 1024 * 1024) && integer(value.result_bytes, 0, 32 * 1024 * 1024) &&
      integer(value.commands, 0, 64) && integer(value.commands_drained, 0, value.commands));
    const workEnd = BigInt(value.work_deadline_ns), start = BigInt(value.cleanup_started_ns),
      end = BigInt(value.cleanup_deadline_ns), observed = BigInt(value.observed_ns), allowance = BigInt(value.cleanup_budget_ms) * 1000000n;
    need(start > 0n && end > start && end - start <= allowance && end <= workEnd + allowance && observed >= start && observed < end);
    if (value.authority_pid === 0) need(value.authority_birth_ticks === '0' && value.authority_pidfd_exit_observed === false && value.authority_exited === false);
    else need(BigInt(value.authority_birth_ticks) > 0n && value.authority_pidfd_exit_observed && value.authority_exited &&
      ![capability.client_pid, capability.controller_pid, value.keeper_pid, value.init_pid].includes(value.authority_pid));
    const suffix = ',"proof_sha256":"' + value.proof_sha256 + '"}';
    need(terminalRaw.endsWith(suffix) && hash(terminalRaw.slice(0, -suffix.length) + '}') === value.proof_sha256);
    if (opened !== undefined) {
      need(validateOpened(opened));
      for (const key of ['nonce', 'allocation_sequence', 'authority_uid', 'worker_uid', 'keeper_pid', 'init_pid', 'work_deadline_ns', 'cleanup_budget_ms']) need(value[key] === opened[key]);
    }
    if (successful) need(value.status === 'completed' && start < workEnd && value.authority_status === 0 &&
      value.authority_pid > 1 && value.authority_namespace_pid > 1 && value.importer_drained && value.source_readonly && value.authority_readback &&
      value.commands > 0 && value.commands_drained === value.commands && value.result_bytes > 0);
    return value;
  } catch { invalid(); }
}
function planSummary(plan) {
  return { manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256,
    physical_binding_sha256: plan.physical_binding_sha256, files: plan.files.length,
    directories: plan.directories.length, total_bytes: plan.total_bytes, no_writeback: true };
}
function validatePlan(plan, terminal) {
  need(exact(plan, ['manifest_sha256', 'directories_sha256', 'physical_binding_sha256', 'files', 'directories', 'total_bytes', 'no_writeback']) &&
    ['manifest_sha256', 'directories_sha256', 'physical_binding_sha256'].every(key => HEX.test(plan[key])) && plan.no_writeback === true &&
    plan.manifest_sha256 === terminal.manifest_sha256 && plan.directories_sha256 === terminal.directories_sha256 &&
    plan.files === terminal.files && plan.directories === terminal.directories && plan.total_bytes === terminal.source_bytes);
}
function validate(record) {
  try {
    record = inert(record);
    const l = record.linux;
    need(record.schema_version === SCHEMA && record.backend === METHOD && exact(l, ['capability', 'terminal_reply', 'terminal_raw', 'authority_raw', 'plan_summary', 'source_snapshot']));
    const terminal = validateTerminal({ capability: l.capability, terminalReply: l.terminal_reply, terminalRaw: l.terminal_raw });
    const authority = rawObject(l.authority_raw, MAX_AUTHORITY_BYTES);
    need(exact(authority, ['schema_version', 'nonce', 'batch_id', 'request_sha256', 'public_key', 'authority_uid', 'worker_uid',
      'manifest_sha256', 'directories_sha256', 'runtime_sha256', 'result', 'commands']) && authority.schema_version === AUTHORITY_SCHEMA &&
      Buffer.byteLength(l.authority_raw) === terminal.result_bytes && hash(l.authority_raw) === terminal.result_sha256 &&
      authority.nonce === terminal.nonce && authority.authority_uid === terminal.authority_uid && authority.worker_uid === terminal.worker_uid &&
      authority.manifest_sha256 === terminal.manifest_sha256 && authority.directories_sha256 === terminal.directories_sha256 &&
      authority.batch_id === record.batch_id && authority.request_sha256 === record.request_sha256 && authority.public_key === record.public_key &&
      authority.runtime_sha256 === l.capability.node_sha256 && record.runtime_sha256 === l.capability.node_sha256 &&
      Array.isArray(authority.result) && Array.isArray(authority.commands) && Array.isArray(record.executions) &&
      authority.result.length === terminal.commands && authority.commands.length === terminal.commands && record.executions.length === terminal.commands &&
      Array.isArray(l.source_snapshot) && l.source_snapshot.length > 0 && l.source_snapshot.length <= 50000);
    validatePlan(l.plan_summary, terminal);
    const sources = new Set();
    for (const source of l.source_snapshot) {
      need(exact(source, ['path', 'sha256']) && HEX.test(source.sha256));
      relative(source.path); need(!sources.has(source.path)); sources.add(source.path);
    }
    need(record.cleanup_budget_ms === terminal.cleanup_budget_ms && record.teardown?.status === 'completed' && record.teardown.method === METHOD && record.teardown.active_processes === 0 &&
      record.teardown.keeper_exited === true && record.teardown.native_terminal_sha256 === terminal.proof_sha256 &&
      record.teardown.controller_excluded_from_boundary === true);
    for (let index = 0; index < authority.commands.length; index++) validateExecution(record, authority.result[index]?.record, index, authority);
    return { terminal, authority };
  } catch { invalid(); }
}
function validateExecution(record, execution, index, decoded) {
  try {
    const l = record.linux, authority = decoded || rawObject(l.authority_raw, MAX_AUTHORITY_BYTES);
    const wrapper = authority.result[index], command = authority.commands[index], argv = execution?.command_argv;
    need(exact(wrapper, ['record', 'relative_path', 'idempotent']) && typeof wrapper.idempotent === 'boolean' &&
      typeof wrapper.relative_path === 'string' && wrapper.relative_path === 'maintenance/verification_executions/' + execution.content_sha256 + '.json' &&
      same(wrapper.record, execution) && record.executions[index]?.execution_id === execution.execution_id &&
      exact(command, ['ordinal', 'script', 'mode', 'args', 'cwd', 'deadline_ns', 'status', 'signal',
        'stdout_bytes', 'stderr_bytes', 'stdout_sha256', 'stderr_sha256']) && command.ordinal === index + 1 &&
      ['script', 'test'].includes(command.mode) && Array.isArray(command.args) && command.args.length <= 32 &&
      command.args.every(arg => typeof arg === 'string' && !arg.includes('\0') && Buffer.byteLength(arg) <= 4096) &&
      (command.mode !== 'test' || command.args.length === 0) && command.status === 0 && command.signal === null &&
      ns(command.deadline_ns) && BigInt(command.deadline_ns) > 0n && BigInt(command.deadline_ns) <= BigInt(l.terminal_reply.work_deadline_ns) &&
      ['stdout_bytes', 'stderr_bytes'].every(key => integer(command[key], 0, 16 * 1024 * 1024)) &&
      ['stdout_sha256', 'stderr_sha256'].every(key => HEX.test(command[key])) &&
      Array.isArray(argv) && ['node', 'node.exe'].includes(argv[0]) && execution.status === 'pass' && execution.exit_code === 0 &&
      execution.signal === null && execution.timed_out === false && execution.runtime_binding === 'process_exec_path' &&
      execution.runtime_sha256 === l.capability.node_sha256 && execution.environment_profile === 'sanitized_node' &&
      same(execution.source_snapshot, l.source_snapshot) && same(execution.source_snapshot_before, l.source_snapshot) &&
      execution.cwd === command.cwd && execution.batch_id === record.batch_id && execution.batch_ordinal === index &&
      execution.batch_public_key === record.public_key && execution.batch_request_sha256 === record.request_sha256 &&
      execution.task_id === record.task_id && execution.session_id === record.session_id &&
      ['stdout_bytes', 'stderr_bytes', 'stdout_sha256', 'stderr_sha256'].every(key => execution[key] === command[key]));
    relative(command.script); relative(command.cwd, true);
    const expected = command.mode === 'test' ? [argv[0], '--test', command.script] : [argv[0], command.script, ...command.args];
    need(same(argv, expected));
  } catch { invalid(); }
}
const IMPLEMENTATION_PATHS = Object.freeze([
  ...['authority', 'client', 'store', 'production', 'control', 'finalization', 'importer'].map(name => 'tools/lib/verification-linux-service-' + name + '.js'),
  'tools/lib/verification-linux-service.c', 'tools/lib/verification-linux-service.h',
  'tools/lib/verification-linux-uid-history.c', 'tools/lib/verification-linux-uid-history.h',
  'tools/lib/verification-isolated-copy.js', 'tools/lib/verification-control.js', 'tools/lib/verification-finalization.js',
  'tools/lib/verification-execution.js', 'tools/lib/verification-supervisor.js', 'tools/lib/repair-on-touch.js',
  'tools/lib/inert-data.js', 'tools/lib/verification-policy.js', 'tools/lib/contained-lock-manager.js',
  'tools/lib/lock-policy.js', 'tools/lib/lock-owner-schema.js', 'tools/lib/lock-publication.js',
  'tools/lib/stable-file.js', 'tools/lib/json-store.js', 'tools/lib/verification-recovery.js',
  'tools/native/lock-publication.c', 'schemas/verification-execution-v2.schema.json',
  'schemas/verification-execution-observation.schema.json'
]);
module.exports = { SCHEMA, ACK_SCHEMA, METHOD, NATIVE_SCHEMA, AUTHORITY_SCHEMA, MAX_AUTHORITY_BYTES,
  IMPLEMENTATION_PATHS, hash, same, inert, validateCapability, validateOpened, validateTerminal, planSummary, validate, validateExecution };
