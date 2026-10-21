'use strict';

// Diagnostic wire validation. No KVE/KVF/ACK producer or acceptance adapter.
const crypto = require('node:crypto');
const { copyInertData } = require('./inert-data');
const copy = require('./verification-isolated-copy');
const { nativeExecutionConfig, resolvePolicy } = require('./verification-policy');
const path = require('node:path');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const fail = code => { throw Object.assign(new Error(code), { code }); };
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort()
    .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
const digest = value => sha(canonical(value));
function request(value) {
  try { value = copyInertData(value, null, 1024 * 1024); }
  catch { fail('darwin_diagnostic_request_invalid'); }
  if (!exact(value, ['report_only', 'repoRoot', 'stateRoot', 'test', 'sourceFiles', 'nativeExecution', 'verificationPolicy']) ||
      value.report_only !== true || typeof value.repoRoot !== 'string' || !path.isAbsolute(value.repoRoot) ||
      typeof value.stateRoot !== 'string' || path.resolve(value.stateRoot) !== path.join(path.resolve(value.repoRoot), '.knowledge') ||
      !exact(value.test, ['argv', 'cwd', 'timeout_ms']) || !Array.isArray(value.test.argv) ||
      !Array.isArray(value.sourceFiles) || value.sourceFiles.length < 1 || value.sourceFiles.length > 50000) {
    fail('darwin_diagnostic_request_invalid');
  }
  // The first vertical deliberately excludes generators, arbitrary node flags,
  // arguments, shell commands, env overrides and output import/currency.
  const argv = value.test.argv;
  if (!(argv.length === 2 && argv[0] === 'node' ||
      argv.length === 3 && argv[0] === 'node' && argv[1] === '--test') ||
      !Number.isSafeInteger(value.test.timeout_ms) || value.test.timeout_ms < 1 || value.test.timeout_ms > 60_000_000_000) {
    fail('darwin_diagnostic_command_unsupported');
  }
  const script = copy.relativeName(argv.at(-1));
  if (!/\.(?:js|cjs|mjs)$/.test(script)) fail('darwin_diagnostic_command_unsupported');
  const cwd = copy.relativeName(value.test.cwd, true);
  const required = [...new Set([...value.sourceFiles.map(name => copy.relativeName(name)),
    cwd === '.' ? script : `${cwd}/${script}`])].sort();
  const config = nativeExecutionConfig(value.nativeExecution);
  if (!config.darwin.enabled) fail('darwin_diagnostic_explicit_opt_in_required');
  const policy = resolvePolicy(value.verificationPolicy);
  // This diagnostic slice has no trusted semantic progress source. Require an
  // explicit disabled inactivity limit rather than silently ignoring it.
  if (policy.no_progress_ms !== 0) fail('darwin_diagnostic_progress_signal_unavailable');
  return { report_only: true, repoRoot: path.resolve(value.repoRoot), stateRoot: path.resolve(value.stateRoot),
    test: { argv: [...argv], cwd, timeout_ms: value.test.timeout_ms }, sourceFiles: required,
    nativeExecution: config, verificationPolicy: { profile: policy.profile, work_budget_ms: policy.work_budget_ms,
      no_progress_ms: policy.no_progress_ms, cleanup_budget_ms: policy.cleanup_budget_ms } };
}
function descriptor(value, probe, nonce) {
  const d = value?.descriptor;
  if (!value?.ok || !hex(value.attempt_id) || !hex(value.descriptor_sha256) ||
      !d || digest(d) !== value.descriptor_sha256 || d.attempt_id !== value.attempt_id ||
      d.attempt_nonce !== nonce || d.schema !== 'knowledge-darwin-private-ruid-descriptor.v1' ||
      d.backend !== 'darwin_private_ruid' || d.mode !== 'isolated_copy' ||
      d.capability_qualified !== false || d.qualification_mode !== true ||
      d.source_sha256 !== probe.reply.source_sha256 || d.broker_binary_sha256 !== probe.reply.binary_sha256 ||
      d.stub_source_sha256 !== probe.reply.stub_source_sha256 || d.stub_binary_sha256 !== probe.reply.stub_binary_sha256 ||
      d.transport_header_sha256 !== probe.reply.transport_header_sha256 ||
      d.uid_history_header_sha256 !== probe.reply.uid_history.header_sha256 ||
      d.uid_history_source_sha256 !== probe.reply.uid_history.source_sha256 ||
      d.installation_id !== probe.reply.uid_history.installation_id_cached ||
      d.host_id !== probe.reply.host_id || d.boot_id !== probe.reply.boot_id ||
      d.account_policy_id !== probe.reply.account_policy.id || d.account_policy_sha256 !== probe.reply.account_policy.sha256 ||
      d.allowed_runtimes?.[probe.runtime_path] !== probe.runtime_sha256 ||
      !Number.isSafeInteger(d.task_ruid) || d.task_ruid < 1000000000 || d.task_gid !== d.task_ruid ||
      !path.posix.isAbsolute(d.workspace_path || '') || d.workspace_path !== value.workspace_path ||
      !hex(value.token)) fail('darwin_diagnostic_descriptor_invalid');
  return d;
}
const RUN_KEYS = ['ok', 'schema', 'attempt_id', 'descriptor_sha256', 'command_ordinal', 'command_sha256',
  'source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq', 'allocation_sha256',
  'host_id', 'boot_id', 'timed_out', 'stop_latched', 'exit_code', 'signal', 'admission_closed', 'capability_qualified'];
function commandResult(value, binding, command) {
  const d = binding.descriptor;
  if (!exact(value, RUN_KEYS) || value.ok !== true || value.schema !== 'knowledge-darwin-command-result.v1' ||
      value.attempt_id !== binding.attempt_id || value.descriptor_sha256 !== binding.descriptor_sha256 ||
      value.command_ordinal !== 1 || value.command_sha256 !== digest(command) ||
      ['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq', 'allocation_sha256', 'host_id', 'boot_id']
        .some(key => value[key] !== d[key]) || value.capability_qualified !== false ||
      typeof value.timed_out !== 'boolean' || typeof value.stop_latched !== 'boolean' ||
      typeof value.admission_closed !== 'boolean' ||
      !(value.exit_code === null || Number.isInteger(value.exit_code) && value.exit_code >= 0 && value.exit_code <= 255) ||
      !(value.signal === null || Number.isInteger(value.signal) && value.signal > 0 && value.signal <= 128) ||
      (value.exit_code === null) === (value.signal === null)) {
    fail('darwin_diagnostic_command_result_invalid');
  }
  return value;
}
function commandPassed(value) {
  return value.ok === true && value.exit_code === 0 && value.signal === null &&
    value.timed_out === false && value.stop_latched === false && value.admission_closed === false;
}
function readback(value, binding, plan, phase) {
  const keys = ['ok', 'schema', 'attempt_id', 'descriptor_sha256', 'phase', 'manifest_sha256',
    'directories_sha256', 'workspace_identity', 'files', 'directories', 'bytes', 'verified_current',
    'allocation_tuple_verified_current', 'observed_monotonic_ms', 'capability_qualified', 'readback_sha256'];
  const { ok, readback_sha256, ...body } = value || {};
  if (!exact(value, keys) || ok !== true || value.schema !== 'knowledge-darwin-copy-readback.v1' ||
      value.attempt_id !== binding.attempt_id || value.descriptor_sha256 !== binding.descriptor_sha256 ||
      value.phase !== phase || value.manifest_sha256 !== plan.manifest_sha256 ||
      value.directories_sha256 !== plan.directories_sha256 || value.files !== plan.files.length ||
      value.directories !== plan.directories.length || value.bytes !== plan.total_bytes ||
      value.verified_current !== true || value.allocation_tuple_verified_current !== true ||
      value.capability_qualified !== false || !exact(value.workspace_identity, ['device', 'inode']) ||
      !['device', 'inode'].every(key => typeof value.workspace_identity[key] === 'string' && /^\d+$/.test(value.workspace_identity[key])) ||
      !Number.isSafeInteger(value.observed_monotonic_ms) || value.observed_monotonic_ms < 0 ||
      !hex(readback_sha256) || digest(body) !== readback_sha256) fail('darwin_diagnostic_copy_readback_invalid');
  return value;
}
function facts(value, binding, terminal) {
  const d = binding.descriptor, p = terminal ? value?.proof : value?.command_drain_proof;
  if (value?.ok !== true || value.attempt_id !== binding.attempt_id ||
      value.descriptor_sha256 !== binding.descriptor_sha256 || value.allocation_tuple_verified_current !== true ||
      value.registry_healthy !== true || value.observation_cached === true || value.cleanup_budget_exceeded !== false ||
      !['commands_complete', 'close_requested'].includes(value.stop_reason) ||
      !p || p.schema !== (terminal ? 'knowledge-darwin-private-ruid-proof.v1' : 'knowledge-darwin-command-drain-proof.v1') ||
      p.attempt_id !== binding.attempt_id || p.descriptor_sha256 !== binding.descriptor_sha256 ||
      ['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq', 'allocation_sha256',
        'host_id', 'boot_id', 'account_policy_id', 'account_policy_sha256', 'task_ruid']
        .some(key => p[key] !== d[key]) || p.capability_qualified !== false ||
      p.uid_history_tuple_verified !== true ||
      value[terminal ? 'proof_sha256' : 'command_drain_sha256'] !== digest(p) ||
      p.terminal_cleanup !== terminal || p.kernel_membership_zero !== true ||
      p.admission_closed !== true || p.spawn_exclusion_acquired !== true || p.spawn_intents_resolved !== true ||
      (terminal ? value.state !== 'closed' || p.native_cleanup_facts_confirmed !== true ||
          p.cleanup_confirmed !== false || p.registered_authority_exited !== true || p.cleanup_budget_exceeded !== false
        : value.state !== 'commands_drained' || p.native_command_drain_facts_confirmed !== true ||
          p.command_drain_confirmed !== false || p.registered_authority_alive !== true || p.spawn_exclusion_held_until_terminal !== true)) {
    fail(terminal ? 'darwin_diagnostic_terminal_facts_invalid' : 'darwin_diagnostic_drain_facts_invalid');
  }
  return p;
}
module.exports = { canonical, digest, sha, hex, exact, request, descriptor, commandResult, commandPassed, readback, facts };
