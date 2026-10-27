'use strict';

// Trusted ordinary-UID storage authority. Repository programs run only through
// the fixed native session. The signing key is never sent to this process.
const path = require('node:path');
const { copyInertData } = require('./inert-data');
const isolated = require('./verification-isolated-copy');
const sessions = require('./verification-darwin-session');
const wire = require('./verification-darwin-session-protocol');
const core = require('./repair-on-touch').__runVerificationTestsCore;
const PROTOCOL = 'knowledge-darwin-authority.v1';
const MAX_OUTPUT = 16 * 1024 * 1024;
const MAX_MESSAGE = 32 * 1024 * 1024;
const clock = () => process.hrtime.bigint();
const fail = code => { throw Object.assign(new Error(code), { code }); };
let used = false, stopped = false, session, plan, payload, workDeadline, phaseSequence = 0;
const abort = new AbortController();
const acknowledgements = new Map();
function guard() {
  if (stopped || abort.signal.aborted || !process.connected) fail('verification_darwin_cancelled');
  if (workDeadline && clock() >= workDeadline) fail('verification_timeout');
}
function send(message) {
  const value = { protocol: PROTOCOL, ...message };
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_MESSAGE) return Promise.reject(Object.assign(new Error('verification_transport_oversized'), { code: 'verification_transport_oversized' }));
  return new Promise((resolve, reject) => process.send(value, error => error ? reject(error) : resolve()));
}
async function phase(stage, deadline) {
  guard();
  const id = ++phaseSequence;
  const waiting = new Promise(resolve => acknowledgements.set(id, resolve));
  await send({ type: 'phase', id, stage, deadline_ns: String(deadline) });
  await waiting;guard();
}
async function sourceSnapshot(paths) {
  guard(); await isolated.verifyProjectPlan(plan, { checkpoint: guard });
  // The copy is root-owned and readable through the broker's exact read ACL.
  // Observe its bytes directly; aggregate native readback separately verifies
  // the entire copied tree and ACL at the three lifecycle boundaries.
  const snapshot = await session.sourceSnapshot(paths);
  for (const item of snapshot) {
    const expected = plan.files.find(row => row.path === item.path);
    if (!expected || expected.sha256 !== item.sha256) fail('verification_copy_source_changed');
  }
  if (snapshot.length !== paths.length) fail('verification_copy_source_changed');
  guard();return snapshot;
}
const commandRecords = [], commands = [], streams = [];
async function runCommand(details) {
  guard();
  if (!details.nodeCommand || details.generatedProducer || details.cwdRelative.includes('\\')) {
    fail('verification_darwin_command_unsupported');
  }
  const invocation = details.nodeInvocation;
  if (!invocation?.valid) fail('verification_node_invocation_unsafe');
  const script = isolated.relativeName(invocation.script);
  if (!plan.files.some(row => row.path === script)) fail('verification_copy_required_source_excluded');
  const runtime = session.capability.runtime_path;
  const temp = session.binding.descriptor.scratch_path;
  if (session.binding.descriptor.scratch_policy !== 'private_uid_sibling.v1' ||
      temp !== session.workspace_path + '.scratch') fail('verification_darwin_scratch_unconfirmed');
  const env = { PATH: path.posix.dirname(runtime), HOME: temp, TMPDIR: temp, TMP: temp, TEMP: temp };
  for (const key of ['LANG', 'LC_ALL']) {
    const value = details.commandOptions.env[key];
    if (typeof value === 'string') env[key] = value;
  }
  const remoteScript = path.posix.join(session.workspace_path, script);
  const command = { argv: [runtime, ...(invocation.mode === 'test' ? ['--test', remoteScript] : [remoteScript, ...details.argv.slice(2)])],
    env, cwd: isolated.relativeName(details.cwdRelative, true),
    timeout_ms: Math.max(1, Math.floor(Number(details.deadline - clock()) / 1e6)) };
  const output = [[], []], counts = [0, 0];
  function receive(index, chunk) {
    const bytes = Buffer.from(chunk);counts[index] += bytes.length;
    if (counts[index] > MAX_OUTPUT) fail('verification_command_output_limit');
    output[index].push(bytes);
  }
  const observed = await session.run(command, { onStdout: chunk => receive(0, chunk), onStderr: chunk => receive(1, chunk) });
  guard();
  const effective = observed.command;
  if (!effective) fail('verification_darwin_command_observation_missing');
  wire.validateCommand(observed.result, session.binding, session.capability, effective, commands.length + 1);
  const stdout = Buffer.concat(output[0], counts[0]), stderr = Buffer.concat(output[1], counts[1]);
  if (observed.stdout_bytes !== stdout.length || observed.stderr_bytes !== stderr.length ||
      observed.stdout_sha256 !== wire.sha(stdout) || observed.stderr_sha256 !== wire.sha(stderr) ||
      observed.helper.exit_observed !== true || observed.helper.exit_code !== 0 || observed.helper.signal !== null) {
    fail('verification_darwin_output_observation_invalid');
  }
  commands.push(effective);commandRecords.push(observed.result);
  streams.push({ stdout_bytes: stdout.length, stderr_bytes: stderr.length,
    stdout_sha256: wire.sha(stdout), stderr_sha256: wire.sha(stderr), helper: observed.helper });
  return { status: observed.status, signal: observed.signal === null ? null : 'SIG' + observed.signal, stdout, stderr };
}
async function prepare(message) {
  payload = message;
  if (typeof message.deadline_ns !== 'string' || !/^\d{1,32}$/.test(message.deadline_ns)) fail('verification_clock_invalid');
  workDeadline = BigInt(message.deadline_ns);guard();
  session = await sessions.attachSession({ ...message.session, signal: abort.signal });guard();
  const registration = await session.registerAuthority();guard();
  await send({ type: 'registered', registration });
  plan = message.plan;
  await isolated.verifyProjectPlan(plan, { checkpoint: guard });guard();
  await send({ type: 'prepared' });
}
async function run() {
  guard();
  const result = await core(payload.request, { nativeBackend: 'darwin_private_ruid', deadline: workDeadline,
    batchId: payload.batch_id, publicKey: payload.public_key, requestSha256: payload.request_sha256,
    phase, sourceSnapshot, runCommand,
    committed: item => send({ type: 'committed', execution_id: item.record.execution_id,
      execution_sha256: item.record.content_sha256, ordinal: item.record.batch_ordinal, status: item.record.status }) });
  guard();await isolated.verifyProjectPlan(plan, { checkpoint: guard });guard();
  await send({ type: 'work_complete', result });
  const drain = await session.drain();
  const readback = await session.readback(plan, 'commands_drained');
  await send({ type: 'complete', result, commands, command_results: commandRecords, streams, drain, readback });
}
function stop() {
  stopped = true;abort.abort();
  for (const resolve of acknowledgements.values()) resolve();
  acknowledgements.clear();
  session?.stop('authority_control_lost').catch(() => {});
}
if (require.main === module) {
  process.on('disconnect', stop);process.on('SIGTERM', stop);process.on('SIGINT', stop);
  process.on('message', async raw => {
    let message;
    try { message = copyInertData(raw, null, MAX_MESSAGE); } catch { stop();return; }
    if (message?.protocol !== PROTOCOL || stopped) return;
    if (message.type === 'ack') {
      const resolve = acknowledgements.get(message.id);acknowledgements.delete(message.id);resolve?.();return;
    }
    try {
      if (message.type === 'prepare' && !used) { used = true;await prepare(message); }
      else if (message.type === 'run' && used && plan && !run.started) { run.started = true;await run(); }
      else fail('verification_darwin_authority_protocol');
    } catch (error) {
      await send({ type: 'error', code: /^[a-zA-Z0-9_]{1,100}$/.test(error.code || '') ? error.code : 'verification_darwin_authority_failed' }).catch(() => {});
      stop();
    }
    // Remain present for the exact native authority terminal sweep.
  });
}
module.exports = { PROTOCOL };
