'use strict';

// This file is the only pre-admission Node entry. It does not read project
// state or load Flow/evaluation until its native owner grants a start message.
let admitted = false, busy = false, sequence = 0, activeKind;
const send = value => { if (process.connected) process.send(value, error => { if (error) process.exit(1); }); };
const serialize = (error, fallback = 'command_worker_error') => {
  const result = { code: error.code || fallback, message: error.message };
  for (const key of ['cleanup', 'run_id', 'retry_of', 'team_release', 'lock_release_error', 'lock_event_error', 'finalization_error', 'record_write_status', 'record_kind', 'timed_out', 'stage', 'verification_budget', 'completed_executions',
    'teardown', 'authority_teardown', 'attempt_id', 'recovery_required', 'result_visibility', 'terminal_commit', 'containment', 'execution', 'invocation', 'cleanup_deadline_ns', 'invocation_recovery', 'recovery_teardown', 'command_failure']) {
    if (error[key] !== undefined) result[key] = error[key];
  }
  return result;
};
process.on('disconnect', () => process.exit(1));
process.stdout.on('error', () => process.exit(1));
process.stderr.on('error', () => process.exit(1));
let sessionPolicy, helper, workStarted, observerLineage, proofRelay;
function progress(phase, detail) { send({ type: 'progress', sequence: ++sequence, phase, detail }); }
process.on('message', async message => {
  let admittedRequest = false;
  try {
    if (!admitted) {
      if (message?.type !== 'start' || !['operation', 'command', 'session'].includes(message.kind)) throw Object.assign(new Error('Invalid start'), { code: 'command_protocol_invalid' });
      admitted = true; activeKind = message.kind;
      const runner = require('./command-runner');
      sessionPolicy = runner.budgets(message.budgets); helper = message.helper; workStarted = runner.mono();
      observerLineage = message.observerLineage; proofRelay = message.proofRelay;
      if (proofRelay) require('./command-scope-proof').setScopeProofRelay(proofRelay);
      if (message.kind === 'command') {
        const setupEnd = runner.mono() + sessionPolicy.setupMs;
        const command = require('./command-authority-entry').snapshotCommand(message.payload, () => {
          if (runner.mono() >= setupEnd) throw Object.assign(new Error('Command admission expired'), { code: 'command_setup_timeout' });
        });
        const path = require('path');
        const entry = require('./command-authority-entry').validateCommandAuthority(command);
        const child = require('child_process').spawn(command.executable, entry ? [path.join(__dirname, 'command-cli-worker.js')] : command.args, {
          cwd: command.cwd, env: runner.safeEnvironment(command.env), stdio: entry ? ['ignore', 1, 2, 'ipc'] : ['ignore', 1, 2], windowsHide: true
        });
        let sent = false;
        const report = value => { if (sent) return; sent = true; send({ type: 'result', value }); };
        child.once('error', error => report({ status: null, signal: null, error: serialize(error) }));
        // exit precedes stream closure when a detached descendant retains a
        // pipe. The outer native scope drains those descendants before EOF.
        child.once('exit', (status, signal) => report({ status, signal, error: null }));
        if (entry) {
          child.on('message', value => { if (value?.type === 'cli_progress') progress('nested_operation_progress', value.phase); });
          child.send({ type: 'cli_start', entry, argv: command.args.slice(1), budgets: sessionPolicy, helper, observerLineage, proofRelay },
            error => { if (error) { child.kill('SIGKILL'); report({ status: null, signal: null, error: serialize(error) }); } });
        }
        return;
      }
      if (message.kind === 'session') return;
      const { operation, payload } = message.payload;
      const options = { budgets: sessionPolicy, preparedHelper: helper, onProgress: progress, observerLineage, proofRelay };
      let value;
      if (operation === 'flow-main') value = await require('../flow').__owned.main(payload.argv, options);
      else if (operation === 'flow-run') value = await require('../flow').__owned.runFlow(payload.options, options);
      else if (operation === 'flow-step') value = await require('../flow').__owned.runOne(payload.command, payload.context, options);
      else if (operation === 'evaluation-main') value = await require('../evaluation-harness').__owned.main(options);
      else if (operation === 'evaluation-check') value = await require('../evaluation-harness').__owned.runCheck(payload.spec, options);
      else if (operation === 'watch-main') value = await require('./watch-maintenance-worker')(payload, options);
      else if (operation === 'verification-run') {
        const invocation = require('./verification-invocation').admitWorkerInvocation(message.invocation, helper);
        if (process.platform === 'linux') require('./verification-linux-namespace').setInvocationHelper(helper);
        const path = require('path');
        const observer = require('child_process').spawn(process.execPath, [path.join(__dirname, 'verification-cancel-observer.js')], {
          env: runner.safeEnvironment(), stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true
        });
        await new Promise((resolve, reject) => {
          const fail = () => reject(Object.assign(new Error('Cancellation observer did not become ready'), { code: 'verification_cancel_observer_failed' }));
          observer.once('error', fail); observer.once('exit', fail);
          observer.once('message', result => result?.type === 'observer_ready' ? resolve() : fail());
          observer.send({ type: 'observe', channel: message.cancellationChannel, invocation,
            deadline_ns: String(BigInt(payload.started_ns) + BigInt(payload.timeout_ms) * 1000000n),
            context: { stateRoot: payload.request.stateRoot, projectKnowledgeRoot: payload.request.stateRoot,
              targetRoot: payload.request.repoRoot, systemRoot: path.resolve(__dirname, '../..') } }, error => { if (error) fail(); });
        });
        const entries = require('./verification-supervisor').__owned.runSupervised(payload.request, payload.timeout_ms,
          BigInt(payload.started_ns), { preparedHelper: helper, lifecycleChannel: message.lifecycleChannel, invocation });
        value = { entries, acceptances: entries.verification_acceptances, budget: entries.verification_budget };
      }
      else if (operation === 'verification-recover') {
        if (process.platform === 'linux') require('./verification-linux-namespace').setInvocationHelper(helper);
        value = require('./verification-recovery').recoverOwnedInvocation(payload.context, payload.input);
      }
      else throw Object.assign(new Error('Unsupported operation'), { code: 'command_operation_invalid' });
      send({ type: 'result', value });
      return;
    }
    if (activeKind !== 'session' || message?.type !== 'execute' || busy || !Number.isSafeInteger(message.id)) throw Object.assign(new Error('Invalid command request'), { code: 'command_protocol_invalid' });
    busy = true; admittedRequest = true;
    const runner = require('./command-runner');
    const remaining = Math.floor(Math.min(message.remainingMs, sessionPolicy.workMs - (runner.mono() - workStarted)));
    if (!Number.isSafeInteger(remaining) || remaining < 1) throw Object.assign(new Error('Work deadline expired'), { code: 'command_work_timeout' });
    progress('command_admitted', message.id);
    const value = await runner.runOwnedCommand(message.command, { preparedHelper: helper, observerLineage, proofRelay,
      budgets: { ...sessionPolicy, workMs: remaining, progressMs: 0 } });
    busy = false;
    progress('command_completed', message.id);
    send({ type: 'reply', id: message.id, value });
  } catch (error) {
    if (message?.type === 'execute') { if (admittedRequest) busy = false; send({ type: 'reply', id: message.id, error: serialize(error) }); }
    else send({ type: 'result', error: serialize(error, ['flow-main', 'flow-run', 'flow-step'].includes(message?.payload?.operation) ? 'flow_unexpected_error' : 'command_worker_error') });
  }
});
send({ type: 'host_ready' });
