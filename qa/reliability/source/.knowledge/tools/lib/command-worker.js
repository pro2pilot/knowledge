'use strict';

// This file is the only pre-admission Node entry. It does not read project
// state or load Flow/evaluation until its native owner grants a start message.
let admitted = false, busy = false, sequence = 0, activeKind;
const send = value => { if (process.connected) process.send(value, error => { if (error) process.exit(1); }); };
const serialize = error => ({ code: error.code || 'command_worker_error', message: error.message,
  ...(error.cleanup ? { cleanup: error.cleanup } : {}), ...(error.run_id ? { run_id: error.run_id, retry_of: error.retry_of } : {}) });
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
        const command = message.payload;
        const path = require('path');
        const target = command.executable === process.execPath && command.nestedAuthority === true ? path.resolve(command.args[0] || '') : null;
        const entry = target === path.resolve(__dirname, '../flow.js') ? 'flow' : target === path.resolve(__dirname, '../evaluation-harness.js') ? 'evaluation' : null;
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
    else send({ type: 'result', error: serialize(error) });
  }
});
send({ type: 'host_ready' });
