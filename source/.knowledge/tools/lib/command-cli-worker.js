'use strict';
// Private IPC exists only for these two fixed installed entrypoints. Normal
// payload commands never receive the proof/custody token or this channel.
const path = require('path');
let admitted = false;
process.on('disconnect', () => process.exit(1));
process.stdout.on('error', () => process.exit(1)); process.stderr.on('error', () => process.exit(1));
process.on('message', async message => {
  if (admitted || message?.type !== 'cli_start' || !['flow', 'evaluation'].includes(message.entry) ||
      !Array.isArray(message.argv) || message.argv.some(value => typeof value !== 'string' || value.includes('\0'))) { process.exit(1); return; }
  admitted = true;
  const target = path.join(__dirname, '..', message.entry === 'flow' ? 'flow.js' : 'evaluation-harness.js');
  process.argv = [process.execPath, target, ...message.argv];
  const runner = require('./command-runner');
  const options = { budgets: runner.budgets(message.budgets), preparedHelper: message.helper,
    observerLineage: message.observerLineage, proofRelay: message.proofRelay,
    onProgress: progress => { if (process.connected) process.send({ type: 'cli_progress', phase: progress?.phase || 'nested_operation_progress' }, () => {}); } };
  try {
    await require(target).__owned.cli(options);
    process.exit(process.exitCode || 0);
  } catch (error) { process.stderr.write(`${error.code || 'command_cli_failed'}\n`); process.exit(1); }
});
