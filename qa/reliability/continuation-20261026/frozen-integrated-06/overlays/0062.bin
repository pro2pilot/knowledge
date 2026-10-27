#!/usr/bin/env node
'use strict';

// This control process never reads or writes project storage. Its native-owned
// worker owns fs.watch, status publication and every sync descendant.
const crypto = require('crypto');
const runner = require('./lib/command-runner');
const channels = require('./lib/command-holder-channel');
const { parseCliArgs } = require('./lib/path-context');
const fail = (code, message, details = {}) => Object.assign(new Error(message || code), { code, ...details });
const clock = () => process.hrtime.bigint();
const milliseconds = value => BigInt(value) * 1000000n;
const MAX_TIMER = 2147483647;

function watchPolicy(flags, options = {}) {
  const command = runner.budgets(options.budgets || runner.cliBudgets(flags));
  // A permit may spend one setup allowance publishing its pre-start state.
  // The subsequently admitted native command keeps its OWN original setup,
  // work and cleanup budgets; neither allowance is silently borrowed.
  const commandAllowance = command.setupMs * 2 + command.workMs + command.cleanupMs;
  const input = options.epochMs ?? flags.watchEpochMs ?? process.env.KNOWLEDGE_WATCH_EPOCH_MS;
  if (input !== undefined && typeof input !== 'number' && (typeof input !== 'string' || !/^\d+$/.test(input))) throw fail('watcher_epoch_budget_invalid');
  // Native authority remains finite even for a long-running daemon. Renew it
  // only after confirmed drain, and rescan across the subscription gap.
  const epochMs = input === undefined ? Math.max(86400000, commandAllowance * 2 + 1000) : Number(input);
  if (!Number.isSafeInteger(epochMs) || epochMs <= commandAllowance + 1000 ||
      epochMs + command.setupMs + command.cleanupMs > MAX_TIMER) throw fail('watcher_epoch_budget_invalid');
  return { command, commandAllowance, epochMs };
}

async function main(argv = process.argv.slice(2), options = {}) {
  const parsed = parseCliArgs(argv);
  if (parsed.flags.help) return { status: 'help' };
  const policy = watchPolicy(parsed.flags, options);
  let stopRequested = false, stopReason = null, activeStop, epochs = 0;
  const stop = reason => { stopRequested = true;stopReason ||= reason;activeStop?.('cancelled'); };
  const onSignal = () => stop('cancelled');
  const onMessage = message => { if (message?.type === 'knowledge:watch-stop') stop('cancelled'); };
  const onDisconnect = () => stop('parent_disconnected');
  process.on('SIGINT', onSignal);process.on('SIGTERM', onSignal);
  process.on('message', onMessage);process.on('disconnect', onDisconnect);
  options.signal?.addEventListener('abort', onSignal);
  if (options.signal?.aborted) stop('cancelled');
  try {
    while (!stopRequested) {
      const control = await channels.createServer();
      const abort = new AbortController();
      const epoch = crypto.randomBytes(8).toString('hex'), started = clock();
      const workEnd = started + milliseconds(policy.command.setupMs + policy.epochMs);
      const rolloverAt = workEnd - milliseconds(policy.commandAllowance + 1000);
      let ready = false, closing = false, ended = false, requested = null, lastPermit = 0, cleanupSignal;
      let rolloverTimer, forceTimer, channelFailure;
      const send = value => control.send(value, error => {
        if (error && !ended) { channelFailure ||= fail('watcher_control_closed', error.message);abort.abort(); }
      });
      const requestStop = mode => {
        if (ended || requested === 'cancelled' || requested === mode) return;
        requested = mode;closing = true;clearTimeout(rolloverTimer);
        if (mode === 'cancelled') {
          if (!ready || !cleanupSignal) { abort.abort();return; }
          // The graceful stop and forced native teardown consume ONE cleanup
          // allowance. No project write or child cooperation is required here.
          cleanupSignal({ type: 'cleanup_epoch', reason: 'cancelled', at_ns: String(clock()) });
          const reserve = Math.min(5000, Math.max(1, Math.floor(policy.command.cleanupMs / 3)));
          forceTimer = setTimeout(() => abort.abort(), Math.max(1, policy.command.cleanupMs - reserve));
        }
        if (control.connected) send({ type: 'stop', mode });
        else if (mode === 'cancelled') abort.abort();
      };
      activeStop = requestStop;
      control.on('connected', () => { if (requested) send({ type: 'stop', mode: requested }); });
      control.on('disconnect', () => {
        if (!ended && !closing) { channelFailure ||= fail('watcher_control_closed');abort.abort(); }
      });
      control.on('message', message => {
        if (message?.type === 'ready' && !ready && message.controller_pid === process.pid && typeof message.watcher_id === 'string') {
          ready = true;
          if (stopRequested) requestStop('cancelled');
          else if (clock() >= rolloverAt) requestStop('rollover');
          else rolloverTimer = setTimeout(() => requestStop('rollover'), Math.max(1, Number(rolloverAt - clock()) / 1000000));
          try { options.onReady?.({ epoch, watcher_id: message.watcher_id }); }
          catch (error) { channelFailure ||= fail('watcher_ready_callback_failed', error.message);abort.abort(); }
          return;
        }
        if (message?.type === 'sync_request' && Number.isSafeInteger(message.id) && message.id === lastPermit + 1) {
          lastPermit = message.id;
          if (!ready || closing || stopRequested || clock() >= rolloverAt) {
            // Close admission before denying the in-flight permit, so the
            // worker cannot treat an ordinary rollover as a command failure.
            if (!closing && !stopRequested) requestStop('rollover');
            send({ type: 'denied', id: message.id });
          } else send({ type: 'permit', id: message.id, deadline_ns: String(clock() + milliseconds(policy.command.setupMs)) });
          return;
        }
        if (message?.type === 'finished' && ['stopped', 'rolled_over', 'failed'].includes(message.status)) { closing = true;return; }
        channelFailure ||= fail('watcher_control_invalid');abort.abort();
      });
      try {
        if (stopRequested) requestStop('cancelled');
        const result = await runner.runOwnedOperation('watch-main', {
          argv, controller_pid: process.pid, epoch_id: epoch, control: control.arguments,
          command_budgets: policy.command, resume_scan: epochs > 0
        }, { ...options, signal: abort.signal,
          budgets: { ...policy.command, workMs: policy.epochMs, progressMs: 0 },
          invocationStartedNs: String(started), absoluteWorkDeadlineNs: String(workEnd),
          absoluteCleanupDeadlineNs: String(workEnd + milliseconds(policy.command.cleanupMs)),
          subscribeLifecycle(receive) { cleanupSignal = receive;return () => { cleanupSignal = null; }; }
        });
        ended = true;
        if (channelFailure) throw channelFailure;
        if (result.cleanup?.status !== 'completed' || result.value?.durable_stop_confirmed !== true ||
            !['stopped', 'rolled_over'].includes(result.value?.status)) {
          throw fail(result.value?.error?.code || 'watcher_stop_unconfirmed',
            result.value?.error?.message || 'Watcher durable stop was not confirmed',
            { cleanup: result.cleanup, watcher: result.value });
        }
        epochs++;
        if (stopRequested) return { ...result.value, status: stopReason === 'parent_disconnected' ? 'failed' : 'stopped',
          stop_reason: stopReason, completed_epochs: epochs, cleanup: result.cleanup };
        if (result.value.status !== 'rolled_over') throw fail('watcher_unexpected_stop', undefined, { cleanup: result.cleanup });
      } catch (error) {
        ended = true;
        const failure = channelFailure || error;
        if (failure !== error && error.cleanup) failure.cleanup = error.cleanup;
        failure.completed_epochs = epochs;failure.stop_reason = stopReason;
        throw failure;
      } finally {
        ended = true;clearTimeout(rolloverTimer);clearTimeout(forceTimer);
        control.close();activeStop = null;
      }
    }
    return { status: 'stopped', completed_epochs: epochs, stop_reason: stopReason, durable_stop_confirmed: true,
      cleanup: { status: 'completed', method: 'no_scope_admitted' } };
  } finally {
    process.removeListener('SIGINT', onSignal);process.removeListener('SIGTERM', onSignal);
    process.removeListener('message', onMessage);process.removeListener('disconnect', onDisconnect);
    options.signal?.removeEventListener('abort', onSignal);
  }
}

if (require.main === module) {
  main().then(value => {
    if (value.status === 'help') console.log('Usage: node .knowledge/tools/watch-maintenance.js [--target-root PATH] [--state-root PATH] [--system-root PATH] [--project-knowledge-root PATH] [--watch-epoch-ms MS]');
    if (value.status === 'failed') process.exitCode = 1;
  }, error => {
    console.error('Watcher failed: ' + error.message);
    console.error(JSON.stringify({ code: error.code || 'watcher_failed', cleanup: error.cleanup || { status: 'unconfirmed' },
      durable_stop_confirmed: false, completed_epochs: error.completed_epochs || 0 }));
    process.exitCode = 1;
  });
}
module.exports = { main, watchPolicy };
