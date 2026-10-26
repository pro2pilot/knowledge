'use strict';
// Test-only --require instrumentation. The production native calls and their
// results remain unchanged. Only selected typed observations are recorded.
const fs = require('fs'), path = require('path'), cp = require('child_process');
const directory = process.env.KNOWLEDGE_QA_CUSTODY_TRACE;
if (!directory || !path.isAbsolute(directory)) throw new Error('Private trace directory required');
const append = fs.appendFileSync;
let role = 'controller', tracing = false;
function trace(event, details = {}) {
  if (tracing) return; tracing = true;
  try { append(path.join(directory, `${role}-${process.pid}.ndjson`), JSON.stringify({ event, role, pid: process.pid, ...details }) + '\n'); }
  finally { tracing = false; }
}
process.on('message', message => {
  if (message?.type === 'init') { role = message.role; trace('init', { durable: message.durable, has_outer_scope: !!message.outerScope }); }
  else if (message?.type === 'bind') trace('bind_received');
  else if (message?.type === 'stop') trace('stop_message');
});
process.on('disconnect', () => trace('ipc_disconnect'));
process.on('exit', code => trace('javascript_exit', { code }));
process.on('uncaughtExceptionMonitor', error => trace('uncaught_exception', { code: error.code || null, type: error.name }));
const originalSend = process.send?.bind(process);
if (originalSend) process.send = function(message, ...args) {
  trace('ipc_send', { type: message?.type, code: message?.code, native_error: message?.native_error,
    scope_bound: typeof message?.scope_sha256 === 'string', has_receipt: !!message?.receipt });
  return originalSend(message, ...args);
};
const spawn = cp.spawn;
cp.spawn = function(command, args, options) {
  if (args?.some(value => typeof value === 'string' && /command-windows-(?:holder|guard)\.js$/.test(value))) {
    args = ['--require', __filename, ...args];
  }
  return spawn.call(cp, command, args, options);
};
const loader = require('../../tools/lib/command-windows-native'), load = loader.loadPreparedHelper;
loader.loadPreparedHelper = function(...args) {
  const result = load(...args), original = result.native, observed = {};
  for (const key of Object.getOwnPropertyNames(original)) observed[key] = original[key];
  let previous;
  for (const key of ['create', 'open', 'attachPeer', 'stop', 'poll', 'markDurable', 'close']) {
    observed[key] = function(...params) {
      try {
        const value = original[key](...params);
        const facts = key === 'poll' ? Object.fromEntries(['stop_latched', 'drained', 'root_exited', 'parent_exited', 'peer_exited',
          'kernel_query_ok', 'active_processes', 'native_error', 'receipt_durable'].map(name => [name, value[name]])) : { returned: typeof value === 'boolean' ? value : 'object' };
        const serial = JSON.stringify(facts);
        if (key !== 'poll' || serial !== previous) { trace('native_' + key, facts); if (key === 'poll') previous = serial; }
        return value;
      } catch (error) { trace('native_' + key + '_error', { code: error.code, native_error: error.native_error }); throw error; }
    };
  }
  trace('native_loaded', { source_sha256: result.binding.source_sha256, binary_sha256: result.binding.binary_sha256 });
  return { ...result, native: observed };
};
const tracked = new Map(), open = fs.openSync, close = fs.closeSync;
fs.openSync = function(file, ...args) {
  const receipt = typeof file === 'string' && path.basename(path.dirname(file)).startsWith('knowledge-command-receipt-');
  try {
    const fd = open.call(fs, file, ...args); if (receipt) { tracked.set(fd, true); trace('receipt_open', { basename: path.basename(file) }); } return fd;
  } catch (error) { if (receipt) trace('receipt_open_error', { code: error.code }); throw error; }
};
fs.closeSync = function(fd, ...args) { tracked.delete(fd); return close.call(fs, fd, ...args); };
for (const key of ['writeFileSync', 'fsyncSync']) {
  const original = fs[key];
  fs[key] = function(fd, ...args) {
    const receipt = tracked.has(fd); if (receipt) trace('receipt_' + key + '_begin');
    try { const value = original.call(fs, fd, ...args); if (receipt) trace('receipt_' + key + '_end'); return value; }
    catch (error) { if (receipt) trace('receipt_' + key + '_error', { code: error.code }); throw error; }
  };
}
for (const key of ['linkSync', 'unlinkSync']) {
  const original = fs[key];
  fs[key] = function(file, ...args) {
    const receipt = typeof file === 'string' && path.basename(path.dirname(file)).startsWith('knowledge-command-receipt-');
    try { const value = original.call(fs, file, ...args); if (receipt) trace('receipt_' + key); return value; }
    catch (error) { if (receipt) trace('receipt_' + key + '_error', { code: error.code }); throw error; }
  };
}
