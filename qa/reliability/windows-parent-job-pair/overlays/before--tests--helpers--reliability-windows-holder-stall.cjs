'use strict';
// Test-only preload. The real fixed holder, native addon and Job run intact.
// Only the JavaScript boundary named by this private per-child test input is
// blocked. This is a modeled synchronous I/O/loop stall, not a kernel D-state.
const fs = require('fs');
const path = require('path');
const config = JSON.parse(process.env.KNOWLEDGE_QA_HOLDER_STALL || '{}');
delete process.env.KNOWLEDGE_QA_HOLDER_STALL;
let role, stalled = false;
const fds = new Map(), realOpen = fs.openSync, realClose = fs.closeSync, realFsync = fs.fsyncSync;
function selected() { return config.roles?.includes(role); }
function stall(phase) {
  if (stalled || config.phase !== phase || !selected()) return;
  stalled = true;
  fs.writeFileSync(path.join(config.marker_directory, `${role}.${phase}.json`), JSON.stringify({
    role, phase, pid: process.pid, scope: 'modeled_js_stall_actual_windows_native_threads'
  }) + '\n', { flag: 'wx' });
  const cell = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    Atomics.wait(cell, 0, 0, 25);
    if (config.release_file && fs.existsSync(config.release_file)) return;
  }
}
process.on('message', message => { if (message?.type === 'init') role = message.role; });
fs.openSync = function(file, ...args) {
  const fd = realOpen.call(fs, file, ...args);
  if (typeof file === 'string') fds.set(fd, file);
  return fd;
};
fs.closeSync = function(fd, ...args) { fds.delete(fd); return realClose.call(fs, fd, ...args); };
fs.fsyncSync = function(fd, ...args) {
  const file = fds.get(fd);
  if (file && path.basename(path.dirname(file)).startsWith('knowledge-command-receipt-') &&
      new RegExp(`^\\.${role}-[a-f0-9]{32}\\.tmp$`).test(path.basename(file))) stall('receipt_fsync');
  return realFsync.call(fs, fd, ...args);
};
if (typeof process.send === 'function') {
  const realSend = process.send.bind(process);
  process.send = function(message, callback) {
    if (message?.type !== 'bound' || !selected() || config.phase !== 'bound') return realSend(message, callback);
    return realSend(message, error => {
      if (callback) callback(error);
      if (!error) stall('bound');
    });
  };
}
