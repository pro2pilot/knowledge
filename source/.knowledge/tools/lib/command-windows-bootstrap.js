'use strict';
// Non-detached launcher: its own loader is covered by the parent's libuv Job.
// Native JOB_LIST creation covers the holder before any holder loader/I/O.
const path = require('path');
const protocol = require('./command-windows-protocol');
let native, bootstrap, initialization, channel, timer, stopping = false, handed = false, exiting = false;
const equal = (a, b) => protocol.canonical(a) === protocol.canonical(b);
const identity = value => ({ pid: value?.pid, birth_filetime: value?.birth_filetime });
function send(value, callback = () => {}) {
  if (process.connected) process.send(value, callback); else callback(new Error('parent_disconnected'));
}
function stop() {
  stopping = true;
  if (bootstrap) try { native.bootstrapStop(bootstrap.id); } catch {}
  if (channel?.connected) channel.send({ type: 'stop' });
}
function finish(code) { if (exiting) return; exiting = true; clearInterval(timer); channel?.close(); process.exit(code); }
function failed(error) {
  stop(); send({ type: 'holder_error', role: initialization?.role,
    code: /^[A-Za-z0-9_]{1,96}$/.test(error?.code || '') ? error.code : 'command_windows_bootstrap_failed',
    native_error: Number.isSafeInteger(error?.native_error) ? error.native_error : null });
  if (!bootstrap) finish(1);
}
function advance() {
  if (!bootstrap || exiting) return;
  try {
    const observation = native.bootstrapPoll(bootstrap.id);
    if (!observation.holder_exited || !observation.watcher_exited || !observation.kernel_query_ok || observation.active_processes !== 0) return;
    // An actual process exit may precede the final TCP chunk/EOF.
    if (channel.everConnected && !channel.disconnected) return;
    if (!native.bootstrapClose(bootstrap.id)) return;
    const body = { type: 'bootstrap_exited', role: initialization.role, holder: bootstrap.holder,
      observation, handed_over: handed, holder_transport_complete: channel.complete };
    bootstrap = null;
    send(body, () => finish(0));
  } catch (error) { failed(error); }
}
for (const name of ['disconnect', 'SIGINT', 'SIGTERM']) process.on(name, stop);
process.stdout.on('error', stop); process.stderr.on('error', stop);
process.on('message', async message => {
  try {
    if (!initialization) {
      if (message?.type !== 'init' || !['primary', 'secondary'].includes(message.role) ||
          !['setupMs', 'lifetimeMs', 'cleanupMs'].every(key => Number.isSafeInteger(message[key]) && message[key] > 0 && message[key] <= 2147483647)) throw new Error('invalid bootstrap initialization');
      initialization = message;
      const loaded = require('./command-windows-native').loadPreparedHelper(message.helper); native = loaded.native;
      const controller = identity(native.processIdentity(process.ppid));
      if (!protocol.validIdentity(controller)) throw new Error('invalid parent birth');
      channel = await require('./command-holder-channel').createServer();
      channel.on('connected', () => {
        if (!bootstrap || stopping) { stop(); return; }
        channel.send({ ...initialization, bootstrap: { method: bootstrap.method, holder: bootstrap.holder,
          controller: bootstrap.controller, launcher: bootstrap.launcher } }, error => { if (error) stop(); });
      });
      channel.on('message', value => {
        try {
          if (value?.role !== initialization.role) throw new Error('invalid holder role');
          if (value.type === 'holder_ready') {
            if (handed || stopping || !equal(value.identity, bootstrap.holder) || !equal(value.controller, bootstrap.controller)) throw new Error('invalid native handoff');
            native.bootstrapCommit(bootstrap.id, value.identity); handed = true;
          } else if (!['bound', 'terminal', 'holder_error'].includes(value.type)) throw new Error('invalid holder message');
          send(value, error => { if (error) stop(); });
        } catch (error) { failed(error); }
      });
      channel.on('disconnect', reason => { stop(); if (reason !== 'eof') failed(Object.assign(new Error(reason), { code: 'command_windows_holder_transport_closed' })); advance(); });
      if (stopping || !process.connected) { stop(); finish(1); return; }
      bootstrap = native.bootstrapCreate(process.execPath, [path.join(__dirname, 'command-windows-holder.js'), ...channel.arguments], controller,
        message.setupMs, message.lifetimeMs, message.cleanupMs);
      send({ type: 'bootstrap_created', role: message.role, holder: bootstrap.holder, controller: bootstrap.controller,
        launcher: bootstrap.launcher, method: bootstrap.method }, error => { if (error) stop(); });
      timer = setInterval(advance, 10);
      if (stopping || !process.connected) stop(); else native.bootstrapResume(bootstrap.id);
      return;
    }
    if (message?.type === 'stop') stop();
    else if (message?.type === 'kill') { stopping = true; if (bootstrap) native.bootstrapKill(bootstrap.id); }
    else if (message?.type === 'bind' && handed && !stopping) channel.send(message, error => { if (error) stop(); });
    else throw new Error('invalid launcher message');
  } catch (error) { failed(error); }
});
