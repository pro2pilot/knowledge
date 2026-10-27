'use strict';

// Fixed, project-free authority process. Native threads read stdin and exact
// process handles independently of this JavaScript loop and of receipt I/O.
// stdin is exclusively the native cancellation pipe; Node never consumes it.
const protocol = require('./command-windows-protocol');
const channel = require('./command-holder-channel').createClient(process.argv.slice(2));
let native, nativeId, keys, role, initialization, local, scope, receipt, timer, stopRequested = false, terminalSent = false;
let nativeClosed = false, terminalFlushed = false, exiting = false, initReceived = false;
const now = () => Number(process.hrtime.bigint()) / 1e6;
let cleanupStarted, cleanupMs;
const errorCode = error => typeof error?.code === 'string' && /^[a-zA-Z0-9_]{1,96}$/.test(error.code) ? error.code : 'command_windows_holder_failed';
function send(value) { if (channel.connected) channel.send(value, error => { if (error) stop(); }); }
function exit(code) { if (exiting) return; exiting = true; clearInterval(timer); process.exit(code); }
function identity(value) {
  if (value?.exited === true) throw Object.assign(new Error('Exact process exited'), { code: 'command_windows_identity_exited' });
  const result = { pid: value?.pid, birth_filetime: value?.birth_filetime };
  if (!protocol.validIdentity(result)) throw Object.assign(new Error('Invalid exact birth'), { code: 'command_windows_identity_invalid' });
  return result;
}
function stop() {
  stopRequested = true; cleanupStarted ??= now();
  if (nativeId) try { native.stop(nativeId); } catch {}
}
channel.on('disconnect', stop);
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
process.stdout.on('error', stop);
process.stderr.on('error', stop);
function equal(a, b) { return protocol.canonical(a) === protocol.canonical(b); }
function acceptScope(value) {
  if (scope || !nativeId || !protocol.validateScope(value)) throw Object.assign(new Error('Invalid scope binding'), { code: 'command_windows_binding_invalid' });
  const d = value.descriptor;
  if (d.scope_id !== initialization.scope_id || d.job_name !== initialization.job_name || !equal(d.root, initialization.root) ||
      !equal(d.native, local.native) || !equal(d.host, local.host) ||
      !equal(d[role].identity, local.identity) || d[role].public_key !== keys.publicKey ||
      role === 'primary' && (!equal(d.controller, local.controller) || (d.secondary !== null) !== initialization.durable) ||
      role === 'secondary' && (!equal(d.secondary.controller, local.controller) || !equal(d.primary.identity, initialization.primary) ||
        !equal(d.receipt_store, local.receipt_store))) throw Object.assign(new Error('Scope binding mismatch'), { code: 'command_windows_binding_invalid' });
  if (role === 'primary' && d.secondary) native.attachPeer(nativeId, d.secondary.identity);
  const observation = native.poll(nativeId);
  if (stopRequested || observation.stop_latched || observation.root_exited || observation.parent_exited || observation.peer_exited ||
      !observation.kernel_query_ok || observation.active_processes < 1) throw Object.assign(new Error('Admission has closed'), { code: 'command_windows_admission_closed' });
  scope = protocol.commandScope(d);
  send({ type: 'bound', role, scope_sha256: protocol.digest(scope), identity: local.identity });
}
function advance() {
  if (!nativeId || exiting) return;
  try {
    let observation = native.poll(nativeId);
    if (!observation.stop_latched) return;
    stopRequested = true; cleanupStarted ??= now();
    if (!observation.drained || !observation.kernel_query_ok || observation.active_processes !== 0 || !observation.root_exited) return;
    if (scope?.descriptor.secondary && !receipt) {
      // publishTerminal flushes and reads back its signed bytes. While any
      // call blocks, the other holder and both native watchdogs stay active.
      receipt = require('./command-windows-receipts').publishTerminal(scope, role, observation, keys.privateKey);
      native.markDurable(nativeId);
    }
    if (!terminalSent) {
      terminalSent = true;
      const message = { type: 'terminal', role, scope_sha256: scope ? protocol.digest(scope) : null,
        observation, receipt: receipt || null, elapsed_cleanup_ms: Math.max(0, now() - cleanupStarted),
        cleanup_budget_exceeded: now() - cleanupStarted >= cleanupMs };
      if (channel.connected) channel.send(message, error => {
        terminalFlushed = !error;
        if (nativeClosed) exit(error ? 1 : 0);
        else if (error) stop();
      });
      else terminalFlushed = true;
    }
    if (!scope && initialization.durable) {
      // No immutable scope was acknowledged, so no Team lock or project work
      // could have been admitted. Do not fabricate a durable scope receipt.
      exit(1); return;
    }
    // Each holder normally closes independently after its own durable proof.
    // A stalled peer has its own native cleanup deadline; truncating a peer's
    // otherwise healthy receipt write here would create avoidable debris.
    if (native.close(nativeId)) { nativeId = undefined; nativeClosed = true; if (terminalFlushed) exit(0); }
  } catch (error) {
    stop(); send({ type: 'holder_error', role, code: errorCode(error), scope_sha256: scope ? protocol.digest(scope) : null,
      native_error: Number.isSafeInteger(error.native_error) ? error.native_error : null });
    // A persistence error never closes the last handle as a reported success.
    // The peer may publish and retire this exact holder. If it cannot, the
    // controller receives unconfirmed cleanup and retains the common lock.
    if (cleanupStarted !== undefined && now() - cleanupStarted >= cleanupMs) exit(1);
  }
}
channel.on('message', message => {
  try {
    if (!initReceived) {
      initReceived = true;
      if (message?.type !== 'init' || !['primary', 'secondary'].includes(message.role) ||
          !protocol.HEX.test(message.scope_id || '') || message.job_name !== `Local\\KnowledgeCommand-${message.scope_id}` ||
          !protocol.validIdentity(message.root) || !Number.isSafeInteger(message.lifetimeMs) || message.lifetimeMs < 1 || message.lifetimeMs > 2147483647 ||
          !Number.isSafeInteger(message.cleanupMs) || message.cleanupMs < 1 || message.cleanupMs > 2147483647 ||
          message.role === 'secondary' && !protocol.validIdentity(message.primary)) throw Object.assign(new Error('Invalid initialization'), { code: 'command_windows_holder_request_invalid' });
      initialization = message; role = message.role; cleanupMs = message.cleanupMs;
      const loaded = require('./command-windows-native').loadPreparedHelper(message.helper); native = loaded.native;
      const own = identity(native.currentIdentity()), launcher = identity(native.processIdentity(process.ppid));
      if (message.bootstrap?.method !== 'job-list-at-birth.v1' || !equal(message.bootstrap.holder, own) ||
          !equal(message.bootstrap.launcher, launcher) || !protocol.validIdentity(message.bootstrap.controller) ||
          !equal(identity(native.processIdentity(message.bootstrap.controller.pid)), message.bootstrap.controller)) throw Object.assign(new Error('Bootstrap birth mismatch'), { code: 'command_windows_bootstrap_binding_invalid' });
      keys = protocol.keyPair(); local = { identity: own, controller: message.bootstrap.controller,
        native: loaded.binding, host: require('./command-windows-native').hostBinding(native) };
      if (role === 'primary') {
        if (typeof message.durable !== 'boolean') throw new Error('Durable mode is required');
        const created = native.create(message.job_name, message.root, local.controller, message.lifetimeMs, message.durable, protocol.ASSIGNMENT, message.cleanupMs);
        nativeId = created.id;
        if (!equal(created.root, message.root) || !equal(created.keeper, local.identity) || !equal(created.controller, local.controller)) throw new Error('Native creation binding changed');
      } else {
        if (message.outerScope) {
          if (!protocol.validateDescriptor(message.outerScope) ||
              !native.memberOf(message.outerScope.job_name, message.outerScope.root) ||
              !native.memberOf(message.outerScope.job_name, message.root) ||
              !native.memberOf(message.outerScope.job_name, message.primary)) throw Object.assign(new Error('Custodian lineage is unconfirmed'), { code: 'command_windows_outer_membership_unconfirmed' });
        }
        local.receipt_store = require('./command-windows-receipts').createStore(message.scope_id);
        const opened = native.open(message.job_name, message.root, local.controller, message.primary, message.lifetimeMs, message.cleanupMs);
        nativeId = opened.id;
        if (!equal(opened.holder, local.identity)) throw new Error('Native custodian binding changed');
      }
      timer = setInterval(advance, 20);
      if (stopRequested || !channel.connected) { stop(); advance(); return; }
      send({ type: 'holder_ready', role, scope_id: message.scope_id, ...local, public_key: keys.publicKey });
      return;
    }
    if (message?.type === 'bind') acceptScope(message.scope);
    else if (message?.type === 'stop') stop();
    else throw Object.assign(new Error('Invalid authority request'), { code: 'command_windows_holder_request_invalid' });
  } catch (error) {
    stop(); send({ type: 'holder_error', role, code: errorCode(error), scope_sha256: scope ? protocol.digest(scope) : null,
      native_error: Number.isSafeInteger(error.native_error) ? error.native_error : null });
    if (!nativeId) exit(1);
  }
});
