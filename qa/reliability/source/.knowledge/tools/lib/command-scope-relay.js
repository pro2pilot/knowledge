'use strict';
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { validateExecutionScope } = require('./command-scope-proof');
async function createScopeRelay() {
  const token = crypto.randomBytes(32).toString('hex');
  const children = new Set(), sockets = new Set(); let closing = false;
  let observerDescriptor, helper;
  const custody = process.platform === 'win32' ? require('./command-windows-custody').createCustodyManager(() => ({ descriptor: observerDescriptor, helper })) : null;
  const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    let input = '', invalid = false; socket.setEncoding('utf8');
    socket.setTimeout(65000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('data', chunk => { input += chunk; if (Buffer.byteLength(input) > 65536) { invalid = true; socket.destroy(); } });
    socket.on('end', () => {
      let request;
      try {
        request = JSON.parse(input);
        if (invalid || closing || request.token !== token ||
            !Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > 600000 || children.size >= 4) throw new Error('invalid');
      } catch { socket.end(JSON.stringify({ proof: { status: 'unconfirmed', code: 'command_scope_request_invalid' } })); return; }
      socket.setTimeout(request.timeoutMs + 2000, () => socket.destroy());
      if (custody && ['windows_custodian_create', 'windows_custodian_bind', 'windows_custodian_close'].includes(request.operation)) {
        custody.dispatch(request).then(value => { if (!socket.destroyed) socket.end(JSON.stringify(value)); }, error => {
          if (!socket.destroyed) socket.end(JSON.stringify({ ok: false, scope_id: request.scope_id, code: error.code || 'command_windows_custodian_unconfirmed' }));
        });
        return;
      }
      if (request.operation !== undefined || !validateExecutionScope(request.scope)) {
        socket.end(JSON.stringify({ proof: { status: 'unconfirmed', code: 'command_scope_request_invalid' } })); return;
      }
      const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.NODE_PATH;
      for (const key of Object.keys(env)) if (key.startsWith('LD_')) delete env[key];
      let executable = process.execPath, args = [path.join(__dirname, 'command-scope-proof.js')], nativeOnly = false;
      if (process.platform === 'linux') {
        const descriptor = request.scope.descriptor;
        const frame = request.scope.observer_lineage.find(row => row.namespace.dev === observerDescriptor?.observer_pid_namespace.dev && row.namespace.ino === observerDescriptor?.observer_pid_namespace.ino);
        if (!helper || !frame || frame.depth !== observerDescriptor.controller.proc_pid_chain.length ||
            descriptor.boot_id !== observerDescriptor.boot_id || descriptor.procfs_dev !== observerDescriptor.procfs_dev ||
            descriptor.helper.source_sha256 !== helper.source_sha256 || descriptor.helper.binary_sha256 !== helper.binary_sha256 || descriptor.helper.architecture !== helper.architecture) {
          socket.end(JSON.stringify({ scope_sha256: digest(request.scope), proof: { status: 'unconfirmed', code: 'command_scope_relay_context_mismatch' } })); return;
        }
        const identity = descriptor.init;
        executable = helper.executable;
        args = ['--parent', String(process.pid), '--observe', descriptor.boot_id, frame.namespace.dev, frame.namespace.ino,
          descriptor.procfs_dev, String(identity.proc_pid_chain[frame.depth - 1]), String(identity.proc_pid), identity.start_ticks,
          identity.pid_namespace.dev, identity.pid_namespace.ino, String(identity.namespace_pid), String(request.timeoutMs)];
        nativeOnly = true;
      }
      const child = spawn(executable, args, { env, stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
      children.add(child); let output = '', complete = false;
      const timer = setTimeout(() => { child.kill('SIGKILL'); socket.destroy(); }, request.timeoutMs + 1000);
      child.stdin.on('error', () => {});
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', chunk => { output += chunk; if (Buffer.byteLength(output) > 65536) { child.kill('SIGKILL'); socket.destroy(); } });
      child.on('error', () => { socket.destroy(); });
      child.on('exit', () => children.delete(child));
      child.on('close', code => {
        complete = true; clearTimeout(timer); children.delete(child);
        if (code === 0 && !closing) {
          if (nativeOnly) {
            try {
              const record = JSON.parse(output);
              const proof = record.status === 'exited' ? { status: 'completed', method: 'linux_pid_namespace', active_processes: 0,
                namespace_drained: true, init_exit_basis: record.method, descriptor_sha256: digest(request.scope.descriptor),
                process_reaped: record.process_reaped === true, release_inferred: record.release_inferred === true }
                : record.status === 'active' ? { status: 'active', method: 'linux_pid_namespace' } : { status: 'unconfirmed', code: 'command_scope_relay_native_unconfirmed' };
              socket.end(JSON.stringify({ scope_sha256: digest(request.scope), proof }));
            } catch { socket.destroy(); }
          } else socket.end(output);
        } else socket.destroy();
      });
      socket.once('close', () => { if (!complete) child.kill('SIGKILL'); });
      child.stdin.end(nativeOnly ? '' : JSON.stringify({ scope: request.scope, timeoutMs: request.timeoutMs }));
    });
  });
  // This local-only authenticated transport has no filesystem path-length or
  // slow-disk dependency. Its random token travels only over private IPC.
  server.maxConnections = 16;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = { host: '127.0.0.1', port: server.address().port };
  return {
    descriptor: { address, token },
    configure(descriptor, prepared) { observerDescriptor = JSON.parse(JSON.stringify(descriptor)); helper = prepared; },
    async close(cleanupMs = 60000) {
      closing = true;
      for (const socket of sockets) socket.destroy();
      for (const child of children) child.kill('SIGKILL');
      server.close();
      const deadline = Number(process.hrtime.bigint()) / 1e6 + cleanupMs;
      const custodyCleanup = custody ? await custody.close(Math.max(1, deadline - Number(process.hrtime.bigint()) / 1e6)) : null;
      while (children.size && Number(process.hrtime.bigint()) / 1e6 < deadline) await new Promise(resolve => setTimeout(resolve, 10));
      if (children.size) { for (const child of children) child.unref(); return { status: 'unconfirmed', code: 'command_scope_relay_exit_unconfirmed' }; }
      return { status: custodyCleanup?.status === 'unconfirmed' ? 'unconfirmed' : 'completed', ...(custodyCleanup ? { custody: custodyCleanup } : {}) };
    }
  };
}
module.exports = { createScopeRelay };
