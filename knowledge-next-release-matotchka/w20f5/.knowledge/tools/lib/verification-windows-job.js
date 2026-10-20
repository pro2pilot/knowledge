'use strict';
const path = require('path');
const { spawn } = require('child_process');

function createWindowsJob(worker, onFailure, lifetimeMs) {
  const systemRoot = process.env.SystemRoot || process.env.WINDIR;
  if (!systemRoot || !path.isAbsolute(systemRoot) || !worker.pid || worker.exitCode !== null || worker.signalCode !== null) {
    throw Object.assign(new Error('Windows verification job setup is unavailable'), { code: 'verification_job_unavailable' });
  }
  const keeper = spawn(path.join(systemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe'),
    ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'verification-windows-job.ps1'), '-WorkerPid', String(worker.pid), '-LifetimeMs', String(Math.ceil(lifetimeMs)), '-ControllerPid', String(process.pid)],
    { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
  let ready = false, closing = false, closed = false, keeperExited = false, keeperCode, line = '', closeResolve, closePromise;
  let failed = false, identities;
  let resolveReady, rejectReady;
  const readyPromise = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const fail = () => {
    const notify = !failed && !closing;
    failed = true;
    rejectReady(Object.assign(new Error('Windows verification job could not be established'), { code: 'verification_job_setup_failed' }));
    if (notify) onFailure();
  };
  keeper.on('error', fail);
  keeper.stdin.on('error', fail);
  keeper.stdout.setEncoding('utf8');
  keeper.stdout.on('data', chunk => {
    line += chunk;
    if (line.length > 8192) { fail(); return; }
    let end;
    while ((end = line.indexOf('\n')) >= 0) {
      let message; try { message = JSON.parse(line.slice(0, end)); } catch { fail(); return; }
      line = line.slice(end + 1);
      if (message.status === 'ready' && !ready && !closing) { ready = true; identities = message.identities; resolveReady(); }
      else if (message.status === 'closed' && closing && !closed && message.active_processes === 0) {
        closed = true;
        if (keeperExited && keeperCode === 0) closeResolve?.();
      } else fail();
    }
  });
  keeper.on('close', code => {
    keeperExited = true;
    keeperCode = code;
    if (!closed || code !== 0) fail();
    closeResolve?.();
  });
  return {
    ready: readyPromise,
    keeper_pid: keeper.pid,
    get identities() { return identities; },
    async close(allowanceMs = 30000) {
      if (closePromise) return closePromise;
      closing = true;
      closePromise = new Promise(resolve => {
        const allowance = Math.max(0, Math.min(3600000, Number(allowanceMs) || 0));
        let done = false, killTimer, limitTimer, forced = !ready;
        const finish = () => {
          if (done) return; done = true;
          clearTimeout(killTimer); clearTimeout(limitTimer);
          keeper.stdin.destroy(); keeper.stdout.destroy(); keeper.unref();
          resolve(!failed && closed && keeperExited && keeperCode === 0
            ? { status: 'completed', method: 'windows_job_object', active_processes: 0, keeper_exited: true, worker_exited: true }
            : { status: 'unconfirmed', code: !ready ? 'job_setup_incomplete' : forced ? 'job_teardown_timeout' : 'job_close_unconfirmed',
              keeper_exited: keeperExited });
        };
        // Sending TerminateProcess is not an exit observation. Reserve part of
        // this allowance for the actual close event, even on setup failure.
        const kill = () => {
          forced = true;
          try { if (!keeperExited) keeper.kill('SIGKILL'); } catch {}
          if (keeperExited) finish();
        };
        closeResolve = finish;
        if (keeperExited) { finish(); return; }
        limitTimer = setTimeout(() => { kill(); finish(); }, Math.max(1, allowance));
        if (!ready) kill();
        else {
          killTimer = setTimeout(kill, Math.max(1, allowance - Math.min(250, allowance / 3)));
          keeper.stdin.end('close\n');
        }
      });
      return closePromise;
    }
  };
}
module.exports = { createWindowsJob };
