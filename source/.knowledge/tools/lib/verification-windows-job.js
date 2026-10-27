'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { copyInertData } = require('./inert-data');
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const { spawn } = require('child_process');

function selectPowerShell() {
  const systemRoot = process.env.SystemRoot || process.env.WINDIR;
  if (!systemRoot || !path.isAbsolute(systemRoot)) throw Object.assign(new Error('Windows PowerShell is unavailable'), { code: 'verification_job_unavailable' });
  const legacy = { executable: path.join(systemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe'), sha256: null };
  if (process.arch !== 'arm64') return legacy;
  // The legacy .NET Framework compiler can consume the entire work budget
  // under ARM emulation. Admit only the native installed PowerShell image at
  // the fixed system Program Files location, never an executable from PATH.
  const programFiles = path.join(path.dirname(systemRoot), 'Program Files');
  if (process.env.ProgramFiles && (!path.isAbsolute(process.env.ProgramFiles) ||
      path.resolve(process.env.ProgramFiles).toLowerCase() !== programFiles.toLowerCase())) return legacy;
  const executable = path.join(programFiles, 'PowerShell', '7', 'pwsh.exe');
  try {
    const bytes = require('./stable-file').readStableFile(programFiles, executable, { maxBytes: 16 * 1024 * 1024 });
    if (bytes.length < 64 || bytes.readUInt16LE(0) !== 0x5a4d) return legacy;
    const pe = bytes.readUInt32LE(0x3c);
    if (pe < 64 || pe > bytes.length - 6 || bytes.readUInt32LE(pe) !== 0x4550 || bytes.readUInt16LE(pe + 4) !== 0xaa64) return legacy;
    return { executable, sha256: digest(bytes) };
  } catch { return legacy; }
}

function createWindowsJob(worker, onFailure, lifetimeMs) {
  const systemRoot = process.env.SystemRoot || process.env.WINDIR;
  if (!systemRoot || !path.isAbsolute(systemRoot) || !worker.pid || worker.exitCode !== null || worker.signalCode !== null) {
    throw Object.assign(new Error('Windows verification job setup is unavailable'), { code: 'verification_job_unavailable' });
  }
  // Never reuse this name. An existing object is rejected by the native helper.
  const jobName = 'Local\\KnowledgeVerification-' + crypto.randomBytes(32).toString('hex');
  const helperSourceDigest = digest(fs.readFileSync(path.join(__dirname,'verification-windows-job.ps1')));
  const shell = selectPowerShell();
  const keeper = spawn(shell.executable,
    ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'verification-windows-job.ps1'), '-WorkerPid', String(worker.pid), '-LifetimeMs', String(Math.ceil(lifetimeMs)), '-ControllerPid', String(process.pid), '-JobName', jobName,
      ...(shell.sha256 ? ['-ExecutableSha256', shell.sha256] : [])],
    { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
  let ready = false, closing = false, closed = false, draining = false, drained = false, keeperExited = false, keeperCode, line = '', closeResolve, closePromise, drainPromise, drainResolve;
  let failed = false, identities, descriptor;
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
      if (message.status === 'ready' && !ready && !closing && message.job_name === jobName) {
        if (shell.sha256 && message.keeper_executable_sha256 !== shell.sha256) { fail(); return; }
        const ids = message.identities;
        if (!ids || !['worker','keeper','controller'].every(key => ids[key] && Number.isSafeInteger(ids[key].pid) && ids[key].pid>0 && typeof ids[key].os_creation_time==='string' && Number.isFinite(Date.parse(ids[key].os_creation_time))) ||
            ids.worker.pid!==worker.pid || ids.keeper.pid!==keeper.pid || ids.controller.pid!==process.pid) { fail(); return; }
        const host=message.host;
        if(!host || !['machine_guid_sha256','computer_name_sha256','user_sid_sha256'].every(k=>/^[a-f0-9]{64}$/.test(host[k]||'')) || !Number.isSafeInteger(host.session_id) || host.session_id<0) {fail();return;}
        ready = true; identities = copyInertData(ids);
        descriptor = {schema_version:'knowledge-windows-job.v1',backend:'windows_job_object',job_name:jobName,
          identities:copyInertData(ids),host:copyInertData(host),source_sha256:helperSourceDigest};
        resolveReady();
      }
      else if (message.status === 'drained' && draining && !closing && !drained && message.active_processes === 0) {
        drained = true; drainResolve?.();
      }
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
    drainResolve?.();
    closeResolve?.();
  });
  return {
    ready: readyPromise,
    keeper_pid: keeper.pid,
    keeper_executable: shell.executable,
    keeper_executable_sha256: shell.sha256,
    get identities() { return identities && copyInertData(identities); },
    get descriptor() { return descriptor && copyInertData(descriptor); },
    async drain(allowanceMs = 30000) {
      if (drainPromise) return drainPromise;
      if (closePromise) return closePromise;
      draining = true;
      const allowance = Math.max(0, Math.min(2147483647, Math.floor(Number(allowanceMs) || 0)));
      drainPromise = new Promise(resolve => {
        let done = false, timer;
        const finish = () => {
          if (done) return; done = true; clearTimeout(timer);
          resolve(!failed && ready && drained && !keeperExited
            ? { status: 'completed', method: 'windows_job_object', active_processes: 0, keeper_exited: false, worker_exited: true,
              empty_job_retained: true, descriptor_sha256: digest(JSON.stringify(descriptor)) }
            : { status: 'unconfirmed', method: 'windows_job_object', code: 'job_drain_unconfirmed', keeper_exited: keeperExited });
        };
        drainResolve = finish;
        timer = setTimeout(finish, Math.max(1, allowance));
        if (!ready || keeperExited) finish();
        else keeper.stdin.write('drain\n');
      });
      return drainPromise;
    },
    async close(allowanceMs = 30000) {
      if (closePromise) return closePromise;
      closing = true;
      closePromise = new Promise(resolve => {
        const allowance = Math.max(0, Math.min(2147483647, Number(allowanceMs) || 0));
        let done = false, killTimer, limitTimer, forced = !ready;
        const finish = () => {
          if (done) return; done = true;
          clearTimeout(killTimer); clearTimeout(limitTimer);
          keeper.stdin.destroy(); keeper.stdout.destroy(); keeper.unref();
          resolve(!failed && closed && keeperExited && keeperCode === 0
            ? { status: 'completed', method: 'windows_job_object', active_processes: 0, keeper_exited: true, worker_exited: true, descriptor_sha256: digest(JSON.stringify(descriptor)) }
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
module.exports = { createWindowsJob, selectPowerShell };
