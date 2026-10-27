'use strict';
// Read-only observations inside an actual first native authority/worker.
// This does not change procfs permissions, dumpability or any LSM policy.
const fs = require('fs');
const { spawnSync } = require('child_process');
const native = require('../../tools/lib/verification-linux-namespace');
function boundedRead(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r'); const buffer = Buffer.alloc(8193), bytes = fs.readSync(fd, buffer, 0, buffer.length, 0);
    return bytes > 8192 ? { status: 'oversized' } : { status: 'observed', value: buffer.subarray(0, bytes).toString('utf8').trim() };
  } catch (error) { return { status: 'unavailable', code: error.code }; }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function operation(name, file) {
  try {
    const value = fs[name](file, name === 'readlinkSync' ? undefined : { bigint: true });
    return { status: 'observed', value: typeof value === 'string' ? value : {
      dev: String(value.dev), ino: String(value.ino), uid: String(value.uid), gid: String(value.gid), mode: value.mode.toString(8)
    } };
  } catch (error) { return { status: 'unavailable', code: error.code }; }
}
function snapshot() {
  const status = boundedRead('/proc/self/status');
  if (status.status === 'observed') status.value = status.value.split('\n').filter(line => /^(Name|Pid|PPid|Uid|Gid|NSpid|Cap\w+|NoNewPrivs|Seccomp|CoreDumping):/.test(line));
  const paths = {};
  for (const file of ['/proc/self/ns', '/proc/self/ns/pid']) paths[file] = {
    lstat: operation('lstatSync', file), stat: operation('statSync', file), readlink: operation('readlinkSync', file)
  };
  return { pid: process.pid, uid: process.getuid(), gid: process.getgid(),
    attr: boundedRead('/proc/self/attr/current'), status, paths };
}
if (process.argv.includes('--child')) {
  process.send(snapshot()); setInterval(() => {}, 1000);
} else (async () => {
  if (process.platform !== 'linux') throw new Error('Actual Linux required');
  const began = new Date().toISOString();
  const helper = native.preparePackagedHelper({ snapshot: true }), records = [];
  for (const authority of [true, false]) {
    const record = { profile: authority ? 'authority' : 'ordinary_worker' }; records.push(record);
    const { worker, job } = native.spawnLinuxContainedWorker(process.execPath, [__filename, '--child'],
      { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] }, { preparedHelper: helper, lifetimeMs: 15000, trustedAuthority: authority });
    let raw = '', stderr = '', timer;
    worker.stdio[4].on('data', chunk => { if (raw.length < 65536) raw += String(chunk).slice(0, 65536 - raw.length); });
    worker.stderr.on('data', chunk => { if (stderr.length < 8192) stderr += String(chunk).slice(0, 8192 - stderr.length); });
    const message = new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('diagnostic_child_timeout')), 10000);
      worker.once('message', resolve); worker.once('error', reject);
      worker.once('exit', () => reject(new Error('diagnostic_child_exited_before_message')));
    }); message.catch(() => {});
    try { record.descriptor = await job.ready; job.permit(); await job.started; record.child = await message; }
    catch (error) { record.failure = { code: error.code || error.message, native_errno: error.native_errno,
      native_observer_stage: error.native_observer_stage, native_setup_stage: error.native_setup_stage }; }
    finally {
      clearTimeout(timer); record.cleanup = await job.close(10000); if (worker.connected) worker.disconnect();
      record.raw_control = raw; record.stderr = stderr;
      record.keeper = { exit_code: worker.exitCode, signal: worker.signalCode };
    }
  }
  const artifact = native.cleanupPreparedHelper(helper);
  // Dedicated CI host kernel diagnostics only. Keep only bounded AppArmor
  // denial lines from this diagnostic interval; never change the profile.
  const kernel = spawnSync('sudo', ['-n', 'dmesg', '--color=never', '--since', began.slice(0, 19).replace('T', ' ')],
    { env: { ...process.env, TZ: 'UTC' }, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024 });
  const denialLines = String(kernel.stdout || '').split('\n').filter(line => /apparmor/i.test(line) && /DENIED/.test(line));
  console.log(JSON.stringify({ schema_version: 'knowledge-linux-nested-observer-diagnostic.v1',
    controller: snapshot(), architecture: process.arch, node: process.version,
    helper: { source_sha256: helper.source_sha256, binary_sha256: helper.binary_sha256 },
    records, artifact_cleanup: artifact, kernel_denials: { since: began,
      status: !kernel.error && kernel.status === 0 ? 'observed' : 'unavailable', exit_code: kernel.status,
      error: kernel.error?.code || null, stderr: String(kernel.stderr || '').slice(0, 4096),
      lines: denialLines.slice(-100).map(line => line.slice(0, 2048)), matching_lines: denialLines.length,
      truncated: denialLines.length > 100 || kernel.error?.code === 'ENOBUFS' },
    policy_changed: false, release_qualification: false }, null, 2));
  if (artifact.status !== 'completed') process.exitCode = 1;
})().catch(error => { console.error(JSON.stringify({ diagnostic_failed: error.code || error.message })); process.exitCode = 1; });
