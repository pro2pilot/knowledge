'use strict';
// Fixed read-only diagnostic workload. Never changes AppArmor, capabilities,
// procfs policy or ptrace state. All lifecycle calls use the installed adapter.
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const modulePath = process.argv[2];
const backend = require(modulePath);
const read = file => { try {
  const fd = fs.openSync(file, 'r');
  try { const b = Buffer.alloc(16385), n = fs.readSync(fd, b, 0, b.length, 0);
    return n > 16384 ? { error: 'bounded_read_exceeded' } : b.subarray(0, n).toString('utf8').trim();
  } finally { fs.closeSync(fd); }
} catch (e) { return { error: e.code }; } };
const procPid = () => Number(fs.readlinkSync('/proc/self'));
function snapshot() {
  const status = read('/proc/self/status');
  return { pid: process.pid, proc_pid: procPid(), uid: process.getuid(),
    apparmor: read('/proc/self/attr/current'),
    status: typeof status === 'string' ? status.split('\n').filter(x => /^(Pid|PPid|Uid|Gid|NSpid|Cap\w+|NoNewPrivs|Seccomp):/.test(x)) : status,
    restrict_userns: read('/proc/sys/kernel/apparmor_restrict_unprivileged_userns'),
    max_user_namespaces: read('/proc/sys/user/max_user_namespaces') };
}
function children(parent) {
  const value = read(`/proc/${parent}/task/${parent}/children`);
  return typeof value === 'string' ? value.split(/\s+/).filter(Boolean).map(Number) : [];
}
function ownHostChild(local, parent, prior) {
  for (const host of children(parent).filter(pid => !prior.includes(pid))) {
    const status = read(`/proc/${host}/status`);
    if (typeof status !== 'string') continue;
    const map = Object.fromEntries(status.split('\n').filter(x => x.includes(':')).map(x => [x.split(':')[0], x.slice(x.indexOf(':')+1).trim()]));
    if (Number(map.PPid) === parent && Number(map.NSpid?.split(/\s+/).at(-1)) === local &&
        map.Uid?.split(/\s+/).every(uid => Number(uid) === process.getuid())) return { proc_pid: host, local_pid: local, ppid: parent, status: 'bound_before_event_loop_reap' };
  }
  return { local_pid: local, status: 'unavailable_no_inference' };
}
function bounded(promise, ms) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('diagnostic_deadline')), ms); })]).finally(() => clearTimeout(timer));
}
async function inner() {
  const report = { authority: snapshot(), native_control: '', stderr: '' };
  const prior = children(report.authority.proc_pid);
  const pair = backend.spawnLinuxContainedWorker(process.execPath, ['-e', 'setInterval(()=>{},1000)'],
    { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] }, { lifetimeMs: 12000, onFailure: () => {} });
  report.inner_helper = ownHostChild(pair.worker.pid, report.authority.proc_pid, prior);
  pair.worker.stdio[4].on('data', b => { if (report.native_control.length < 65536) report.native_control += String(b).slice(0, 65536-report.native_control.length); });
  pair.worker.stderr.on('data', b => { if (report.stderr.length < 8192) report.stderr += String(b).slice(0, 8192-report.stderr.length); });
  try { report.descriptor = await bounded(pair.job.ready, 8000); pair.job.permit(); await bounded(pair.job.started, 3000); report.inner_started = true; }
  catch (error) { report.failure = { code: error.code || error.message,
    native_errno: error.native_errno, native_observer_stage: error.native_observer_stage,
    native_setup_stage: error.native_setup_stage }; }
  finally { report.cleanup = await pair.job.close(3000); if (pair.worker.connected) pair.worker.disconnect(); }
  process.send(report);
  setInterval(() => {}, 1000);
}
async function main() {
  if (process.platform !== 'linux' || process.arch !== 'arm64' || process.getuid() === 0) throw new Error('ordinary_native_ARM64_required');
  const began = new Date().toISOString(), report = { schema_version: 'knowledge-linux-installed-nested-diagnostic.v1',
    controller: snapshot(), began_utc: began, policy_changed: false, ptrace_used: false,
    release_qualification: false, native_control: '', stderr: '' };
  const prepared = backend.preparePackagedHelper({ snapshot: true });
  report.helper = { source_sha256: prepared.source_sha256, binary_sha256: prepared.binary_sha256 };
  const pair = backend.spawnLinuxContainedWorker(process.execPath, [__filename, modulePath, '--inner'],
    { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] }, { preparedHelper: prepared, lifetimeMs: 20000, trustedAuthority: true, onFailure: () => {} });
  pair.worker.stdio[4].on('data', b => { if (report.native_control.length < 65536) report.native_control += String(b).slice(0, 65536-report.native_control.length); });
  pair.worker.stderr.on('data', b => { if (report.stderr.length < 8192) report.stderr += String(b).slice(0, 8192-report.stderr.length); });
  const received = new Promise((resolve, reject) => { pair.worker.once('message', resolve); pair.worker.once('error', reject); pair.worker.once('exit', () => reject(new Error('outer_exited_before_diagnostic'))); });
  received.catch(() => {});
  try { report.descriptor = await bounded(pair.job.ready, 5000); pair.job.permit(); await bounded(pair.job.started, 3000); report.inner = await bounded(received, 12000); }
  catch (error) { report.failure = { code: error.code || error.message, native_errno: error.native_errno }; }
  finally { report.cleanup = await pair.job.close(3000); if (pair.worker.connected) pair.worker.disconnect(); }
  report.artifact_cleanup = report.cleanup.status === 'completed' ? backend.cleanupPreparedHelper(prepared) : { status: 'retained_unconfirmed' };
  const owned = new Set([report.controller.proc_pid, report.inner?.authority?.proc_pid, report.inner?.inner_helper?.proc_pid]);
  for (const d of [report.descriptor, report.inner?.descriptor]) if (d) for (const role of ['controller','keeper','init','worker']) owned.add(d[role].proc_pid);
  owned.delete(undefined); report.observed_owned_proc_pids = [...owned];
  const kernel = spawnSync('sudo', ['-n', 'dmesg', '--color=never', '--since', began.slice(0,19).replace('T',' ')],
    { env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', TZ: 'UTC', LANG: 'C' }, encoding: 'utf8', timeout: 5000, maxBuffer: 1024*1024 });
  const denialLines = String(kernel.stdout || '').split('\n').filter(line => /apparmor/i.test(line) && /DENIED/.test(line));
  report.kernel_denials = { status: !kernel.error && kernel.status === 0 ? 'observed' : 'unavailable',
    exit_code: kernel.status, error: kernel.error?.code || null, stderr: String(kernel.stderr || '').slice(0,2048),
    matching_owned_lines: denialLines.filter(line => owned.has(Number(line.match(/\bpid=(\d+)/)?.[1]))).slice(-30),
    unattributed_interval_count: denialLines.filter(line => !owned.has(Number(line.match(/\bpid=(\d+)/)?.[1]))).length };
  report.controller_after = snapshot();
  report.status = report.inner && report.cleanup.status === 'completed' && report.artifact_cleanup.status === 'completed' ? 'DIAGNOSTIC_OBSERVED' : 'DIAGNOSTIC_INCOMPLETE';
  console.log(JSON.stringify(report, null, 2));
  if (report.status !== 'DIAGNOSTIC_OBSERVED') process.exitCode = 1;
}
(process.argv.includes('--inner') ? inner() : main()).catch(e => { console.error(e.stack); process.exitCode=1; });
