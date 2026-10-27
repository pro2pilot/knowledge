'use strict';
// Read-only host-policy observations and actual pre-admission native setup.
// This diagnostic changes no AppArmor profile, sysctl, capabilities or tests.
const fs = require('fs'), path = require('path');
const { spawnSync } = require('child_process');
const native = require('../../tools/lib/verification-linux-namespace');
const read = file => { try { const fd = fs.openSync(file, 'r'), bytes = Buffer.alloc(4097); let n; try { n = fs.readSync(fd, bytes, 0, bytes.length, 0); } finally { fs.closeSync(fd); } return n > 4096 ? { status: 'oversized' } : { status: 'observed', value: bytes.subarray(0, n).toString('utf8').trim() }; } catch (e) { return { status: 'unavailable', code: e.code }; } };
const stages = ['fork_or_event', 'no_new_privileges', 'securebits', 'ambient_clear', 'capset', 'dumpable', 'ambient_setfcap', 'capget', 'final_capability_readback'];
(async () => {
  if (process.platform !== 'linux') throw new Error('This diagnostic requires actual Linux');
  const helper = native.preparePackagedHelper({ snapshot: true });
  const policy = {};
  for (const file of ['/proc/sys/kernel/apparmor_restrict_unprivileged_userns', '/proc/sys/kernel/unprivileged_userns_clone',
    '/proc/sys/user/max_user_namespaces', '/sys/module/apparmor/parameters/enabled', '/proc/self/attr/current']) policy[file] = read(file);
  const probe = spawnSync(helper.executable, ['--probe'], { encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
  let raw = '', failure, descriptor, cleanup;
  const { worker, job } = native.spawnLinuxContainedWorker(process.execPath, ['-e', 'setInterval(()=>{},1000)'],
    { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }, { preparedHelper: helper, lifetimeMs: 20000, trustedAuthority: true });
  worker.stdio[4].on('data', chunk => { if (raw.length < 65536) raw += chunk; });
  try { descriptor = await job.ready; job.permit(); await job.started; }
  catch (error) { failure = { code: error.code, native_errno: error.native_errno, setup_stage: error.native_setup_stage,
    setup_operation: stages[error.native_setup_stage] || 'unknown' }; }
  finally { cleanup = await job.close(10000); if (worker.connected) worker.disconnect(); }
  const artifact = native.cleanupPreparedHelper(helper);
  const out = { schema_version: 'knowledge-linux-capability-diagnostic.v1', architecture: process.arch, node: process.version,
    policy, helper: { source_sha256: helper.source_sha256, binary_sha256: helper.binary_sha256 },
    raw_probe: { status: probe.status, signal: probe.signal, error: probe.error?.code || null, stdout: probe.stdout, stderr: probe.stderr },
    authority_setup: { status: descriptor && !failure && cleanup.status === 'completed' ? 'ready' : 'unavailable',
      failure: failure || null, raw_control: raw, keeper_exit_code: worker.exitCode, keeper_signal: worker.signalCode, cleanup },
    artifact_cleanup: artifact, policy_changed: false, release_qualification: false };
  console.log(JSON.stringify(out, null, 2));
  // Observation completion is distinct from feature availability. The
  // subsequent native acceptance suite keeps its existing FAIL assertions.
  if (artifact.status !== 'completed' || probe.error) process.exitCode = 1;
})().catch(error => { console.error(JSON.stringify({ status: 'diagnostic_failed', code: error.code || error.message })); process.exitCode = 1; });
