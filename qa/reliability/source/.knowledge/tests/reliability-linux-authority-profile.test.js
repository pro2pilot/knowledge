'use strict';
// Actual nested user/PID namespaces. The nonzero-UID case does not modify
// AppArmor or any host policy; only a root test controller drops its own
// child to a numeric unprivileged UID for the same native scenario.
const test = require('node:test'), assert = require('node:assert/strict'), path = require('path');
const { spawnSync } = require('node:child_process');
const backend = process.env.KNOWLEDGE_TEST_LINUX_BACKEND || path.resolve(__dirname, '../tools/lib/verification-linux-namespace.js');
function invocation(depth, authority) {
  return `const native=require(${JSON.stringify(backend)});const helper=native.preparePackagedHelper();
  const {worker,job}=native.spawnLinuxContainedWorker(process.execPath,['-e',${JSON.stringify(depth > 1 ? invocation(depth - 1, authority) : "process.send({profiles:[],uids:[process.getuid()]});setInterval(()=>{},1000)")}],
  {stdio:['ignore','ignore','inherit','ipc']},{preparedHelper:helper,lifetimeMs:20000,trustedAuthority:${authority}});
  let value;const message=new Promise((resolve,reject)=>{worker.once('message',v=>resolve(v));worker.once('error',reject);worker.once('exit',()=>{if(!value)reject(new Error('child exited before result'))})});message.catch(()=>{});
  (async()=>{try{const descriptor=await job.ready;job.permit();await job.started;value=await message;const cleanup=await job.close(10000);
  if(cleanup.status!=='completed')throw new Error('cleanup '+JSON.stringify(cleanup));if(worker.connected)worker.disconnect();
  const result={profiles:[descriptor.capability_profile,...value.profiles],uids:[process.getuid(),...value.uids]};
  if(process.connected){process.send(result);setInterval(()=>{},1000)}else console.log(JSON.stringify(result));}
  catch(e){console.error(JSON.stringify({stage:'nested_native_setup',depth:${depth},uid:process.getuid(),code:e.code,native_errno:e.native_errno,native_observer_stage:e.native_observer_stage,native_setup_stage:e.native_setup_stage}));console.error(e.stack);await job.close(10000);if(worker.connected)worker.disconnect();process.exit(1)}})();`;
}
function run(uid, depth, authority) {
  const options = { encoding: 'utf8', timeout: 40000, maxBuffer: 262144, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } };
  if (process.getuid() === 0 && uid !== 0) { options.uid = uid; options.gid = uid; }
  const result = spawnSync(process.execPath, ['-e', invocation(depth, authority)], options);
  assert.equal(result.error, undefined, result.error?.message); assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr); return JSON.parse(result.stdout);
}
test('nonzero UID: three real authority scopes retain no capabilities and preserve UID mapping', () => {
  assert.equal(process.platform, 'linux'); const uid = process.getuid() || 65534;
  const result = run(uid, 3, true); assert.deepEqual(result.uids, Array(4).fill(uid));
  assert.deepEqual(result.profiles, Array(3).fill('authority_none'));
});
test('current UID: the exact nested mapping determines the authority capability profile', () => {
  assert.equal(process.platform, 'linux'); const uid = process.getuid(), result = run(uid, 3, true);
  assert.deepEqual(result.uids, Array(4).fill(uid));
  assert.deepEqual(result.profiles, Array(3).fill(uid === 0 ? 'authority_setfcap' : 'authority_none'));
});
test('nonzero UID: ordinary command workers remain in the zero-capability profile', () => {
  const uid = process.getuid() || 65534, result = run(uid, 2, false);
  assert.deepEqual(result.uids, Array(3).fill(uid)); assert.deepEqual(result.profiles, ['worker_none', 'worker_none']);
});
