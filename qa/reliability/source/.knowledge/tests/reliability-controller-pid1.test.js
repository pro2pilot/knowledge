'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const runner = require('../tools/lib/command-runner');
const policy = { workMs: 20000, progressMs: 0, setupMs: 10000, cleanupMs: 10000 };
async function asNamespaceInit(code) {
  const result = await runner.runOwnedCommand({ executable: '/usr/bin/unshare',
    args: ['--user', '--map-current-user', '--pid', '--fork', '--kill-child=KILL', '--', process.execPath, '-e', code],
    cwd: process.cwd(), env: process.env, nestedAuthority: true }, { budgets: policy });
  assert.equal(result.cleanup?.status, 'completed', JSON.stringify(result));
  assert.equal(result.cleanup.active_processes, 0);
  assert.equal(result.status, 0, JSON.stringify(result));
  const observed = JSON.parse(result.stdout);
  console.log(JSON.stringify({ scenario: 'physical_linux_controller_pid1', ...observed }));
  assert.equal(observed.pid, 1);
  return observed;
}
test('a real namespace PID1 may own and drain an ordinary command scope', { skip: process.platform !== 'linux' }, async () => {
  const modulePath = path.join(__dirname, '../tools/lib/command-runner.js');
  const observed = await asNamespaceInit(`'use strict';const r=require(${JSON.stringify(modulePath)});(async()=>{
    const result=await r.runOwnedCommand({executable:process.execPath,args:['-e','console.log("pid1-owned")'],cwd:process.cwd(),env:process.env},
      {budgets:{workMs:5000,progressMs:0,setupMs:5000,cleanupMs:5000}});
    console.log(JSON.stringify({pid:process.pid,result}));
  })().catch(e=>{console.log(JSON.stringify({pid:process.pid,error:e.code||e.message}));process.exitCode=1});`);
  assert.equal(observed.result.status, 0, JSON.stringify(observed));
  assert.equal(observed.result.stdout, 'pid1-owned\n');
  assert.equal(observed.result.cleanup.status, 'completed');
  assert.equal(observed.result.cleanup.active_processes, 0);
});
test('a readonly native observer binds a real PID1 parent', { skip: process.platform !== 'linux' }, async () => {
  const binary = path.join(__dirname, `../tools/lib/native/linux-${process.arch}/verification-linux-namespace`);
  const observed = await asNamespaceInit(`'use strict';const p=require('child_process').spawnSync(${JSON.stringify(binary)},
    ['--parent',String(process.pid),'--identity'],{encoding:'utf8',timeout:5000});
    console.log(JSON.stringify({pid:process.pid,status:p.status,signal:p.signal,error:p.error?.code||null,stdout:p.stdout,stderr:p.stderr}));`);
  assert.equal(observed.status, 0, JSON.stringify(observed));
  const native = JSON.parse(observed.stdout);
  assert.equal(native.identity.pid, 1);
  assert.equal(native.identity.namespace_pid, 1);
});
test('the native exact-stop API still refuses PID1 as a signal target', { skip: process.platform !== 'linux' }, async () => {
  const binary = path.join(__dirname, `../tools/lib/native/linux-${process.arch}/verification-linux-namespace`);
  const observed = await asNamespaceInit(`'use strict';const call=args=>require('child_process').spawnSync(${JSON.stringify(binary)},args,{encoding:'utf8',timeout:5000});
    const self=JSON.parse(call(['--identity']).stdout), i=self.identity;
    const stopped=call(['--stop',self.boot_id,self.observer_pid_namespace.dev,self.observer_pid_namespace.ino,self.procfs_dev,
      String(i.pid),String(i.proc_pid),i.start_ticks,i.pid_namespace.dev,i.pid_namespace.ino,String(i.namespace_pid),'1000']);
    console.log(JSON.stringify({pid:process.pid,status:stopped.status,signal:stopped.signal,stdout:stopped.stdout,stderr:stopped.stderr}));`);
  assert.equal(observed.status, 1, JSON.stringify(observed));
  assert.equal(JSON.parse(observed.stdout).code, 'native_identity_invalid');
});
