'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const source = process.env.KNOWLEDGE_LOCK_TEST_SOURCE
  ? path.resolve(process.env.KNOWLEDGE_LOCK_TEST_SOURCE) : path.resolve(__dirname, '..');

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-lock-permissions-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

const bootstrap = `
const fs=require('node:fs'),path=require('node:path');
const [source,root]=process.argv.slice(1);
const manager=require(path.join(source,'tools/lib/contained-lock-manager'));
const {LOCKS}=require(path.join(source,'tools/lib/lock-policy'));
const request={rootKind:'state',rootPath:root,context:{stateRoot:root},lockName:'team-flow',purpose:LOCKS['team-flow'].purpose};
const owner=path.join(root,'locks/v1/team-flow.lock/owner.json');
`;

function child(root, script, enforcePermissions = false) {
  let command = process.execPath, args = ['-e', bootstrap + script, source, root];
  // Root's DAC override would make a chmod-only fixture vacuous. Drop just
  // those bypass capabilities for this child; never modify host identity or
  // directories outside the owned fixture. Other platforms use actual ACL /
  // mode enforcement by their normal CI account.
  if (enforcePermissions && process.platform === 'linux' && process.getuid() === 0) {
    command = '/usr/bin/setpriv';
    args = ['--bounding-set=-dac_override,-dac_read_search', '--', process.execPath, ...args];
  }
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 15000,
    env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.signal, null);
  return JSON.parse(result.stdout);
}

test('POSIX directory and owner permissions retain the existing caller umask contract',
  { skip: process.platform === 'win32' ? 'Windows ACL inheritance is qualified separately from POSIX mode bits.' : false }, t => {
    const root = fixture(t);
    const result = child(root, `process.umask(0o002);const h=manager.acquireContainedLock(request);
const result={directory:fs.statSync(h.path).mode&0o777,owner:fs.statSync(owner).mode&0o777};h.release();console.log(JSON.stringify(result));`);
    assert.equal(result.directory, 0o775, 'Atomic publication must not silently remove existing group access.');
    assert.equal(result.owner, 0o664);
  });

test('an exited owner remains recoverable when its immutable file is physically read-only', t => {
  const root = fixture(t);
  const original = child(root, `const h=manager.acquireContainedLock(request);fs.chmodSync(owner,0o444);console.log(JSON.stringify({lock_id:h.lock_id}));`);
  const result = child(root, `
let writeDenied=false;try{const fd=fs.openSync(owner,'r+');fs.closeSync(fd);}catch(e){if(!['EACCES','EPERM'].includes(e.code))throw e;writeDenied=true;}
if(!writeDenied)throw new Error('The fixture did not enforce read-only access; no native permission claim is possible.');
let result;try{const h=manager.acquireContainedLock({...request,timeoutMs:1000});result={writeDenied,acquired:true,lock_id:h.lock_id,released:h.release().status};}
catch(e){result={writeDenied,acquired:false,code:e.code,reason:e.owner_disposition};}console.log(JSON.stringify(result));`, true);
  assert.equal(result.writeDenied, true);
  assert.equal(result.acquired, true, JSON.stringify(result));
  assert.notEqual(result.lock_id, original.lock_id);
  assert.equal(result.released, 'released');
});

test('relaxing lease write access does not authorize an unreadable owner',
  { skip: process.platform === 'win32' ? 'chmod cannot express a denied-read Windows ACL; native ACL cases belong to Windows qualification.' : false }, t => {
    const root = fixture(t);
    child(root, `const h=manager.acquireContainedLock(request);fs.chmodSync(owner,0o000);console.log(JSON.stringify({lock_id:h.lock_id}));`);
    const file = path.join(root, 'locks/v1/team-flow.lock/owner.json');
    const original = fs.statSync(file, { bigint: true });
    const result = child(root, `let denied=false;try{const fd=fs.openSync(owner,'r');fs.closeSync(fd);}catch(e){if(e.code!=='EACCES')throw e;denied=true;}
if(!denied)throw new Error('The fixture did not enforce denied-read access.');let result;try{manager.acquireContainedLock({...request,timeoutMs:1000});result={denied,acquired:true};}
catch(e){result={denied,acquired:false,code:e.code};}console.log(JSON.stringify(result));`, true);
    assert.equal(result.denied, true);
    assert.equal(result.acquired, false);
    assert.equal(result.code, 'unsafe_lock_owner');
    const after = fs.statSync(file, { bigint: true });
    assert.equal(after.dev, original.dev); assert.equal(after.ino, original.ino);
    fs.chmodSync(file, 0o600);
  });
