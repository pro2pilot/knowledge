'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { qualifyNativePublication, publishPreparedLock, closeOwnerLease } = require('../tools/lib/lock-publication');

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-native-publish-')));
  const version = path.join(root, 'locks', 'v1'), release = path.join(version, '.release');
  fs.mkdirSync(release, { recursive: true });
  const stage = 'publish-team-flow-01234567-89ab-4cde-8fed-0123456789ab.lock', target = 'team-flow.lock';
  fs.mkdirSync(path.join(release, stage));
  fs.writeFileSync(path.join(release, stage, 'owner.json'), '{"complete":true}\n', { flag: 'wx' });
  const identity = fs.statSync(path.join(release, stage), { bigint: true });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, version, release, stage, target, identity, publicPath: path.join(version, target), stagePath: path.join(release, stage) };
}
function identity(file) { const s=fs.lstatSync(file,{bigint:true}); return [s.dev,s.ino,s.mode]; }

test('native prebuilt is pinned to current source, host and N-API 8', () => {
  const q=qualifyNativePublication();
  assert.equal(q.info.platform,process.platform); assert.equal(q.info.architecture,process.arch);
  assert.equal(q.info.source_sha256,q.manifest.source_sha256); assert.equal(q.info.napi_version,8);
});
test('one native operation publishes the complete prepared directory', t => {
  const f=fixture(t), before=identity(f.stagePath);
  const result=publishPreparedLock(f.root,f.stage,f.target);
  t.after(()=>{if(result.lease_id)closeOwnerLease(result.lease_id);});
  assert.equal(result.status,'published'); assert.equal(result.published,true);
  assert.deepEqual(identity(f.publicPath),before); assert.equal(fs.existsSync(f.stagePath),false);
  assert.equal(fs.readFileSync(path.join(f.publicPath,'owner.json'),'utf8'),'{"complete":true}\n');
});
test('native refuses a hardlinked prepared owner inode without publishing it', t=>{
  const f=fixture(t),owner=path.join(f.stagePath,'owner.json'),link=path.join(f.root,'shared-owner');
  fs.linkSync(owner,link);const before=identity(f.stagePath);
  const result=publishPreparedLock(f.root,f.stage,f.target);
  assert.equal(result.status,'failed');assert.equal(result.published,false);assert.equal(fs.existsSync(f.publicPath),false);
  assert.deepEqual(identity(f.stagePath),before);assert.equal(fs.statSync(link).nlink,2);
});
test('native refuses an oversized prepared owner before allocating or publishing', t=>{
  const f=fixture(t);fs.writeFileSync(path.join(f.stagePath,'owner.json'),Buffer.alloc(4097,120));
  const result=publishPreparedLock(f.root,f.stage,f.target);
  assert.equal(result.status,'failed');assert.equal(result.published,false);assert.equal(fs.existsSync(f.publicPath),false);
  assert.equal(fs.statSync(path.join(f.stagePath,'owner.json')).size,4097);
});
for (const kind of ['empty-directory','nonempty-directory','file']) test(`native no-replace preserves an existing ${kind}`, t => {
  const f=fixture(t);
  if (kind==='file') fs.writeFileSync(f.publicPath,'foreign');
  else {fs.mkdirSync(f.publicPath); if(kind==='nonempty-directory')fs.writeFileSync(path.join(f.publicPath,'foreign'),'retained');}
  const before=identity(f.publicPath), stageBefore=identity(f.stagePath);
  const result=publishPreparedLock(f.root,f.stage,f.target);
  assert.equal(result.status,'exists',JSON.stringify(result)); assert.equal(result.published,false);
  assert.deepEqual(identity(f.publicPath),before); assert.deepEqual(identity(f.stagePath),stageBefore);
  if(kind==='file')assert.equal(fs.readFileSync(f.publicPath,'utf8'),'foreign');
  else assert.deepEqual(fs.readdirSync(f.publicPath),kind==='empty-directory'?[]:['foreign']);
});
test('a substituted private parent cannot publish outside the anchored layout', t => {
  const f=fixture(t), moved=path.join(f.version,'moved-release');
  fs.renameSync(f.release,moved); fs.symlinkSync(moved,f.release,process.platform==='win32'?'junction':'dir');
  const result=publishPreparedLock(f.root,f.stage,f.target);
  assert.equal(result.status,'failed'); assert.equal(result.published,false);
  assert.equal(fs.existsSync(f.publicPath),false); assert.equal(fs.existsSync(path.join(moved,f.stage,'owner.json')),true);
});
test('a substituted private stage cannot publish a foreign directory', t => {
  const f=fixture(t), moved=path.join(f.release,'foreign');
  fs.renameSync(f.stagePath,moved); fs.symlinkSync(moved,f.stagePath,process.platform==='win32'?'junction':'dir');
  const result=publishPreparedLock(f.root,f.stage,f.target);
  assert.equal(result.status,'failed'); assert.equal(result.published,false); assert.equal(fs.existsSync(f.publicPath),false);
});
test('native refuses path traversal rather than resolving it', t => {
  const f=fixture(t);
  assert.throws(()=>publishPreparedLock(f.root,'../'+f.stage,f.target),{code:'lock_native_argument_invalid'});
  assert.throws(()=>publishPreparedLock(f.root,f.stage,'../team-flow.lock'),{code:'lock_native_argument_invalid'});
  assert.equal(fs.existsSync(f.stagePath),true); assert.equal(fs.existsSync(f.publicPath),false);
});
test('an exhausted native admission budget retains the complete private stage', t => {
  const f=fixture(t), before=identity(f.stagePath);
  const result=publishPreparedLock(f.root,f.stage,f.target,0.000001);
  assert.equal(result.status,'budget_exhausted'); assert.equal(result.published,false);
  assert.deepEqual(identity(f.stagePath),before); assert.equal(fs.existsSync(f.publicPath),false);
});
