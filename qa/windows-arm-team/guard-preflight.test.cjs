'use strict';
// Run in the actual Node --test child before product tests. Every target is
// physically owned by this QA job; this is not an OS sandbox demonstration.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
test('D5 recursive guard is installed in the actual Windows test worker',()=>{
  assert.equal(process.platform,'win32');assert.equal(process.arch,'arm64');assert.equal(process.version,'v24.22.1');
  assert.match(process.env.NODE_TEST_CONTEXT||'',/^child/);
  const guard=globalThis[Symbol.for('knowledge.d5.guard')];
  assert.ok(guard&&Object.isFrozen(guard)&&guard.recursiveOnly===true&&guard.notSandbox===true);
  const root=fs.realpathSync.native(process.env.KNOWLEDGE_QA_OWNED_TEMP),outside=fs.realpathSync.native(process.env.KNOWLEDGE_QA_PREFLIGHT_OUTSIDE);
  const privateRoot=fs.realpathSync.native(process.env.KNOWLEDGE_QA_PRIVATE_ROOT);
  assert.equal(guard.root,root);assert.equal(path.dirname(root),path.dirname(outside));
  assert.ok(!outside.toLowerCase().startsWith(root.toLowerCase()+path.sep));
  const sentinel=path.join(outside,'sentinel.txt');fs.writeFileSync(sentinel,'owned QA outside fixture\n',{flag:'wx'});
  const inside=path.join(root,'guard-allow');fs.mkdirSync(inside);fs.mkdirSync(path.join(inside,'nested'));
  fs.writeFileSync(path.join(inside,'nested/file'),'delete owned fixture\n',{flag:'wx'});
  fs.rmSync(inside,{recursive:true,force:true});assert.equal(fs.existsSync(inside),false);
  assert.throws(()=>fs.rmSync(outside,{recursive:true,force:true}));
  assert.throws(()=>fs.rmSync(path.join(outside,'missing'),{recursive:true,force:true}));
  fs.rmSync(path.join(root,'missing-safe'),{recursive:true,force:true});
  const alias=path.join(root,'alias-target');fs.mkdirSync(alias);fs.writeFileSync(path.join(alias,'keep'),'alias sentinel\n',{flag:'wx'});
  assert.throws(()=>fs.rmSync(alias+'.',{recursive:true,force:true}));
  assert.throws(()=>fs.rmSync(root+path.sep+'..'+path.sep+path.basename(root)+path.sep+'alias-target',{recursive:true,force:true}));
  const junction=path.join(root,'guard-junction');fs.symlinkSync(outside,junction,'junction');
  assert.throws(()=>fs.rmSync(junction,{recursive:true,force:true}));
  assert.throws(()=>fs.rmSync(path.join(junction,'missing'),{recursive:true,force:true}));
  assert.equal(fs.readFileSync(sentinel,'utf8'),'owned QA outside fixture\n');assert.equal(fs.readFileSync(path.join(alias,'keep'),'utf8'),'alias sentinel\n');
  // Preserve these fixtures. Supervisor does not recursively remove its root.
  fs.appendFileSync(path.join(privateRoot,'preflight-proof.ndjson'),JSON.stringify({schema:'knowledge-d5-guard-worker-proof.v1',event:'preflight_worker_proof',pid:process.pid,
    worker_context:process.env.NODE_TEST_CONTEXT,guard_version:guard.version,recursive_only:true,os_sandbox:false,
    checks:{allow_inside:true,reject_outside:true,reject_outside_force_missing:true,allow_inside_force_missing:true,reject_trailing_dot_alias:true,
      reject_dotdot_alias:true,reject_junction:true,reject_junction_force_missing:true,outside_sentinel_unchanged:true}})+'\n');
});
