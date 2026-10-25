'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { fixture,clone } = require('./helpers/currency-overlay');
const core = require('../tools/lib/knowledge-currency');
const batch = require('../tools/lib/knowledge-currency-batch');
const native = require('../tools/lib/repair-on-touch');
const records = f => f.ledgers().map(bytes => bytes.toString('base64'));

test('physical verification issues factual overlay while both raw ledgers and risks remain byte identical; retry is idempotent', t => {
  const f = fixture(t); const ids = f.verify(); const before = records(f);
  const result = f.issue(ids);
  assert.equal(result.status,'committed'); assert.equal(result.lifecycle_effect,'none');
  assert.deepEqual(result.closed_factual_findings,[]); assert.equal(result.application_risks_closed,0);
  assert.deepEqual(records(f),before);
  const current = f.evaluate(); assert.equal(current.valid,true,JSON.stringify(current.issues));
  assert.equal(current.files[f.first.source].routing_cap,'routing_trusted');
  assert.equal(current.assurance.open_findings.length,1);
  assert.equal(f.findings[1].status,'open');
  assert.deepEqual(f.issue(ids),result); assert.deepEqual(records(f),before);
  const readiness = native.taskReadiness(f.findings,native.buildTaskScope({modules:[f.first.id],files:[f.first.source]}));
  assert(readiness.score < 100); assert.equal(readiness.relevant_findings_open,2);
});

test('two independent units retain unaffected coverage when source or claim provenance changes', t => {
  const f = fixture(t); const beta = f.addUnit('beta'); f.issue(f.verify()); const before = records(f);
  f.write(f.first.source,'module.exports = 8;\n');
  const result = f.evaluate(); assert.equal(result.valid,true,JSON.stringify(result.issues));
  assert.equal(result.files[f.first.source],undefined); assert(result.files[beta.source]);
  const issue = result.issues.find(issue=>issue.receipt_id && issue.impact==='scope');
  assert(issue && core.isNativeScopedCurrencyIssue(issue));
  assert.deepEqual(issue.changed_paths,[f.first.source]); assert.deepEqual(records(f),before);
  f.write(beta.evidence,{claims:[{description:'Changed assertion has not been reviewed.'}]});
  const both = f.evaluate(); assert.equal(both.valid,false); assert.deepEqual(Object.keys(both.files),[]);
});

test('changed common authority invalidates all units and has no positive projection', t => {
  const f = fixture(t); f.addUnit('second'); f.issue(f.verify());
  f.write(core.AUTHORITY_FILES[0],'// changed runtime authority\n');
  const result = f.evaluate(); assert.equal(result.valid,false); assert.deepEqual(Object.keys(result.files),[]);
  assert(result.issues.some(issue=>issue.code==='currency_authority_changed'));
});

test('risk changes affect only the risk scope and cannot disappear through an empty caller projection', t => {
  const f = fixture(t); const beta = f.addUnit('risk-independent'); f.issue(f.verify());
  f.first.risk.reason = 'Changed synthetic impact is a semantic risk update.'; f.persist();
  const result = f.evaluate(); assert.equal(result.valid,true,JSON.stringify(result.issues));
  assert.equal(result.files[f.first.source],undefined); assert(result.files[beta.source]);
  assert.equal(result.assurance.open_findings.length,2);
  const caller = core.evaluateCurrency(f.context,{ staleItems:{items:[]},repairQueue:{queue:[]} });
  assert.equal(Object.keys(caller.files).length,0); assert.equal(caller.assurance.open_findings.length,2);
});

test('missing receipts preserve legacy behavior; older local schema is visibly unsupported and untouched', t => {
  const f = fixture(t); const before = records(f);
  const legacy = f.evaluate(); assert.equal(legacy.enabled,false); assert.equal(legacy.valid,false);
  assert.deepEqual(legacy.issues,[]);
  const old = {schema_version:'knowledge-currency-receipt.v2',receipt_id:'KCUR-'+'a'.repeat(64),content_sha256:'a'.repeat(64)};
  f.stateWrite('maintenance/knowledge_currency/receipts/'+'a'.repeat(64)+'.json',old);
  f.stateWrite('maintenance/knowledge_currency/index.json',{schema_version:core.INDEX_SCHEMA,receipt_ids:[old.receipt_id]});
  const result = f.evaluate(); assert.equal(result.valid,false);
  assert(result.issues.some(issue=>issue.code==='currency_manifest_schema_invalid'));
  assert.deepEqual(records(f),before);
});

test('a closed or reopened occurrence cannot be certified by an earlier factual receipt', t => {
  const f = fixture(t); f.issue(f.verify());
  f.first.row.status='closed'; f.first.row.resolution_evidence={type:'unverified_legacy'}; f.persist();
  assert.equal(f.evaluate().valid,false);
  f.first.row.status='open'; f.first.row.resolution_evidence=null; f.first.row.occurrence=2;
  f.first.row.reopened_at=new Date().toISOString(); f.persist();
  assert.equal(f.evaluate().valid,false);
});

test('changing exact child or batch request bytes after KVE prevents any issuance', t => {
  for (const kind of ['child','batch']) {
    const f = fixture(t,'tamper-'+kind); const ids=f.verify(); const before=records(f);
    const file=kind==='child'?f.first.requestPath:f.batchPath;
    fs.appendFileSync(path.join(f.root,file),'\n');
    assert.throws(()=>f.issue(ids),error=>/currency_batch_(child_hash|kve_input)_mismatch/.test(error.code));
    assert.deepEqual(records(f),before);
    assert(!fs.existsSync(path.join(f.state,'maintenance/knowledge_currency/index.json')));
  }
});

test('independence and review content are bound before physical verification and before writes', t => {
  const f=fixture(t); f.prepareBatch();
  const review=JSON.parse(fs.readFileSync(path.join(f.root,f.first.review),'utf8'));
  review.reviewer_id=f.first.request.author_id; f.write(f.first.review,review);
  assert.throws(()=>batch.checkBatch(f.context,f.batchPath),{code:'currency_review_not_independent'});
  const ids=f.verify(); const before=records(f);
  fs.appendFileSync(path.join(f.root,f.first.review),'\n');
  assert.throws(()=>f.issue(ids),error=>/currency_kve_source_(mismatch|drift)/.test(error.code));
  assert.deepEqual(records(f),before);
});

test('forged pending rows never grant native factual finding authority', t => {
  const f=fixture(t); f.issue(f.verify());
  const nativeRows=clone(f.findings);
  f.findings.length=0; f.persist();
  const result=core.evaluateCurrency(f.context,{staleItems:{items:nativeRows},repairQueue:{queue:nativeRows}});
  assert.equal(result.valid,false); assert.deepEqual(Object.keys(result.files),[]);
  assert(result.issues.some(issue=>issue.code==='currency_native_finding_mismatch'));
});

test('hostile caller data is rejected before getters/proxy traps and before creating stores', t => {
  const f=fixture(t); let calls=0; const before=records(f);
  const hostile=[Object.defineProperty({},'claims',{enumerable:true,get(){calls++;return [];}}),
    new Proxy({}, {get(){calls++;throw Error('trap');},ownKeys(){calls++;return [];}}),
    Object.create({claims:[]}),Object.defineProperty({},'hidden',{value:1})];
  const revoked=Proxy.revocable({},{}); revoked.revoke(); hostile.push(revoked.proxy);
  for (const value of hostile) {
    assert.throws(()=>core.prepareCurrencyScope(f.context,value),{code:'transaction_input_invalid'});
    assert.throws(()=>core.evaluateCurrency(f.context,value),{code:'transaction_input_invalid'});
    assert.throws(()=>batch.issueBatch(f.context,value,[]),{code:'transaction_input_invalid'});
  }
  assert.equal(calls,0); assert.deepEqual(records(f),before);
  assert(!fs.existsSync(path.join(f.state,'maintenance/knowledge_currency')));
});

test('disjoint state root issues and reads only its own overlay without project ledger writes', t => {
  const f=fixture(t,'disjoint',{disjoint:true}); const ids=f.verify(); const before=records(f);
  f.issue(ids); assert.equal(f.evaluate().valid,true); assert.deepEqual(records(f),before);
  assert(!fs.existsSync(path.join(f.root,'.knowledge/maintenance/knowledge_currency')));
});

test('interrupted exact-write transaction retries without altering raw ledgers', t => {
  for (const point of ['after_prepare_manifest','after_commit_marker','after_promote_0']) {
    const f=fixture(t,point.replaceAll('_','-')); const ids=f.verify(), before=records(f);
    process.env.KNOWLEDGE_TRANSACTION_FAULT=point;
    try { assert.throws(()=>f.issue(ids)); } finally { delete process.env.KNOWLEDGE_TRANSACTION_FAULT; }
    assert.deepEqual(records(f),before);
    assert.equal(f.issue(ids).status,'committed'); assert.equal(f.evaluate().valid,true);
    assert.deepEqual(records(f),before);
  }
});

test('tampered native evidence without its accepted batch is refused without ledger mutations', t => {
  const f=fixture(t,'proof'); const ids=f.verify(), before=records(f);
  const original=JSON.parse(fs.readFileSync(path.join(f.state,'maintenance/verification_executions',ids.execution_ids[0].slice(4)+'.json'),'utf8'));
  const decoratedIds = [...ids.execution_ids];
  Object.defineProperty(decoratedIds, 'verification_acceptances', { value: ids.verification_acceptances });
  assert.throws(() => batch.issueBatch(f.context, f.batchPath, decoratedIds, null, ids.verification_acceptances), { code: 'transaction_input_invalid' });
  for (const mutate of [row=>{row.task_id='another-task';},row=>{row.session_id='another-session';},
    row=>{row.status='fail';row.exit_code=1;},row=>{row.timed_out=true;},
    row=>{row.source_snapshot=row.source_snapshot.filter(pin=>pin.path!==f.batchPath);row.source_snapshot_before=clone(row.source_snapshot);},
    row=>{row.source_snapshot.push(clone(row.source_snapshot[0]));row.source_snapshot_before=clone(row.source_snapshot);}]) {
    const changed=clone(original); mutate(changed);
    const digest=native.executionDigest(changed); changed.execution_id='KVE-'+digest; changed.content_sha256=digest;
    f.stateWrite('maintenance/verification_executions/'+digest+'.json',changed);
    assert.throws(()=>f.issue({ execution_ids:[changed.execution_id], verification_acceptances:ids.verification_acceptances }), { code: 'verification_finalization_required' });
    assert.deepEqual(records(f),before);
    assert(!fs.existsSync(path.join(f.state,'maintenance/knowledge_currency/index.json')));
  }
});

test('changed intrinsic prototypes are rejected without invoking hidden getters or replacement iterators', t => {
  const f=fixture(t,'admission'); let calls=0;
  for (const variant of [
    {prototype:Object.prototype,key:'currency_defer',get(){calls++;throw Error('getter');}},
    {prototype:Object.prototype,key:'code',get(){calls++;throw Error('getter');}},
    {prototype:Array.prototype,key:Symbol.iterator,value(){calls++;throw Error('iterator');}}
  ]) {
    const previous=Object.getOwnPropertyDescriptor(variant.prototype,variant.key);
    const descriptor=Object.create(null); descriptor.configurable=true;
    if (variant.get) descriptor.get=variant.get; else {descriptor.value=variant.value;descriptor.writable=true;}
    Object.defineProperty(variant.prototype,variant.key,descriptor);
    let caught;
    try { core.prepareCurrencyScope(f.context,f.first.request); } catch(error) { caught=error; }
    finally { if(previous)Object.defineProperty(variant.prototype,variant.key,previous);else Reflect.deleteProperty(variant.prototype,variant.key); }
    assert.equal(caught?.code,'transaction_input_invalid');
  }
  assert.equal(calls,0);
});

test('supersession is explicit, complete and preserves old receipt bytes and unrelated debt', t => {
  const f=fixture(t,'refresh'); const first=f.issue(f.verify()), before=records(f);
  const oldId=first.receipt_ids[0], oldPath=path.join(f.state,'maintenance/knowledge_currency/receipts',oldId.slice(5)+'.json');
  const oldBytes=fs.readFileSync(oldPath);
  f.first.request.supersedes=[oldId];
  const ids=f.verify([f.first],[oldId]); const fresh=f.issue(ids);
  assert.equal(fresh.status,'committed'); assert.deepEqual(fresh.superseded_receipts,[oldId]);
  assert.deepEqual(fs.readFileSync(oldPath),oldBytes); assert.deepEqual(records(f),before);
  assert.equal(f.evaluate().valid,true);
  assert.deepEqual(f.issue(ids),fresh);
});

test('private risk metadata blocks currency recording with a masked RU notice and no value leakage', t => {
  const f=fixture(t,'privacy');
  const cli=require('../tools/knowledge-currency'),registry=require('../tools/lib/recording-blockers');
  f.write('.knowledge/settings/operator-profile.json',{preferred_language:'ru'});
  const samples=['sk-'+'A'.repeat(30),'person@example.test','C:\\Private\\Customer\\file.txt','password = synthetic-sensitive-value'];
  for(const sample of samples) {
    f.first.risk.reason=sample;f.persist();const before=records(f);
    assert.throws(()=>core.prepareCurrencyScope(f.context,f.first.request),error=>{
      assert.equal(error.code,'currency_recording_blocked');assert(!error.message.includes(sample));return true;
    });
    f.write(f.first.requestPath,f.first.request);
    assert.throws(()=>cli.main(['prepare','--request='+f.first.requestPath],f.context),error=>{
      assert.equal(error.code,'currency_recording_blocked');assert.match(error.chat_notice,/заблокирована/);
      assert.match(error.chat_notice,/Inspector/);assert(!error.chat_notice.includes(sample));return true;
    });
    const output=f.evaluate();assert(!JSON.stringify(output).includes(sample));
    assert.deepEqual(records(f),before);assert(!fs.existsSync(path.join(f.state,'maintenance/knowledge_currency/index.json')));
    assert(!JSON.stringify(registry.listBlockers(f.context)).includes(sample));
  }
});

test('a terminal risk label cannot remove its metadata from factual scope or assert application assurance', t => {
  const f=fixture(t,'terminal-risk');f.issue(f.verify());
  f.first.risk.status='closed';f.first.risk.resolution_evidence=null;f.persist();
  const stale=f.evaluate();assert.equal(stale.valid,false);
  assert.equal(stale.assurance.open_findings.length,0);
  assert.equal(stale.assurance.terminal_findings_not_assessed.length,1);
  assert.equal(stale.assurance.grants_assurance,false);
  assert.equal(stale.assurance.status,'not_assessed');
  const scope=core.prepareCurrencyScope(f.context,f.first.request).scope;
  assert.equal(scope.protected_risks.length,1);
  assert.equal(scope.protected_risks[0].lifecycle_id,f.first.risk.lifecycle_id);
});

test('factual scope uses the same complete registry/card declaration as routing', t => {
  const f=fixture(t,'owner-alpha'); f.addUnit('owner-beta');
  const card=JSON.parse(fs.readFileSync(path.join(f.root,f.first.card),'utf8'));
  card.path='src/different';f.write(f.first.card,card);
  assert.throws(()=>core.prepareCurrencyScope(f.context,f.first.request),error=>error.code==='module_ownership_invalid');
  card.path='src/owner-alpha';card.ownership_paths=['docs/alpha/'];
  card.conditional_dependencies=[{module_id:'owner-beta',when_paths:['src/owner-alpha/']}];
  card.dependencies=['owner-beta'];f.write(f.first.card,card);
  const scope=core.prepareCurrencyScope(f.context,f.first.request).scope.modules[0].registry_scope;
  assert.deepEqual(scope.ownership_paths,['docs/alpha/']);
  assert.deepEqual(scope.conditional_dependencies,card.conditional_dependencies);
  assert.deepEqual(scope.dependencies,['owner-beta']);
  f.issue(f.verify());assert.equal(f.evaluate().valid,true);
  card.ownership_paths=['docs/another/'];f.write(f.first.card,card);
  const stale=f.evaluate();assert.equal(stale.valid,true);
  assert.equal(stale.files[f.first.source],undefined);
  assert.equal(stale.files[f.units[1].source].routing_cap,'routing_trusted');
});
