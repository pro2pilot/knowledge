'use strict';
// Synthetic repositories only. Native executions are physical test evidence,
// never production/application certification or a real independent review.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const native = require('../../tools/lib/repair-on-touch');
const currency = require('../../tools/lib/knowledge-currency');
const batch = require('../../tools/lib/knowledge-currency-batch');
const lifecycle = require('../../tools/lib/queue-lifecycle');
const clone = value => JSON.parse(JSON.stringify(value));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function fixture(t, name = 'alpha', options = {}) {
  const parent = fs.realpathSync(os.tmpdir());
  const root = fs.mkdtempSync(path.join(parent, 'knowledge-overlay-'));
  // Register cleanup before copying runtime files or requiring fixture data:
  // an unsuccessful setup must not leave its disposable repository behind.
  if (t) t.after(() => {
    const resolved = fs.realpathSync(root), relative = path.relative(parent,resolved);
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw Error('Unsafe fixture cleanup');
    fs.rmSync(resolved,{recursive:true,force:false});
  });
  const state = options.disjoint ? path.join(root, 'state') : path.join(root, '.knowledge');
  const system = path.join(root, '.knowledge');
  const context = { mode: 'repo', targetRoot: root, projectKnowledgeRoot: system, systemRoot: system,
    stateRoot: state, agentId: 'currency-overlay-fixture' };
  const write = (file, body) => {
    const target = path.join(root, file); fs.mkdirSync(path.dirname(target), { recursive:true });
    fs.writeFileSync(target, typeof body === 'string' ? body : JSON.stringify(body, null, 2) + '\n');
  };
  const stateWrite = (file, body) => {
    const target = path.join(state, file); fs.mkdirSync(path.dirname(target), { recursive:true });
    fs.writeFileSync(target, JSON.stringify(body, null, 2) + '\n');
  };
  const pin = file => ({ path:file, sha256:hash(fs.readFileSync(path.join(root, file))) });
  const runtime = path.resolve(__dirname, '../..');
  fs.mkdirSync(path.join(system, 'tools'), { recursive:true });
  fs.cpSync(path.join(runtime, 'tools/lib'), path.join(system, 'tools/lib'), { recursive:true });
  fs.cpSync(path.join(runtime, 'schemas'), path.join(system, 'schemas'), { recursive:true });
  for (const file of currency.AUTHORITY_FILES.filter(file => !file.includes('/lib/'))) {
    write(file, fs.readFileSync(path.join(runtime, file.slice(11)), 'utf8'));
  }
  write('.knowledge/package.json', { name:'currency-overlay-fixture', version:'0.0.0' });
  // This configuration belongs only to the disposable synthetic repository.
  // Native child commands must not perform update discovery during tests.
  write('.knowledge/config.yaml', 'updates:\n  enabled: false\n');
  const findings = [], modules = [], units = [];
  function finding(moduleId, code, artifact) {
    const risk = code === 'security_finding';
    const row = { module_id:moduleId, code, primary_artifact:artifact, affected_artifacts:[artifact],
      reason: risk ? 'Synthetic application risk remains explicitly unverified.' : 'Synthetic source requires factual review.',
      status:'open', severity:risk ? 'high':'medium', score_cost:7,
      repair_class:risk ? 'manual_review':'verify_on_touch',
      required_checks:risk ? ['dedicated_review']:['read_current_source', 'compare_existing_claims'],
      resolution_predicate:risk ? 'dedicated_security_review_passed':'source_and_relevant_tests_confirm_claim',
      security_sensitive:risk, safe_during_current_task:!risk, critical_path:false,
      occurrence:1, opened_at:'2026-01-01T00:00:00.000Z', resolution_evidence:null };
    return { ...row, identity_sha256:lifecycle.identitySha256(row), lifecycle_id:lifecycle.stableId('LC',row),
      stale_id:lifecycle.stableId('STALE',row), repair_id:lifecycle.stableId('RQ',row) };
  }
  function persist() {
    stateWrite('maintenance/stale_items.json', { items:clone(findings) });
    stateWrite('maintenance/repair_queue.json', { queue:clone(findings) });
    write('.knowledge/modules/module_registry.json', { modules });
  }
  function addUnit(id) {
    const source = `src/${id}/value.js`, evidence = `.knowledge/evidence/${id}.json`;
    const card = `.knowledge/modules/${id}.json`, review = `.knowledge/evidence/${id}-review.json`;
    const requestPath = `.knowledge/evidence/${id}-request.json`;
    const description = `The ${id} source exports the factual constant seven.`;
    write(source, 'module.exports = 7;\n');
    write(evidence, { claims:[{ path:source, module_id:id, description }] });
    write(card, { module_id:id, key_files:[source], evidence_files:[evidence] });
    modules.push({ module_id:id, path:`src/${id}`, card, key_files:[source], evidence_files:[evidence] });
    const row = finding(id,'tracked_file_needs_recheck',source);
    const risk = finding(id,'security_finding',`src/${id}/risk.js`);
    findings.push(row,risk); persist();
    const request = { schema_version:currency.REQUEST_SCHEMA, author_id:'fixture-author',
      task_id:'overlay-task', session_id:'overlay-session', source_files:[source,evidence],
      claims:[{ claim_id:`claim-${id}`, path:source, module_id:id, description,
        evidence_paths:[source,evidence], provenance:[{ path:evidence, pointer:'/claims/0' }] }],
      modules:[{ module_id:id, card_path:card }], provenance_paths:[], review_path:review, supersedes:[] };
    const unit = { id, source, evidence, card, review, requestPath, request, row, risk };
    units.push(unit); return unit;
  }
  function prepare(unit) {
    persist();
    const prepared = currency.prepareCurrencyScope(context, unit.request);
    write(unit.review, { schema_version:currency.REVIEW_SCHEMA, author_id:unit.request.author_id,
      reviewer_id:'independent-fixture-reviewer', reviewed_at:new Date(Date.now()-1000).toISOString(),
      scope_sha256:prepared.scope_sha256, protected_risks_sha256:prepared.protected_risks_sha256,
      result:'confirmed', method:'source_and_claim_review', routing_only:true, security_certificate:false,
      claims:prepared.scope.claims.map(claim => ({ claim_id:claim.claim_id, claim_sha256:claim.claim_sha256,
        result:'confirmed', notes:'Synthetic reviewer fixture checked source, provenance and open risk limitations.',
        checked_paths:[...prepared.scope.source_files,...prepared.scope.supporting_files].map(pin => pin.path) })) });
    write(unit.requestPath, unit.request);
    return prepared;
  }
  const batchPath = '.knowledge/evidence/batch.json';
  function prepareBatch(selected = units, supersedes = []) {
    selected.forEach(prepare);
    write(batchPath, { schema_version:batch.BATCH_SCHEMA, task_id:selected[0].request.task_id, session_id:selected[0].request.session_id,
      requests:selected.map(unit => pin(unit.requestPath)), supersedes });
    return batch.checkBatch(context,batchPath);
  }
  function verify(selected = units, supersedes = []) {
    prepareBatch(selected,supersedes);
    const prepared = batch.prepareBatchForFinish(context,batchPath, { taskId:'overlay-task',sessionId:'overlay-session',
      sourceFiles:[batchPath,...selected.map(unit => unit.requestPath),...selected.flatMap(unit => {
        const scope = currency.prepareCurrencyScope(context,unit.request).scope;
        return [...scope.source_files,...scope.supporting_files].map(pin => pin.path).concat(unit.review);
      })] });
    write('tests/verify-facts.js', `const assert=require('assert').strict;\n${selected.map(unit => `assert.equal(require('../${unit.source}'),7);`).join('\n')}
require('../.knowledge/tools/lib/knowledge-currency-batch').checkBatch(${JSON.stringify(context)},${JSON.stringify(batchPath)});\n`);
    const sources = [...new Set([batchPath,...selected.map(unit=>unit.requestPath),...prepared.pins.filter(pin=>!pin.predecessor_receipt_id).map(pin=>pin.path),'tests/verify-facts.js'])];
    const executions = native.runVerificationTests({ stateRoot:state, repoRoot:root, taskId:'overlay-task',sessionId:'overlay-session',
      tests:[{ argv:['node','tests/verify-facts.js'],cwd:'.',timeout_ms:30000 }],sourceFiles:sources.map(path=>({path})),checkedBy:'currency-overlay-fixture' });
    if (executions[0].record.status !== 'pass') throw Error(JSON.stringify(executions[0]));
    if (!Array.isArray(executions.verification_acceptances) || executions.verification_acceptances.length !== 1) {
      throw Error('Native verification did not return its batch acceptance');
    }
    return {
      execution_ids: executions.map(entry=>entry.record.execution_id),
      verification_acceptances: executions.verification_acceptances
    };
  }
  const first = addUnit(name);
  return { root,state,context,write,stateWrite,pin,findings,modules,units,first,addUnit,persist,prepare,prepareBatch,verify,batchPath,
    ledgers:()=>['maintenance/stale_items.json','maintenance/repair_queue.json'].map(file=>fs.readFileSync(path.join(state,file))),
    issue:(verification)=>batch.issueBatch(context,batchPath,verification.execution_ids,null,verification.verification_acceptances),
    evaluate:()=>currency.evaluateCurrency(context) };
}
module.exports = { fixture,clone,hash };
