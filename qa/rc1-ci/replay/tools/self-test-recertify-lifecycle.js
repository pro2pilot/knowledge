#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync, spawn } = require('child_process');
const {
  reconcile,
  stableId,
  closeFindings,
  canonicalPath,
  canonicalModule,
  normalizedFinding,
  findingOccurrence
} = require('./lib/queue-lifecycle');
const {
  createDedicatedReceipt,
  saveDedicatedReceipt,
  verifyDedicatedEvidence
} = require('./lib/dedicated-verification');
const { systemVersion } = require('./lib/system-version');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const systemRoot = path.resolve(__dirname, '..');
function assert(value, message) { if (!value) throw new Error(message); }
function expectErrorCode(fn, code, message) {
  let captured = null;
  try { fn(); } catch (error) { captured = error; }
  assert(captured?.code === code, `${message}: expected ${code}, received ${captured?.code || 'no error'}`);
  return captured;
}
function json(file, value) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(value, null, 2)); }
function hash(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function env(root, agent) { return { ...process.env, KNOWLEDGE_SYSTEM_ROOT: systemRoot, KNOWLEDGE_TARGET_ROOT: root, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(root, '.knowledge'), KNOWLEDGE_STATE_ROOT: path.join(root, '.knowledge'), KNOWLEDGE_AGENT_ID: agent }; }
function removeFixture(root) {
  const tempBase = path.resolve(os.tmpdir());
  const target = path.resolve(root);
  if (path.dirname(target) !== tempBase || !path.basename(target).startsWith('knowledge-recertify-')) {
    throw new Error(`Refusing to remove unexpected fixture path: ${target}`);
  }
  return removeTempDirStrict(target, {
    attempts: 30,
    initialDelayMs: 200,
    maxDelayMs: 200,
    maxElapsedMs: 10000
  });
}
function execute(root, agent = 'recertify-test') {
  const result = spawnSync(process.execPath, [path.join(systemRoot, 'tools', 'recertify.js'), 'alpha', '--json'], { cwd: root, env: env(root, agent), encoding: 'utf8', timeout: 30000, windowsHide: true });
  return { ...result, body: JSON.parse(result.stdout || '{}') };
}
function setup(root) {
  const knowledge = path.join(root, '.knowledge');
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.mkdirSync(path.join(root, 'tests'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'alpha.js'), 'module.exports = 1;\n');
  fs.writeFileSync(path.join(root, 'tests', 'alpha.test.js'), 'require("../src/alpha");\n');
  json(path.join(knowledge, 'evidence', 'alpha.json'), { generated_at: new Date().toISOString(), result: 'pass' });
  const sources = { 'src/alpha.js': hash(path.join(root, 'src', 'alpha.js')) };
  const evidence = { '.knowledge/evidence/alpha.json': hash(path.join(knowledge, 'evidence', 'alpha.json')) };
  const tests = { 'tests/alpha.test.js': hash(path.join(root, 'tests', 'alpha.test.js')) };
  json(path.join(knowledge, 'modules', 'alpha.json'), { module_id: 'alpha', current_trust_level: 'suspect', target_trust_level: 'trusted', verification_status: 'needs_recheck', key_files: Object.keys(sources), evidence_files: Object.keys(evidence), recertification: { verification_status: 'code_verified', source_hashes: sources, evidence_hashes: evidence, test_hashes: tests, max_evidence_age_days: 1 } });
  json(path.join(knowledge, 'modules', 'module_registry.json'), { modules: [{ module_id: 'alpha', card: '.knowledge/modules/alpha.json' }] });
  json(path.join(knowledge, 'freshness.json'), { tracked_files: [...Object.entries({ ...sources, ...evidence, ...tests }).map(([file, sha256]) => ({ path: file, sha256, status: 'needs_recheck' }))], artifact_statuses: { '.knowledge/modules/alpha.json': { status: 'needs_recheck' } } });
  const stale = { items: [] }; const repair = { queue: [] };
  reconcile({ staleItems: stale, repairQueue: repair, source: 'sync', agentId: 'seed', timestamp: new Date().toISOString(), findings: [{ module_id: 'alpha', code: 'tracked_file_needs_recheck', artifact: 'src/alpha.js', reason: 'changed: src/alpha.js', affected_artifacts: ['src/alpha.js'] }] });
  const card = JSON.parse(fs.readFileSync(path.join(knowledge, 'modules', 'alpha.json')));
  card.recertification.resolves = [{
    lifecycle_id: stale.items[0].lifecycle_id,
    code: 'tracked_file_needs_recheck',
    artifact: 'src/alpha.js',
    predicate: 'source_and_tests_match_pinned_hashes'
  }];
  json(path.join(knowledge, 'modules', 'alpha.json'), card);
  json(path.join(knowledge, 'maintenance', 'stale_items.json'), stale);
  json(path.join(knowledge, 'maintenance', 'repair_queue.json'), repair);
  json(path.join(knowledge, 'maintenance', 'trust_report.json'), { modules: { trusted: [], near_trusted: [], routing_trusted: [], advisory_only: [], suspect: ['alpha'], low_confidence: [] }, module_statuses: [{ module_id: 'alpha', trust_status: 'suspect', freshness_status: 'suspect' }] });
}
async function concurrent(root) {
  const run = (agent) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(systemRoot, 'tools', 'recertify.js'), 'alpha', '--json'], { cwd: root, env: env(root, agent), windowsHide: true });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', (data) => { stdout += data; }); child.stderr.on('data', (data) => { stderr += data; });
    child.on('close', (code) => code === 0 ? resolve(JSON.parse(stdout)) : reject(new Error(stderr || stdout)));
  });
  return Promise.all([run('agent-a'), run('agent-b')]);
}
async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-recertify-'));
  try {
    setup(root);
    const first = execute(root);
    assert(first.status === 0 && first.body.status === 'recertified' && !first.body.idempotent, 'successful first-party recertification failed');
    const freshness = JSON.parse(fs.readFileSync(path.join(root, '.knowledge', 'freshness.json')));
    assert(freshness.tracked_files.every((item) => item.status === 'clean'), 'recertification did not clear matching freshness statuses');
    const recertifiedCard = JSON.parse(fs.readFileSync(path.join(root, '.knowledge', 'modules', 'alpha.json')));
    const recertifiedTrust = JSON.parse(fs.readFileSync(path.join(root, '.knowledge', 'maintenance', 'trust_report.json')));
    assert(recertifiedCard.current_trust_level === 'trusted' && recertifiedCard.verification_status === 'code_verified' && recertifiedCard.last_verified_at, 'recertification did not safely elevate the card to its explicit target');
    assert(recertifiedTrust.modules.suspect.length === 0 && recertifiedTrust.modules.trusted.includes('alpha'), 'recertification did not remove the module from suspect trust buckets');
    const closed = JSON.parse(fs.readFileSync(path.join(root, '.knowledge', 'maintenance', 'repair_queue.json')));
    assert(closed.queue.every((item) => item.status === 'closed' && item.resolution_evidence?.type === 'finding_specific_recertification'), 'recertification did not close lifecycle items with finding-specific evidence');
    const repeat = execute(root);
    assert(repeat.status === 0 && repeat.body.idempotent === true, 'unchanged recertification was not idempotent');
    fs.writeFileSync(path.join(root, 'src', 'alpha.js'), 'module.exports = 2;\n');
    const changed = execute(root);
    assert(changed.status === 2 && changed.body.errors.some((item) => item.startsWith('source_hash_mismatch:')), 'changed source was accepted');
    const unchangedCard = JSON.parse(fs.readFileSync(path.join(root, '.knowledge', 'modules', 'alpha.json')));
    assert(unchangedCard.last_verified_at === recertifiedCard.last_verified_at && unchangedCard.current_trust_level === 'trusted', 'failed recertification changed trust fields');
    fs.writeFileSync(path.join(root, 'src', 'alpha.js'), 'module.exports = 1;\n');
    fs.rmSync(path.join(root, 'tests', 'alpha.test.js'));
    const missing = execute(root);
    assert(missing.status === 2 && missing.body.errors.some((item) => item.startsWith('test_missing')), 'missing test was accepted');
    fs.writeFileSync(path.join(root, 'tests', 'alpha.test.js'), 'require("../src/alpha");\n');
    json(path.join(root, '.knowledge', 'evidence', 'alpha.json'), { generated_at: '2000-01-01T00:00:00.000Z', result: 'pass' });
    const card = JSON.parse(fs.readFileSync(path.join(root, '.knowledge', 'modules', 'alpha.json')));
    card.recertification.evidence_hashes['.knowledge/evidence/alpha.json'] = hash(path.join(root, '.knowledge', 'evidence', 'alpha.json'));
    json(path.join(root, '.knowledge', 'modules', 'alpha.json'), card);
    const stale = execute(root);
    assert(stale.status === 2 && stale.body.errors.some((item) => item.startsWith('evidence_stale:')), 'stale evidence was accepted');
    json(path.join(root, '.knowledge', 'evidence', 'alpha.json'), { generated_at: new Date().toISOString(), result: 'pass' });
    card.recertification.evidence_hashes['.knowledge/evidence/alpha.json'] = hash(path.join(root, '.knowledge', 'evidence', 'alpha.json'));
    json(path.join(root, '.knowledge', 'modules', 'alpha.json'), card);
    card.key_files = ['../outside.js'];
    card.recertification.source_hashes['../outside.js'] = '0'.repeat(64);
    json(path.join(root, '.knowledge', 'modules', 'alpha.json'), card);
    const traversal = execute(root);
    assert(traversal.status === 2 && traversal.body.errors.some((item) => item.startsWith('source_missing_or_unsafe:../')), 'path traversal was accepted');
    card.key_files = ['src/alpha.js'];
    delete card.recertification.source_hashes['../outside.js'];
    json(path.join(root, '.knowledge', 'modules', 'alpha.json'), card);
    const freshnessPath = path.join(root, '.knowledge', 'freshness.json');
    const fresh = JSON.parse(fs.readFileSync(freshnessPath));
    fresh.tracked_files.find((item) => item.path === '.knowledge/evidence/alpha.json').sha256 = card.recertification.evidence_hashes['.knowledge/evidence/alpha.json'];
    fresh.tracked_files.forEach((item) => { item.status = 'needs_recheck'; });
    json(freshnessPath, fresh);
    const concurrentStalePath = path.join(root, '.knowledge', 'maintenance', 'stale_items.json');
    const concurrentQueuePath = path.join(root, '.knowledge', 'maintenance', 'repair_queue.json');
    const concurrentStale = JSON.parse(fs.readFileSync(concurrentStalePath));
    const concurrentQueue = JSON.parse(fs.readFileSync(concurrentQueuePath));
    reconcile({
      staleItems: concurrentStale,
      repairQueue: concurrentQueue,
      source: 'sync',
      agentId: 'concurrency-seed',
      timestamp: new Date().toISOString(),
      findings: [{
        module_id: 'alpha',
        code: 'tracked_file_needs_recheck',
        artifact: 'src/alpha.js',
        reason: 'reopened for concurrent exact recertification',
        affected_artifacts: ['src/alpha.js']
      }]
    });
    json(concurrentStalePath, concurrentStale);
    json(concurrentQueuePath, concurrentQueue);
    const pair = await concurrent(root);
    assert(pair.every((item) => item.status === 'recertified') && pair.some((item) => item.idempotent), 'concurrent recertification was not serialized/idempotent');
    const staleItems = { items: [] }; const repairQueue = { queue: [] }; const time = new Date().toISOString();
    const opened = reconcile({ staleItems, repairQueue, source: 'sync', agentId: 'a', timestamp: time, findings: [{ module_id: 'alpha', code: 'changed', artifact: 'src/alpha.js', reason: 'changed' }] });
    const duplicate = reconcile({ staleItems, repairQueue, source: 'sync', agentId: 'b', timestamp: time, findings: [{ module_id: 'alpha', code: 'changed', artifact: 'src/alpha.js', reason: 'changed' }] });
    const absent = reconcile({ staleItems, repairQueue, source: 'sync', agentId: 'b', timestamp: time, findings: [] });
    const lifecycleId = staleItems.items[0].lifecycle_id;
    const explicitClose = closeFindings({
      staleItems,
      repairQueue,
      lifecycleIds: [lifecycleId],
      allowedCodes: ['changed'],
      verifiedArtifacts: ['src/alpha.js'],
      resolutionEvidence: [{
        lifecycle_id: lifecycleId,
        code: 'changed',
        artifact: 'src/alpha.js',
        predicate: 'source_and_tests_match_pinned_hashes',
        predicate_result: true,
        verifier_type: 'first_party_hash_recertification'
      }],
      recertificationId: 'RCERT-lifecycle-transition',
      agentId: 'b',
      timestamp: time
    });
    const reopened = reconcile({ staleItems, repairQueue, source: 'sync', agentId: 'b', timestamp: time, findings: [{ module_id: 'alpha', code: 'changed', artifact: 'src/alpha.js', reason: 'changed' }] });
    assert(
      opened.events[0]?.transition === 'open' &&
      duplicate.events.length === 0 &&
      absent.events[0]?.transition === 'observation_absent' &&
      explicitClose.closed_lifecycle_ids.length === 1 &&
      reopened.events[0]?.transition === 'reopen',
      'queue lifecycle transitions are not deterministic'
    );
    assert(staleItems.items.length === 1 && repairQueue.queue.length === 1 && staleItems.items[0].id.startsWith('STALE-') && repairQueue.queue[0].id.startsWith('RQ-'), 'queue projection duplicated or used unstable IDs');
    const ordered = { module_id: 'alpha', code: 'changed-file', affected_artifacts: ['src/z.js', '.\\src\\a.js', 'src/z.js'] };
    const permuted = { module_id: ' ALPHA ', code: 'changed file', affected_artifacts: ['src/a.js', 'src/z.js'] };
    assert(stableId('LC', ordered) === stableId('LC', permuted), 'stable finding ID changed with artifact order, duplicates, separators, or normalized code/module spelling');
    assert(
      stableId('LC', { module_id: 'alpha', code: 'changed', artifact: 'src/A.js' }) !==
      stableId('LC', { module_id: 'alpha', code: 'changed', artifact: 'src/a.js' }),
      'case-distinct repository paths collided'
    );
    assert(
      stableId('LC', { module_id: 'alpha-beta', code: 'changed', artifact: 'src/a.js' }) !==
      stableId('LC', { module_id: 'alpha_beta', code: 'changed', artifact: 'src/a.js' }),
      'hyphen and underscore module IDs collided'
    );
    assert(canonicalModule(' ALPHA ') === 'alpha', 'safe module trim/case normalization regressed');
    expectErrorCode(() => canonicalModule('alpha/beta'), 'module_id_invalid', 'path-like module ID was accepted');
    for (const unsafe of ['../src/a.js', 'C:/src/a.js', '/src/a.js', '\\\\server\\share\\a.js']) {
      expectErrorCode(() => canonicalPath(unsafe), 'finding_artifact_unsafe', `unsafe lifecycle artifact was accepted: ${unsafe}`);
    }
    const collisionIncoming = {
      module_id: 'collision-a',
      code: 'changed',
      artifact: 'src/a.js',
      affected_artifacts: ['src/a.js']
    };
    const collisionOther = normalizedFinding({
      module_id: 'collision-b',
      code: 'changed',
      artifact: 'src/b.js',
      affected_artifacts: ['src/b.js']
    });
    const forcedLifecycleId = stableId('LC', collisionIncoming);
    const collisionStale = {
      items: [{
        id: 'STALE-forged',
        lifecycle_id: forcedLifecycleId,
        stale_id: 'STALE-forged',
        repair_id: 'RQ-forged',
        ...collisionOther,
        status: 'open',
        opened_at: time,
        last_seen_at: time,
        sources: { sync: { active: true, observed_at: time, agent_id: 'seed' } }
      }]
    };
    const collisionRepair = { queue: [] };
    expectErrorCode(() => reconcile({
      staleItems: collisionStale,
      repairQueue: collisionRepair,
      source: 'sync',
      agentId: 'collision-test',
      timestamp: time,
      findings: [collisionIncoming]
    }), 'lifecycle_id_collision', 'short lifecycle collision was merged');
    const projectionStale = { items: [] };
    const projectionRepair = { queue: [] };
    reconcile({
      staleItems: projectionStale,
      repairQueue: projectionRepair,
      source: 'projection-test',
      agentId: 'seed',
      timestamp: time,
      findings: [{
        module_id: 'alpha',
        code: 'changed',
        artifact: 'src/alpha.js',
        reason: 'projection integrity'
      }]
    });
    projectionRepair.queue[0].status = 'closed';
    expectErrorCode(() => reconcile({
      staleItems: projectionStale,
      repairQueue: projectionRepair,
      source: 'projection-test',
      agentId: 'verify',
      timestamp: time,
      findings: []
    }), 'lifecycle_projection_conflict', 'conflicting stale/repair projections were merged');
    projectionRepair.queue[0].status = projectionStale.items[0].status;
    projectionStale.items[0].identity_sha256 = '0'.repeat(64);
    expectErrorCode(() => reconcile({
      staleItems: projectionStale,
      repairQueue: projectionRepair,
      source: 'projection-test',
      agentId: 'verify',
      timestamp: time,
      findings: []
    }), 'lifecycle_identity_hash_mismatch', 'forged lifecycle identity hash was accepted');
    const unspecificStale = { items: [] };
    const unspecificRepair = { queue: [] };
    reconcile({
      staleItems: unspecificStale,
      repairQueue: unspecificRepair,
      source: 'unspecific-test',
      agentId: 'seed',
      timestamp: time,
      findings: [{ module_id: 'alpha', code: 'changed', reason: 'no exact artifact' }]
    });
    const unspecific = unspecificStale.items[0];
    const unspecificClose = closeFindings({
      staleItems: unspecificStale,
      repairQueue: unspecificRepair,
      lifecycleIds: [unspecific.lifecycle_id],
      allowedCodes: [unspecific.code],
      verifiedArtifacts: ['unknown'],
      resolutionEvidence: [{
        lifecycle_id: unspecific.lifecycle_id,
        code: unspecific.code,
        artifact: 'unknown',
        predicate: 'source_and_tests_match_pinned_hashes',
        predicate_result: true
      }],
      recertificationId: 'RCERT-unspecific',
      agentId: 'test',
      timestamp: time
    });
    assert(
      unspecificClose.closed_lifecycle_ids.length === 0 &&
      unspecificClose.rejected_lifecycle_ids[0]?.reason === 'finding_artifact_not_specific',
      'finding without an exact artifact was closed'
    );
    const mixedStale = { items: [] }; const mixedRepair = { queue: [] };
    reconcile({
      staleItems: mixedStale,
      repairQueue: mixedRepair,
      source: 'sync',
      agentId: 'seed',
      timestamp: time,
      findings: [
        { module_id: 'alpha', code: 'tracked_file_needs_recheck', artifact: 'src/alpha.js', reason: 'hash changed' },
        { module_id: 'alpha', code: 'open_contradiction', artifact: 'src/policy.md', reason: 'contradictory behavior' }
      ]
    });
    const target = mixedStale.items.find((item) => item.code === 'tracked_file_needs_recheck');
    const unrelated = mixedStale.items.find((item) => item.code === 'open_contradiction');
    const closure = closeFindings({
      staleItems: mixedStale,
      repairQueue: mixedRepair,
      lifecycleIds: [target.lifecycle_id],
      allowedCodes: ['tracked_file_needs_recheck'],
      verifiedArtifacts: ['src/alpha.js'],
      resolutionEvidence: [{
        lifecycle_id: target.lifecycle_id,
        code: target.code,
        artifact: target.artifact,
        predicate: 'source_and_tests_match_pinned_hashes',
        predicate_result: true,
        verifier_type: 'first_party_hash_recertification'
      }],
      recertificationId: 'RCERT-test',
      agentId: 'test',
      timestamp: time
    });
    assert(closure.closed_lifecycle_ids.length === 1, 'listed finding was not closed');
    assert(mixedRepair.queue.find((item) => item.lifecycle_id === unrelated.lifecycle_id).status === 'open', 'unrelated contradiction was closed');
    assert(closure.untouched_open_findings.some((item) => item.lifecycle_id === unrelated.lifecycle_id), 'receipt projection omitted untouched open finding');
    const protectedStale = { items: [] }; const protectedRepair = { queue: [] };
    reconcile({
      staleItems: protectedStale,
      repairQueue: protectedRepair,
      source: 'security-scan',
      agentId: 'seed',
      timestamp: time,
      findings: [
        {
          module_id: 'alpha',
          code: 'security',
          artifact: 'src/auth.js',
          reason: 'security review required',
          repair_class: 'dedicated_action_required',
          required_checks: ['dedicated_review'],
          resolution_predicate: 'dedicated_review_required',
          security_sensitive: true
        },
        {
          module_id: 'alpha',
          code: 'policy_violation',
          artifact: 'policy/access.md',
          reason: 'policy review required',
          repair_class: 'dedicated_action_required',
          required_checks: ['dedicated_review'],
          resolution_predicate: 'dedicated_review_required'
        }
      ]
    });
    reconcile({
      staleItems: protectedStale,
      repairQueue: protectedRepair,
      source: 'security-scan',
      agentId: 'seed',
      timestamp: time,
      findings: []
    });
    assert(protectedStale.items.every((item) => item.status === 'open'), 'protected findings auto-closed when detector stopped reporting them');
    assert(protectedStale.items.some((item) => item.code === 'security_finding'), 'security alias was not canonicalized');
    const hashAttempt = closeFindings({
      staleItems: protectedStale,
      repairQueue: protectedRepair,
      lifecycleIds: protectedStale.items.map((item) => item.lifecycle_id),
      allowedCodes: ['security', 'policy_violation'],
      verifiedArtifacts: protectedStale.items.map((item) => item.artifact),
      resolutionEvidence: protectedStale.items.map((item) => ({
        lifecycle_id: item.lifecycle_id,
        code: item.code,
        artifact: item.artifact,
        predicate: 'source_and_tests_match_pinned_hashes',
        predicate_result: true,
        verifier_type: 'first_party_hash_recertification'
      })),
      recertificationId: 'RCERT-hash-bypass-test',
      agentId: 'test',
      timestamp: time
    });
    assert(hashAttempt.closed_lifecycle_ids.length === 0, 'hash recertification closed a protected finding');
    assert(
      hashAttempt.rejected_lifecycle_ids.every((item) =>
        item.reason === 'resolution_predicate_mismatch'),
      'protected findings did not reject the wrong resolution predicate'
    );
    const security = protectedStale.items.find((item) => item.code === 'security_finding');
    const selfDeclaredEvidence = {
      lifecycle_id: security.lifecycle_id,
      code: 'security_finding',
      artifact: security.artifact,
      predicate: 'dedicated_review_required',
      predicate_result: true,
      verifier_type: 'security_review',
      verifier_id: 'SELF-DECLARED',
      verifier_result: 'pass'
    };
    const selfDeclaredAttempt = closeFindings({
      staleItems: protectedStale,
      repairQueue: protectedRepair,
      lifecycleIds: [security.lifecycle_id],
      allowedCodes: ['security'],
      verifiedArtifacts: [security.artifact],
      resolutionEvidence: [selfDeclaredEvidence],
      recertificationId: 'RCERT-self-declared-test',
      agentId: 'self-declared-reviewer',
      timestamp: time
    });
    assert(
      selfDeclaredAttempt.closed_lifecycle_ids.length === 0 &&
      selfDeclaredAttempt.rejected_lifecycle_ids[0]?.reason === 'dedicated_verifier_mismatch',
      'self-declared security_review evidence closed a protected finding'
    );

    const verificationReceiptSha256 = crypto.createHash('sha256')
      .update(`verification:${security.lifecycle_id}`)
      .digest('hex');
    const verificationReceipt = {
      receipt_id: `KVR-${verificationReceiptSha256}`,
      content_sha256: verificationReceiptSha256,
      finding_id: security.lifecycle_id,
      finding_occurrence_sha256: findingOccurrence(security).sha256,
      module_id: security.module_id,
      resolution_predicate: security.resolution_predicate,
      predicate_result: 'pass',
      checked_at: time,
      checked_by: 'verification-actor'
    };
    const dedicatedReceipt = createDedicatedReceipt({
      verificationReceipt,
      finding: security,
      confirmedLifecycleId: security.lifecycle_id,
      dedicatedVerifierId: 'SEC-REVIEW-1',
      reviewedBy: 'security-reviewer',
      reviewedAt: time
    });
    const dedicatedSaved = saveDedicatedReceipt(
      path.join(root, '.knowledge'),
      dedicatedReceipt,
      { verificationReceipt, finding: security }
    );
    const productionDedicatedVerifier = ({ evidence }) => verifyDedicatedEvidence({
      stateRoot: path.join(root, '.knowledge'),
      evidence,
      verificationReceipt,
      finding: security
    });
    const dedicatedEvidence = {
      ...selfDeclaredEvidence,
      verifier_type: 'repair_on_touch_verification',
      verifier_id: verificationReceipt.receipt_id,
      verifier_result: 'pass',
      receipt_id: verificationReceipt.receipt_id,
      receipt_sha256: verificationReceipt.content_sha256,
      receipt_path:
        `maintenance/verification_receipts/${verificationReceipt.content_sha256}.json`,
      dedicated_verifier_type: dedicatedReceipt.dedicated_verifier_type,
      dedicated_verifier_id: dedicatedReceipt.dedicated_verifier_id,
      dedicated_predicate: dedicatedReceipt.dedicated_predicate,
      dedicated_result: dedicatedReceipt.dedicated_result,
      dedicated_receipt_id: dedicatedReceipt.receipt_id,
      dedicated_receipt_path: dedicatedSaved.relative_path,
      dedicated_receipt_sha256: dedicatedReceipt.content_sha256
    };
    const wrongDedicatedAttempt = closeFindings({
      staleItems: protectedStale,
      repairQueue: protectedRepair,
      lifecycleIds: [security.lifecycle_id],
      allowedCodes: ['security'],
      verifiedArtifacts: [security.artifact],
      resolutionEvidence: [{
        ...dedicatedEvidence,
        dedicated_verifier_type: 'policy_review'
      }],
      recertificationId: 'RCERT-wrong-dedicated-test',
      agentId: 'security-reviewer',
      timestamp: time,
      verifyDedicatedEvidence: productionDedicatedVerifier
    });
    assert(
      wrongDedicatedAttempt.closed_lifecycle_ids.length === 0 &&
      wrongDedicatedAttempt.rejected_lifecycle_ids[0]?.reason === 'dedicated_verifier_mismatch',
      'wrong dedicated verifier type closed a security finding'
    );
    const reservedOverrideAttempt = closeFindings({
      staleItems: protectedStale,
      repairQueue: protectedRepair,
      lifecycleIds: [security.lifecycle_id],
      allowedCodes: ['security'],
      verifiedArtifacts: [security.artifact],
      resolutionEvidence: [{
        ...dedicatedEvidence,
        type: 'attacker_type',
        recertification_id: 'ATTACKER-RCERT',
        verified_at: '1900-01-01T00:00:00.000Z',
        verified_by: 'attacker'
      }],
      recertificationId: 'RCERT-reserved-field-test',
      agentId: 'security-reviewer',
      timestamp: time,
      verifyDedicatedEvidence: productionDedicatedVerifier
    });
    assert(
      reservedOverrideAttempt.closed_lifecycle_ids.length === 0 &&
      reservedOverrideAttempt.rejected_lifecycle_ids[0]?.reason === 'resolution_evidence_reserved_field',
      'resolution evidence overrode trusted closure fields'
    );
    const dedicatedAttempt = closeFindings({
      staleItems: protectedStale,
      repairQueue: protectedRepair,
      lifecycleIds: [security.lifecycle_id],
      allowedCodes: ['security'],
      verifiedArtifacts: [security.artifact],
      resolutionEvidence: [dedicatedEvidence],
      recertificationId: 'RCERT-dedicated-test',
      agentId: 'security-reviewer',
      timestamp: time,
      verifyDedicatedEvidence: productionDedicatedVerifier
    });
    assert(dedicatedAttempt.closed_lifecycle_ids.length === 1, 'dedicated security verifier could not close its explicit finding');
    const storedDedicatedEvidence = protectedRepair.queue.find((item) => item.lifecycle_id === security.lifecycle_id).resolution_evidence;
    assert(
      storedDedicatedEvidence.type === 'finding_specific_recertification' &&
      storedDedicatedEvidence.recertification_id === 'RCERT-dedicated-test' &&
      storedDedicatedEvidence.verified_at === time &&
      storedDedicatedEvidence.verified_by === 'security-reviewer' &&
      storedDedicatedEvidence.dedicated_verifier_validated === true &&
      storedDedicatedEvidence.dedicated_authority_id ===
        'first_party_content_addressed_dedicated_receipt_loader.v1' &&
      storedDedicatedEvidence.receipt_id === verificationReceipt.receipt_id &&
      storedDedicatedEvidence.dedicated_receipt_id === dedicatedReceipt.receipt_id &&
      storedDedicatedEvidence.dedicated_receipt_sha256 === dedicatedReceipt.content_sha256,
      'trusted dedicated evidence fields were not authoritatively bound'
    );
    assert(protectedRepair.queue.find((item) => item.code === 'policy_violation').status === 'open', 'dedicated verifier closed an unrelated policy finding');
    const emptyRoot = path.join(root, 'empty-resolves');
    setup(emptyRoot);
    const emptyCardPath = path.join(emptyRoot, '.knowledge', 'modules', 'alpha.json');
    const emptyCard = JSON.parse(fs.readFileSync(emptyCardPath));
    emptyCard.recertification.resolves = [];
    json(emptyCardPath, emptyCard);
    const emptyResult = execute(emptyRoot, 'empty-policy-test');
    assert(emptyResult.status === 2 &&
      emptyResult.body.errors?.includes('exact_lifecycle_resolution_required'),
    'recertification elevated trust without an exact lifecycle resolution');

    const crossRoot = path.join(root, 'cross-module');
    setup(crossRoot);
    const crossStalePath = path.join(crossRoot, '.knowledge', 'maintenance', 'stale_items.json');
    const crossQueuePath = path.join(crossRoot, '.knowledge', 'maintenance', 'repair_queue.json');
    const crossStale = JSON.parse(fs.readFileSync(crossStalePath));
    const crossQueue = JSON.parse(fs.readFileSync(crossQueuePath));
    reconcile({
      staleItems: crossStale,
      repairQueue: crossQueue,
      source: 'cross-module-test',
      agentId: 'seed',
      timestamp: time,
      findings: [{
        module_id: 'beta',
        code: 'tracked_file_needs_recheck',
        artifact: 'src/alpha.js',
        reason: 'beta must not be closed by alpha'
      }]
    });
    json(crossStalePath, crossStale);
    json(crossQueuePath, crossQueue);
    const betaFinding = crossStale.items.find((item) => item.module_id === 'beta');
    const crossCardPath = path.join(crossRoot, '.knowledge', 'modules', 'alpha.json');
    const crossCard = JSON.parse(fs.readFileSync(crossCardPath));
    crossCard.recertification.resolves = [{
      lifecycle_id: betaFinding.lifecycle_id,
      code: betaFinding.code,
      artifact: betaFinding.artifact,
      predicate: 'source_and_tests_match_pinned_hashes'
    }];
    json(crossCardPath, crossCard);
    const crossResult = execute(crossRoot, 'cross-module-test');
    assert(crossResult.status === 2 &&
      crossResult.body.errors?.includes(`lifecycle_module_mismatch:${betaFinding.lifecycle_id}`) &&
      JSON.parse(fs.readFileSync(crossQueuePath)).queue.find((item) => item.lifecycle_id === betaFinding.lifecycle_id).status === 'open',
    'module alpha closed a lifecycle finding owned by beta');

    const reasonRoot = path.join(root, 'trust-reasons');
    setup(reasonRoot);
    const reasonTrustPath = path.join(reasonRoot, '.knowledge', 'maintenance', 'trust_report.json');
    const reasonTrust = JSON.parse(fs.readFileSync(reasonTrustPath));
    reasonTrust.module_statuses[0].reasons = {
      changed_or_missing_important_files: ['src/alpha.js'],
      open_contradictions: ['CONTRADICTION-1'],
      uncovered_important_files: []
    };
    json(reasonTrustPath, reasonTrust);
    const reasonResult = execute(reasonRoot, 'trust-reason-test');
    const reasonCard = JSON.parse(fs.readFileSync(path.join(reasonRoot, '.knowledge', 'modules', 'alpha.json')));
    const reasonAfter = JSON.parse(fs.readFileSync(reasonTrustPath));
    assert(reasonResult.status === 0 &&
      reasonResult.body.status === 'recertified_with_open_findings' &&
      reasonCard.current_trust_level === 'suspect' &&
      reasonAfter.module_statuses[0].reasons.open_contradictions.includes('CONTRADICTION-1') &&
      reasonAfter.modules.suspect.includes('alpha') &&
      !reasonAfter.modules.trusted.includes('alpha'),
    'unrelated trust-report reason was erased or trust was elevated');

    console.log(JSON.stringify({
      schema_version: systemVersion(),
      status: 'pass',
      checks: [
        'successful finding-specific recertification and explicit target trust elevation',
        'changed source rejection without trust mutation',
        'missing test rejection',
        'stale evidence rejection',
        'unsafe traversal rejection',
        'idempotency',
        'concurrency lock',
        'deduplicated observation-absent/explicit-close/reopen lifecycle',
        'stable finding ID input-order invariance',
        'unsafe/absolute lifecycle paths and path-like module IDs rejected',
        'case-distinct paths and hyphen/underscore module IDs remain distinct',
        'short lifecycle hash collision fails closed',
        'cross-projection conflicts and forged identity hashes fail closed',
        'finding without an exact artifact cannot be closed',
        'unrelated contradiction remains open',
        'security and policy aliases reject hash and mismatched dedicated verifier evidence',
        'self-declared dedicated evidence and reserved-field overrides fail closed',
        'content-addressed physical dedicated receipt closes only its exact finding',
        'all findings remain open when detector output disappears until exact verified closure',
        'empty lifecycle policy cannot elevate trust',
        'cross-module lifecycle closure is rejected',
        'unrelated trust-report reasons survive exact closure and block elevation'
      ]
    }, null, 2));
  } finally {
    removeFixture(root);
  }
}
main().catch((error) => { console.error(error.stack || error.message); process.exit(1); });
