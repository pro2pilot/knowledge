'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const transaction = require('../tools/lib/json-transaction');
const { readQueueSnapshot, commitQueuePair, preserveHistoryRequest } = require('../tools/lib/sync-history');
const { reconcile } = require('../tools/lib/queue-lifecycle');

const systemRoot = path.resolve(__dirname, '..');
const repo = path.resolve(systemRoot, '..');
const cli = path.join(systemRoot, 'tools', 'sync-tracked.js');
const ownedParent = path.resolve(process.env.KNOWLEDGE_SYNC_TEST_TMP || path.join(repo, '.qa-tmp', 'sync-history-tests'));
const key = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

assert.ok(ownedParent.startsWith(repo + path.sep) && !key(path.relative(repo, ownedParent)).startsWith('..'),
  'sync history fixtures must remain under the repository-owned test temp');
fs.mkdirSync(ownedParent, { recursive: true });

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' || Buffer.isBuffer(value) ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function snapshotTree(root) {
  const rows = [];
  const visit = directory => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      assert.equal(entry.isSymbolicLink(), false, `fixture contains a link: ${target}`);
      if (entry.isDirectory()) visit(target);
      else { assert.equal(entry.isFile(), true); rows.push([path.relative(root, target).replace(/\\/g, '/'), digest(fs.readFileSync(target))]); }
    }
  };
  visit(root);
  return rows.sort(([a], [b]) => a.localeCompare(b));
}
function fixture(t) {
  const root = fs.mkdtempSync(path.join(ownedParent, 'run-'));
  const state = path.join(root, '.knowledge');
  const file = relative => path.join(root, ...relative.split('/'));
  const read = relative => JSON.parse(fs.readFileSync(file(relative), 'utf8'));
  t.after(() => {
    const physical = fs.realpathSync.native(root);
    const relative = path.relative(fs.realpathSync.native(ownedParent), physical);
    assert.ok(relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
    fs.rmSync(physical, { recursive: true, force: false });
  });

  const activePath = 'src/service.js';
  const ignoredPath = 'qa-runs/retired/source.js';
  const ignoredCard = '.knowledge/modules/retired.json';
  write(file(activePath), 'module.exports = "active";\n');
  write(file(ignoredPath), 'module.exports = "historical";\n');
  const modules = [
    { module_id: 'root', path: '.', card: '.knowledge/modules/root.json', key_files: [], evidence_files: [] },
    { module_id: 'service', path: 'src/', card: '.knowledge/modules/service.json', key_files: [activePath], evidence_files: [] },
    { module_id: 'retired', path: 'qa-runs/retired/', card: ignoredCard, key_files: [ignoredPath], evidence_files: [] }
  ];
  write(file('.knowledge/modules/module_registry.json'), { modules });
  for (const moduleInfo of modules) write(file(moduleInfo.card), { ...moduleInfo, confidence: 'high', verification_status: 'source_checked' });
  write(file('README.md'), '# Isolated sync fixture\n');
  write(file('.knowledge/project_index.json'), { project_name: 'isolated fixture', primary_source_of_truth: 'code', task_routing: [] });
  write(file('.knowledge/contradictions.json'), { items: [] });
  write(file('.knowledge/maps/critical_paths.json'), { paths: [] });
  write(file('.knowledge/maps/wiki_graph.json'), { structural_status: 'healthy', broken_edge_count: 0 });
  write(file('.knowledge/maintenance/wiki_lint_report.json'), { structural_status: 'healthy' });
  write(file('.knowledge/maintenance/quality_report.json'), { quality_score: 100, issues: [] });
  write(file('.knowledge/maintenance/concurrency_policy.json'), { mode: 'locked_atomic_writes' });
  write(file('.knowledge/maintenance/automation_status.json'), { mode: 'event-driven' });
  write(file('.knowledge/maintenance/sync_log.json'), { generated_at: null, entries: [] });
  write(file('.knowledge/freshness.json'), {
    tracked_files: [
      { path: activePath, sha256: '0'.repeat(64), status: 'changed' },
      { path: ignoredPath, sha256: digest(fs.readFileSync(file(ignoredPath))), status: 'clean' }
    ], artifact_dependencies: {}, artifact_statuses: {}
  });
  write(file('.knowledge/maps/file_criticality.json'), {
    files: [activePath, ignoredPath].map(filePath => ({ path: filePath, classification: 'important' })),
    coverage_by_module: { retired: { important_or_critical_files: [ignoredPath], tracked_in_freshness: [ignoredPath], referenced_by_module_card: [ignoredPath], covered_by_evidence: [], uncovered: [ignoredPath] } }
  });
  write(file('.knowledge/evidence/file_facts.json'), { facts: [{ file: ignoredPath, evidence: { source_sha256: digest(fs.readFileSync(file(ignoredPath))) } }] });
  const legacyStale = [
    { id: 'legacy-card', artifact: ignoredCard, status: 'needs_recheck', reason: 'Historical card row.' },
    { id: 'legacy-detected', artifact: '.knowledge/freshness.json', status: 'partial', reason: `New file detected: ${ignoredPath}` },
    { id: 'legacy-terminal', artifact: ignoredCard, status: 'resolved', resolved_at: '2020-01-01T00:00:00.000Z', resolution: 'Preserve historical note.' },
    { id: 'legacy-unrelated', artifact: 'src/other.js', status: 'needs_recheck', reason: 'Unrelated historical item.' }
  ];
  const legacyRepair = [
    { id: 'legacy-card-repair', affected_artifacts: [ignoredCard], status: 'open', subject: 'Historical card row.' },
    { id: 'legacy-detected-repair', affected_artifacts: [ignoredPath], status: 'needs_recheck', subject: `Review file ${ignoredPath}` },
    { id: 'legacy-terminal-repair', affected_artifacts: [ignoredCard], status: 'closed', closed_at: '2020-01-01T00:00:00.000Z', resolution: 'Preserve historical note.' },
    { id: 'legacy-unrelated-repair', affected_artifacts: ['src/other.js'], status: 'open', subject: 'Unrelated historical item.' }
  ];
  const stale = { items: legacyStale };
  const repair = { queue: legacyRepair };
  const activeFinding = {
    module_id: 'service', code: 'tracked_file_changed', artifact: '.knowledge/freshness.json',
    reason: `changed: ${activePath}`, priority: 'medium', critical_path: false, security_sensitive: false,
    affected_artifacts: ['.knowledge/freshness.json', activePath]
  };
  reconcile({ staleItems: stale, repairQueue: repair, findings: [activeFinding], source: 'sync', agentId: 'fixture-agent', timestamp: '2026-01-01T00:00:00.000Z' });
  write(file('.knowledge/maintenance/stale_items.json'), stale);
  write(file('.knowledge/maintenance/repair_queue.json'), repair);
  const cardBytes = fs.readFileSync(file(ignoredCard));
  const lcBefore = stale.items.filter(row => row.lifecycle_id);
  const lcRepairBefore = repair.queue.filter(row => row.lifecycle_id);
  const deleteAudit = '.knowledge/maintenance/history-delete-audit.ndjson';
  const preload = '.knowledge/history-delete-audit.cjs';
  write(file(deleteAudit), '');
  write(file(preload), String.raw`
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const append = fs.appendFileSync.bind(fs);
const identity = value => process.platform === 'win32' ? value.toLowerCase() : value;
const target = identity(path.resolve(process.env.KNOWLEDGE_TEST_HISTORY_CARD));
const active = [];
function record(method, file) {
  if (typeof file !== 'string' && !Buffer.isBuffer(file)) return;
  if (identity(path.resolve(String(file))) !== target) return;
  append(process.env.KNOWLEDGE_TEST_HISTORY_AUDIT, JSON.stringify({ method, path: String(file), parent: active.at(-1) || null }) + '\n');
  if (process.env.KNOWLEDGE_TEST_FORBID_HISTORY_DELETE === '1') throw new Error('history_card_delete_forbidden');
}
for (const name of ['rmSync', 'unlinkSync']) {
  const native = fs[name];
  fs[name] = function(file, ...args) {
    record(name, file);
    if (name !== 'rmSync') return Reflect.apply(native, this, [file, ...args]);
    active.push({ method: name, path: String(file) });
    try { return Reflect.apply(native, this, [file, ...args]); } finally { active.pop(); }
  };
}
for (const name of ['rm', 'unlink']) {
  const native = fs[name];
  fs[name] = function(file, ...args) { record(name, file); return Reflect.apply(native, this, [file, ...args]); };
}
`);
  return { root, state, file, read, ignoredCard, ignoredPath, activePath, legacyStale, legacyRepair, cardBytes, lcBefore, lcRepairBefore, deleteAudit, preload };
}
function run(f, args = []) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (/^KNOWLEDGE_/i.test(name) || name === 'NODE_OPTIONS') delete env[name];
  Object.assign(env, {
    KNOWLEDGE_MODE: 'repo', KNOWLEDGE_SYSTEM_ROOT: systemRoot,
    KNOWLEDGE_TARGET_ROOT: f.root, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: f.state, KNOWLEDGE_STATE_ROOT: f.state,
    KNOWLEDGE_AGENT_ID: 'sync-history-portable-test', KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1',
    KNOWLEDGE_DISCOVER_NEW: '0', KNOWLEDGE_SYNC_TEST_TMP: ownedParent,
    KNOWLEDGE_TEST_HISTORY_CARD: f.file(f.ignoredCard), KNOWLEDGE_TEST_HISTORY_AUDIT: f.file(f.deleteAudit), KNOWLEDGE_TEST_FORBID_HISTORY_DELETE: '1',
    NODE_OPTIONS: `--require=${JSON.stringify(f.file(f.preload))}`,
    GIT_CEILING_DIRECTORIES: f.root, TEMP: ownedParent, TMP: ownedParent
  });
  return spawnSync(process.execPath, [cli, ...args], { cwd: f.root, env, encoding: 'utf8', windowsHide: true });
}
function success(f, args = []) {
  const result = run(f, args);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  return JSON.parse(result.stdout);
}
function stableLifecycle(rows) {
  return rows.filter(row => row.lifecycle_id).map(row => ({
    lifecycle_id: row.lifecycle_id, status: row.status, identity_sha256: row.identity_sha256,
    occurrence: row.occurrence, required_checks: row.required_checks,
    resolution_evidence: row.resolution_evidence, closed_at: row.closed_at
  })).sort((a, b) => a.lifecycle_id.localeCompare(b.lifecycle_id));
}

test('default and explicit history preservation retain card bytes, non-LC rows and LC policy state', t => {
  const ordinary = fixture(t), explicit = fixture(t);
  const defaultResult = success(ordinary, ['--scan']);
  const explicitResult = success(explicit, ['--scan', '--preserve-history']);
  for (const [f, result, requested] of [[ordinary, defaultResult, null], [explicit, explicitResult, '--preserve-history']]) {
    assert.equal(result.preserve_history, true);
    assert.equal(result.history_mode, 'preserve_history');
    assert.equal(result.preserve_history_requested, requested);
    assert.deepEqual(result.history_cleanup_actions, { deleted_cards: 0, resolved_legacy_rows: 0 });
    assert.deepEqual(fs.readFileSync(f.file(f.ignoredCard)), f.cardBytes);
    assert.equal(fs.readFileSync(f.file(f.deleteAudit), 'utf8').trim(), '');
    const stale = f.read('.knowledge/maintenance/stale_items.json').items;
    const repair = f.read('.knowledge/maintenance/repair_queue.json').queue;
    assert.deepEqual(stale.filter(row => !row.lifecycle_id), f.legacyStale);
    assert.deepEqual(repair.filter(row => !row.lifecycle_id), f.legacyRepair);
    assert.deepEqual(stableLifecycle(stale), stableLifecycle(f.lcBefore));
    assert.deepEqual(stableLifecycle(repair), stableLifecycle(f.lcRepairBefore));
    assert.equal(result.ignored_module_cards_removed.length, 0);
    assert.equal(Object.hasOwn(result.preserved_cleanup_debt, 'resolution_evidence'), false);
    assert.equal(result.preserved_cleanup_debt.limits, 'Preserved history is not verification or resolution evidence.');
    const syncEntry = f.read('.knowledge/maintenance/sync_log.json').entries.at(-1);
    assert.equal(syncEntry.preserve_history, true);
    assert.equal(syncEntry.preserve_history_requested, requested);
    assert.deepEqual(syncEntry.history_cleanup_actions, { deleted_cards: 0, resolved_legacy_rows: 0 });
    const debt = syncEntry.preserved_cleanup_debt;
    assert.ok(debt.status === 'preserved_cleanup_debt');
    assert.ok(debt.legacy_stale_items.length >= 2 && debt.legacy_repair_items.length >= 2);
    const event = fs.readFileSync(f.file(`.knowledge/maintenance/events/${syncEntry.timestamp.slice(0, 10)}.ndjson`), 'utf8')
      .trim().split('\n').map(line => JSON.parse(line)).at(-1);
    assert.deepEqual(event.preserved_cleanup_debt, debt);
    assert.ok(event.queue_transitions.every(row => !['close', 'closed', 'resolve', 'resolved'].includes(row.transition)));
  }
});

test('history argument rejects negative, malformed and unknown forms before any fixture mutation', t => {
  const bad = [
    ['--scan', '--preserve-history=false'], ['--scan', '--preserve-history', 'false'],
    ['--scan', '--preserve-history', '--preserve-history'], ['--scan', '--preserveHistory'],
    ['--scan', '--preserve_history'], ['--scan', '--no-preserve-history'],
    ['--scan', '--preserve-histroy'], ['--scan', '--preserve-history', '--unknown-option=value'],
    ['--scan', '--preserve-history', '--state-root']
  ];
  for (const args of bad) {
    const f = fixture(t), before = snapshotTree(f.root);
    const result = run(f, args);
    assert.notEqual(result.status, 0, args.join(' '));
    assert.match(result.stderr, /Invalid --preserve-history invocation/, args.join(' '));
    assert.deepEqual(snapshotTree(f.root), before, args.join(' '));
  }
  assert.deepEqual(preserveHistoryRequest([]), { preserveHistory: true, requested: null });
  assert.deepEqual(preserveHistoryRequest(['--scan', '--preserve-history']), { preserveHistory: true, requested: '--preserve-history' });
});

test('queue pair transaction rolls forward both exact outputs after a paired fault', t => {
  const root = fs.mkdtempSync(path.join(ownedParent, 'pair-fault-'));
  t.after(() => { assert.ok(fs.realpathSync.native(root).startsWith(fs.realpathSync.native(ownedParent) + path.sep)); fs.rmSync(root, { recursive: true, force: false }); });
  const state = path.join(root, '.knowledge'), stalePath = path.join(state, 'maintenance/stale_items.json'), repairPath = path.join(state, 'maintenance/repair_queue.json');
  write(stalePath, { items: [{ id: 'before-stale' }] });
  write(repairPath, { queue: [{ id: 'before-repair' }] });
  const staleSnapshot = readQueueSnapshot(state, stalePath, { items: [] });
  const repairSnapshot = readQueueSnapshot(state, repairPath, { queue: [] });
  const transactionId = 'sync-pair-fault';
  assert.throws(() => commitQueuePair({ stateRoot: state, stalePath, repairPath, staleSnapshot, repairSnapshot,
    staleItems: { items: [{ id: 'after-stale' }] }, repairQueue: { queue: [{ id: 'after-repair' }] },
    transactionId, faultAt: 'after_promote_0' }), error => error.code === 'transaction_fault_injected');
  const transactionRoot = path.join(state, 'maintenance/transactions', transactionId);
  const policy = { allowedGuardRoots: [state], allowedWriteRoots: [state], exactWritePaths: [stalePath, repairPath] };
  const inspected = transaction.inspectTransaction(transactionRoot, policy);
  assert.deepEqual(inspected.manifest.intent.guards.map(row => row.target).sort(), [stalePath, repairPath].sort());
  const boundPolicy = { ...policy, expectedTransactionId: inspected.manifest.transaction_id,
    expectedIntentSha256: inspected.manifest.intent_sha256, expectedManifestSha256: inspected.manifest_sha256 };
  assert.equal(transaction.recoverOne(transactionRoot, boundPolicy).status, 'committed');
  assert.deepEqual(JSON.parse(fs.readFileSync(stalePath, 'utf8')), { items: [{ id: 'after-stale' }] });
  assert.deepEqual(JSON.parse(fs.readFileSync(repairPath, 'utf8')), { queue: [{ id: 'after-repair' }] });
});

test('queue pair read guard detects CAS drift before it changes the companion output', t => {
  const root = fs.mkdtempSync(path.join(ownedParent, 'pair-cas-'));
  t.after(() => { assert.ok(fs.realpathSync.native(root).startsWith(fs.realpathSync.native(ownedParent) + path.sep)); fs.rmSync(root, { recursive: true, force: false }); });
  const state = path.join(root, '.knowledge'), stalePath = path.join(state, 'maintenance/stale_items.json'), repairPath = path.join(state, 'maintenance/repair_queue.json');
  write(stalePath, { items: [{ id: 'before-stale' }] });
  write(repairPath, { queue: [{ id: 'before-repair' }] });
  const staleSnapshot = readQueueSnapshot(state, stalePath, { items: [] });
  const repairSnapshot = readQueueSnapshot(state, repairPath, { queue: [] });
  const external = { items: [{ id: 'external-stale' }] };
  write(stalePath, external);
  assert.throws(() => commitQueuePair({ stateRoot: state, stalePath, repairPath, staleSnapshot, repairSnapshot,
    staleItems: { items: [{ id: 'candidate-stale' }] }, repairQueue: { queue: [{ id: 'candidate-repair' }] },
    transactionId: 'sync-pair-cas' }), error => error.code === 'transaction_guard_drift');
  assert.deepEqual(JSON.parse(fs.readFileSync(stalePath, 'utf8')), external);
  assert.deepEqual(JSON.parse(fs.readFileSync(repairPath, 'utf8')), { queue: [{ id: 'before-repair' }] });
});

test('history helpers reject hostile raw input before getters or proxy traps', () => {
  let calls=0;
  const hostile={};Object.defineProperty(hostile,'stateRoot',{enumerable:true,get(){calls++;throw Error('getter');}});
  assert.throws(()=>commitQueuePair(hostile),error=>error.code==='transaction_input_invalid');
  assert.throws(()=>readQueueSnapshot('.', 'absent.json',hostile),error=>error.code==='transaction_input_invalid');
  const proxy=new Proxy([],{get(){calls++;throw Error('proxy');}});
  assert.throws(()=>preserveHistoryRequest(proxy),error=>error.code==='transaction_input_invalid');
  assert.equal(calls,0);
});
