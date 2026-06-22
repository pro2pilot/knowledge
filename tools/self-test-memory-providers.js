#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { checkPythonModule, discoverPython } = require('./lib/python-discovery');
const mem0Main = require('./memory-mem0');

const systemRoot = path.resolve(__dirname, '..');
const keepTemp = process.argv.includes('--keep-temp');
let rootForCleanup = null;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runNode(script, args = [], options = {}) {
  const res = spawnSync(process.execPath, [script, ...args], {
    cwd: options.cwd || systemRoot,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 20000
  });
  return res;
}

function parseJson(res, label) {
  assert(res.status === 0, `${label} failed\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
  try { return JSON.parse((res.stdout || '').trim()); }
  catch (error) { throw new Error(`${label} did not return JSON: ${error.message}\n${res.stdout}`); }
}

function expectFail(res, label) {
  assert(res.status !== 0, `${label} should have failed`);
  const text = `${res.stdout}\n${res.stderr}`;
  return text;
}

function baseArgs(project, state) {
  return [
    '--project-knowledge-root', systemRoot,
    '--system-root', systemRoot,
    '--target-root', project,
    '--state-root', state
  ];
}

function memoryCli(project, state, args = [], options = {}) {
  return runNode(path.join(systemRoot, 'tools', 'memory-provider.js'), [...args, ...baseArgs(project, state)], options);
}

function mem0Cli(project, state, args = [], options = {}) {
  return runNode(path.join(systemRoot, 'tools', 'memory-mem0.js'), [...args, ...baseArgs(project, state)], options);
}

function pineconeCli(project, state, args = [], options = {}) {
  return runNode(path.join(systemRoot, 'tools', 'memory-pinecone.js'), [...args, ...baseArgs(project, state)], options);
}

function inspector(project, state) {
  return runNode(path.join(systemRoot, 'tools', 'build-visual-inspector.js'), ['--json', ...baseArgs(project, state)]);
}

function testPythonDiscovery(root) {
  const fakePython = path.join(root, 'fake-bin', 'python.exe');
  const explicitBad = path.join(root, 'missing-python', 'python.exe');
  const explicitPrecedence = discoverPython({
    candidates: [
      { command: explicitBad, source: 'cli --python', explicit: true },
      { command: 'python', source: 'path_command' }
    ],
    validateCandidate: (candidate) => candidate.explicit
      ? { ...candidate, status: 'not_found', diagnostic_code: 'python_not_found', error: 'missing explicit python' }
      : { ...candidate, status: 'ok', diagnostic_code: 'python_available', executable: fakePython, version: '3.11.0' }
  });
  assert(explicitPrecedence.status === 'not_found', 'bad explicit --python should not silently fall back to PATH');
  assert(explicitPrecedence.candidates_checked === 1, 'explicit --python should stop discovery after its own failure');
  assert(explicitPrecedence.diagnostic_code === 'python_not_found', 'explicit --python failure diagnostic mismatch');

  const pathDiscovery = discoverPython({
    candidates: [{ command: 'python', source: 'path_command' }],
    validateCandidate: (candidate) => ({
      ...candidate,
      status: 'ok',
      diagnostic_code: 'python_available',
      executable: fakePython,
      version: '3.11.0'
    })
  });
  assert(pathDiscovery.status === 'found', 'fake PATH python was not selected');
  assert(pathDiscovery.selected.executable === fakePython, 'fake PATH python selected path mismatch');

  const none = discoverPython({
    candidates: [{ command: 'python', source: 'path_command' }],
    validateCandidate: (candidate) => ({
      ...candidate,
      status: 'not_found',
      diagnostic_code: 'python_not_found',
      error: 'not found'
    })
  });
  assert(none.status === 'not_found', 'missing Python discovery should report not_found');
  assert((none.next_commands || []).some((command) => command.includes('--python')), 'missing Python discovery should return actionable --python command');
  assert(!JSON.stringify(none).includes('spawnSync python'), 'missing Python discovery leaked raw spawnSync wording');

  const timedOut = discoverPython({
    candidates: [{ command: 'python', source: 'path_command' }],
    validateCandidate: (candidate) => ({
      ...candidate,
      status: 'error',
      diagnostic_code: 'python_timeout',
      error: 'candidate command timed out'
    })
  });
  assert(timedOut.diagnostic_code === 'python_timeout', 'Python discovery timeout diagnostic mismatch');

  const moduleTimeout = checkPythonModule(fakePython, 'mem0', {
    runCommand: () => ({ error: Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' }) })
  });
  assert(moduleTimeout.diagnostic_code === 'python_timeout', 'Mem0 import timeout diagnostic mismatch');

  assert(mem0Main.__test.normalizeDiagnosticCode('python_invalid') === 'python_not_usable', 'python_invalid should normalize to python_not_usable at Mem0 boundary');
  assert(mem0Main.__test.liveImportOptions({ pythonTimeoutMs: '30000' }, { op: 'health' }).timeoutMs === 30000, '--python-timeout-ms alias should set Python timeout');
  assert(mem0Main.__test.liveImportOptions({ pythonTimeMs: '30000' }, { op: 'health' }).timeoutMs === 30000, '--pythonTimeMs alias should set Python timeout');
  assert(mem0Main.__test.liveMem0TimeoutMs({ timeoutMs: '45000', pythonTimeMs: '30000' }, { op: 'health' }) === 45000, '--timeout-ms should control total live health wait');

  const qdrantLock = mem0Main.__test.classifyMem0RuntimeFailure({
    ok: false,
    error: '[Errno 13] Permission denied: /tmp/qdrant/.lock'
  });
  assert(qdrantLock?.diagnostic_code === 'mem0_storage_permission_error', 'qdrant lock permission error diagnostic mismatch');
  assert((qdrantLock.next_commands || []).some((command) => /writable persistent storage/i.test(command)), 'qdrant lock diagnostic should include storage next command');
}

function main() {
  const cyrillic = '\u043f\u0430\u043c\u044f\u0442\u044c';
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `knowledge memory providers ${cyrillic} `));
  rootForCleanup = root;
  const project = path.join(root, 'repo with spaces');
  const state = path.join(root, 'state root');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });

  const list = parseJson(memoryCli(project, state, ['list', '--json']), 'list');
  assert(list.providers.some((provider) => provider.id === 'mem0-oss'), 'mem0-oss missing from list');
  assert(list.providers.some((provider) => provider.id === 'pinecone'), 'pinecone missing from list');

  const preview = parseJson(memoryCli(project, state, ['preview', 'mem0-oss', '--json']), 'preview mem0');
  assert(preview.provider_id === 'mem0-oss', 'preview returned wrong provider');
  assert(!fs.existsSync(path.join(state, 'external_memory', 'mem0', 'install_receipt.json')), 'preview wrote install receipt');

  const denied = expectFail(memoryCli(project, state, ['install', 'mem0-oss', '--version', 'mem0ai==2.0.4', '--json']), 'install without confirmation');
  assert(/yes-i-reviewed-license/i.test(denied), 'install failure did not mention confirmation flag');

  const install = parseJson(memoryCli(project, state, ['install', 'mem0-oss', '--version', 'mem0ai==2.0.4', '--yes-i-reviewed-license', '--json']), 'install receipt');
  assert(install.installed === false, 'install receipt must not claim Mem0 installed');
  const receiptPath = path.join(state, 'external_memory', 'mem0', 'install_receipt.json');
  assert(fs.existsSync(receiptPath), 'install receipt missing');
  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  assert(receipt.version === 'mem0ai==2.0.4', 'receipt version pin mismatch');
  assert(receipt.install_executed === false, 'receipt should say install was not executed');

  const status = parseJson(memoryCli(project, state, ['status', 'mem0-oss', '--json']), 'status mem0');
  assert(status.provider_id === 'mem0-oss', 'status provider mismatch');
  assert(status.status === 'runtime_not_installed', 'Mem0 status should not claim live runtime install');
  assert(status.runtime_health === 'not_available', 'Mem0 runtime health should be honest before install');
  assert(status.source_of_truth === false && status.trust_effect === 'advisory_only', 'external memory trust policy changed');

  const health = parseJson(mem0Cli(project, state, ['health', '--json']), 'mem0 health');
  assert(health.status === 'runtime_not_installed' && health.live_runtime_checked === false, 'Mem0 health should not claim live runtime');
  assert(health.source_of_truth === false && health.trust_effect === 'advisory_only', 'Mem0 health violated advisory-only envelope');
  assert(health.secrets_redacted === true, 'Mem0 health should keep secrets_redacted as boolean true');

  const missingPython = path.join(root, 'missing-python', 'python.exe');
  const liveMissing = parseJson(mem0Cli(project, state, ['health', '--adapter', 'live', '--python', missingPython, '--json']), 'mem0 live missing python');
  assert(liveMissing.status === 'runtime_not_installed', 'Mem0 live missing Python should stay runtime_not_installed');
  assert(liveMissing.diagnostic_code === 'python_not_found', 'Mem0 live missing Python diagnostic mismatch');
  assert(liveMissing.selected_python === null, 'Mem0 live missing Python should not select an interpreter');
  assert((liveMissing.next_commands || []).some((command) => command.includes('--python')), 'Mem0 live missing Python should return --python next command');
  assert(!JSON.stringify(liveMissing).includes('spawnSync python'), 'Mem0 live missing Python leaked raw spawnSync wording');

  const liveAuto = parseJson(mem0Cli(project, state, ['health', '--adapter', 'live', '--json']), 'mem0 live auto health');
  assert(liveAuto.live_runtime_checked === true, 'Mem0 live auto health should mark live runtime checked');
  assert(['python_not_found', 'python_permission_error', 'python_timeout', 'python_not_usable', 'mem0_package_missing', 'mem0_available', 'mem0_runtime_error', 'python_runtime_error', 'mem0_storage_permission_error'].includes(liveAuto.diagnostic_code), 'Mem0 live auto health diagnostic code unexpected');
  if (liveAuto.diagnostic_code === 'mem0_package_missing') {
    assert((liveAuto.next_commands || []).some((command) => command.includes('-m pip install mem0ai==2.0.4')), 'Mem0 missing package should include pinned pip command');
  }
  assert(!JSON.stringify(liveAuto).includes('spawnSync python'), 'Mem0 live auto health leaked raw spawnSync wording');

  testPythonDiscovery(root);

  const dryAdd = parseJson(mem0Cli(project, state, ['add', '--text', 'dry run memory', '--scope', 'repo', '--json']), 'mem0 dry add');
  assert(dryAdd.persisted === false && dryAdd.dry_run === true, 'Mem0 dry add should not persist by default');

  const testAdd = parseJson(mem0Cli(project, state, ['add', '--adapter', 'test', '--text', 'billing code says invoices are optional', '--scope', 'repo', '--json']), 'mem0 test add');
  assert(testAdd.persisted === true && testAdd.record?.id, 'Mem0 test adapter add did not persist advisory record');
  const search = parseJson(mem0Cli(project, state, ['search', 'invoices', '--adapter', 'test', '--json']), 'mem0 test search');
  assert(search.results.length === 1, 'Mem0 test adapter search did not find advisory record');
  const listed = parseJson(mem0Cli(project, state, ['list', '--adapter', 'test', '--json']), 'mem0 test list');
  assert(listed.records.length === 1, 'Mem0 test adapter list did not return advisory record');
  const exported = parseJson(mem0Cli(project, state, ['export-redacted', '--adapter', 'test', '--json']), 'mem0 export redacted');
  assert(!JSON.stringify(exported).includes('billing code says invoices are optional'), 'Mem0 redacted export leaked memory text');
  const deleted = parseJson(mem0Cli(project, state, ['delete', '--adapter', 'test', '--id', testAdd.record.id, '--json']), 'mem0 test delete');
  assert(deleted.deleted === true, 'Mem0 test adapter delete did not mark record deleted');

  const updateDenied = expectFail(memoryCli(project, state, ['update', 'mem0-oss', '--yes-i-reviewed-license', '--json']), 'update without version');
  assert(/explicit version/i.test(updateDenied), 'update failure did not require explicit version');

  const dataFile = path.join(state, 'external_memory', 'mem0', 'memory.db');
  fs.writeFileSync(dataFile, 'do not delete\n', 'utf8');
  const uninstall = parseJson(memoryCli(project, state, ['uninstall', 'mem0-oss', '--json']), 'uninstall mem0');
  assert(uninstall.data_deleted === false, 'uninstall should preserve data by default');
  assert(fs.existsSync(dataFile), 'uninstall deleted data without --delete-data');

  const pinecone = parseJson(memoryCli(project, state, ['status', 'pinecone', '--json'], {
    env: { PINECONE_MODE: 'local', PINECONE_HOST: 'http://localhost:9999', PINECONE_API_KEY: 'fake-pinecone-secret-value-that-must-not-leak' }
  }), 'pinecone status');
  assert(pinecone.mode === 'local', 'pinecone local mode not detected');
  assert(!JSON.stringify(pinecone).includes('fake-pinecone-secret-value-that-must-not-leak'), 'pinecone status leaked API key');
  assert(pinecone.adapter_command === 'node .knowledge/tools/memory-pinecone.js health --json', 'pinecone adapter command missing from status');

  const pineHealth = parseJson(pineconeCli(project, state, ['health', '--json'], {
    env: { PINECONE_MODE: 'local', PINECONE_HOST: 'http://localhost:9999', PINECONE_API_KEY: 'fake-pinecone-secret-value-that-must-not-leak' }
  }), 'pinecone adapter health');
  assert(pineHealth.status === 'available' && pineHealth.network_calls === 'not_run', 'pinecone health should be offline status only');
  assert(pineHealth.secrets_redacted === true && pineHealth.environment.api_key_required === false, 'pinecone adapter health should preserve non-secret booleans');
  assert(!JSON.stringify(pineHealth).includes('fake-pinecone-secret-value-that-must-not-leak'), 'pinecone adapter health leaked API key');

  const pineAdd = parseJson(pineconeCli(project, state, ['add', '--text', 'adapter smoke memory', '--metadata-json', '{"source_of_truth":true}', '--json'], {
    env: { PINECONE_MODE: 'local', PINECONE_HOST: 'http://localhost:9999' }
  }), 'pinecone adapter dry add');
  assert(pineAdd.dry_run === true && pineAdd.persisted === false, 'pinecone add should dry-run by default');
  assert(pineAdd.record?.source_of_truth === false && pineAdd.record?.trust_effect === 'advisory_only', 'pinecone add record violated advisory policy');
  assert((pineAdd.warnings || []).some((warning) => /source_of_truth override/i.test(warning)), 'pinecone add did not report trust override block');

  const pineSearch = parseJson(pineconeCli(project, state, ['search', 'adapter', '--json'], {
    env: { PINECONE_MODE: 'local', PINECONE_HOST: 'http://localhost:9999' }
  }), 'pinecone adapter dry search');
  assert(pineSearch.dry_run === true && pineSearch.last_retrieval_count === 0, 'pinecone search should dry-run by default');

  const legacyDir = path.join(state, 'external_memory', 'claude_mem');
  fs.mkdirSync(legacyDir, { recursive: true });
  const migrated = parseJson(memoryCli(project, state, ['migrate-legacy', '--json']), 'migrate legacy');
  assert(migrated.legacy_found >= 1, 'legacy Claude MEM state not detected');
  assert(fs.existsSync(path.join(legacyDir, 'DEPRECATED.md')), 'legacy deprecation note missing');

  const all = parseJson(memoryCli(project, state, ['status-all', '--json']), 'status-all');
  assert(all.recommended_provider === 'mem0-oss', 'recommended provider mismatch');
  assert(all.source_of_truth_policy.external_memory_can_raise_trust === false, 'external memory can raise trust');
  assert(all.source_of_truth_policy.external_memory_can_execute_actions === false, 'external memory can execute actions');
  assert(all.metrics.provider_count >= 2, 'memory metrics provider count missing');
  assert(all.live_checks.network_calls === 'not_run', 'status-all should not run network checks');
  assert(all.live_checks.adapter_live_calls_require_explicit_command === true, 'live adapter calls should require explicit command');

  const insp = parseJson(inspector(project, state), 'build inspector');
  assert((insp.features || []).includes('memory_provider_cards'), 'inspector did not report memory provider cards');
  const html = fs.readFileSync(path.join(state, 'inspector', 'index.html'), 'utf8');
  assert(/Memory Providers/.test(html), 'inspector missing Memory Providers label');
  assert(/Mem0 OSS/.test(html), 'inspector missing Mem0 card');

  const teamRoot = path.join(root, 'team root');
  const team = parseJson(runNode(path.join(systemRoot, 'tools', 'memory-provider.js'), [
    'status-all',
    '--json',
    '--mode', 'team',
    '--team-root', teamRoot,
    '--workspace-id', 'ws-memory',
    '--agent-id', 'agent-memory',
    '--target-root', project,
    '--project-knowledge-root', systemRoot,
    '--system-root', systemRoot
  ]), 'team status-all');
  assert(team.mode === 'team', 'team mode status did not run in team mode');
  assert(team.state_root.includes('ws-memory'), 'team stateRoot did not include workspace id');

  const packaged = parseJson(runNode(path.join(systemRoot, 'tools', 'package-release.js'), ['--json']), 'package release');
  const validated = parseJson(runNode(path.join(systemRoot, 'tools', 'validate-release-artifact.js'), [packaged.output_path, '--json']), 'validate release artifact');
  assert(validated.status === 'ok', 'release artifact validation failed');
  const zipScan = spawnSync(process.execPath, ['-e', `
const fs=require('fs'),zlib=require('zlib');
const b=fs.readFileSync(process.argv[1]);
let p=-1; for(let i=b.length-22;i>=0;i--){ if(b.readUInt32LE(i)===0x06054b50){p=i;break;} }
const n=b.readUInt16LE(p+10); let ptr=b.readUInt32LE(p+16); const names=[];
for(let i=0;i<n;i++){ const nl=b.readUInt16LE(ptr+28),el=b.readUInt16LE(ptr+30),cl=b.readUInt16LE(ptr+32); names.push(b.slice(ptr+46,ptr+46+nl).toString('utf8')); ptr+=46+nl+el+cl; }
console.log(JSON.stringify(names.filter((name)=>/graphiti|zep/i.test(name))));
`, packaged.output_path], { encoding: 'utf8', windowsHide: true });
  assert(zipScan.status === 0, 'zip scan failed');
  const proNames = JSON.parse((zipScan.stdout || '[]').trim());
  assert(proNames.length === 0, 'Graphiti/Zep pro provider files leaked into free release artifact');

  const result = {
    schema_version: '3.2.0',
    status: 'pass',
    temp_root: keepTemp ? root : null,
    temp_root_cleaned: !keepTemp,
    checks: [
      'list returns Mem0 and Pinecone',
      'preview writes no receipt',
      'install refuses without license confirmation',
      'install records receipt without claiming package install',
      'Mem0 runtime health reports runtime_not_installed without live checks',
      'Mem0 live health uses bounded Python discovery diagnostics',
      'Mem0 dry-run add does not persist',
      'Mem0 test adapter add/search/list/delete works without production claim',
      'Mem0 export-redacted omits memory content',
      'update requires explicit pinned version',
      'uninstall preserves data by default',
      'pinecone local status redacts API key',
      'pinecone adapter health/add/search dry-run and redact by default',
      'legacy Claude MEM detected and marked deprecated',
      'external memory cannot raise trust',
      'free release excludes Graphiti/Zep pro providers',
      'Inspector renders Memory Providers cards',
      'repo-local and team stateRoot modes work',
      'paths with spaces and Cyrillic work',
      'status/list/inspector made no network calls'
    ]
  };
  if (!keepTemp) fs.rmSync(root, { recursive: true, force: true });
  console.log(JSON.stringify(result, null, 2));
}

process.on('exit', () => {
  if (!keepTemp && rootForCleanup && fs.existsSync(rootForCleanup)) {
    try { fs.rmSync(rootForCleanup, { recursive: true, force: true }); } catch {}
  }
});

try { main(); }
catch (error) { console.error(error.stack || error.message); process.exit(1); }
