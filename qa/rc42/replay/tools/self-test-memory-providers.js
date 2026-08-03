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
const recipeQualityOnly = process.argv.includes('--recipe-quality-only');
let rootForCleanup = null;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function hasEllipsisCommand(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .some((line) => line === '...' || /^(?:node|python|pip|npm|pnpm|yarn|bun|npx)\b.*\.\.\./i.test(line));
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

  const launcherDiscovery = discoverPython({
    platform: 'win32',
    candidates: [{ command: 'py', args: ['-3.12'], source: 'windows_py_3.12_launcher', from_launcher: true }],
    validateCandidate: (candidate) => ({
      ...candidate,
      status: 'ok',
      diagnostic_code: 'python_available',
      executable: fakePython,
      version: '3.12.10'
    })
  });
  assert(launcherDiscovery.status === 'found' && launcherDiscovery.selected.executable === fakePython, 'Windows py -3.12 launcher candidate should resolve to sys.executable');

  assert(mem0Main.__test.normalizeDiagnosticCode('python_invalid') === 'python_not_usable', 'python_invalid should normalize to python_not_usable at Mem0 boundary');
  assert(mem0Main.__test.normalizeDiagnosticCode('python_not_found') === 'python_missing', 'python_not_found should normalize to python_missing at Mem0 boundary');
  assert(mem0Main.__test.normalizeDiagnosticCode('mem0_package_missing') === 'mem0_runtime_missing', 'mem0_package_missing should normalize to mem0_runtime_missing at Mem0 boundary');
  assert(mem0Main.__test.liveImportOptions({ pythonTimeoutMs: '30000' }, { op: 'health' }).timeoutMs === 30000, '--python-timeout-ms alias should set Python timeout');
  assert(mem0Main.__test.liveImportOptions({ pythonTimeMs: '30000' }, { op: 'health' }).timeoutMs === 30000, '--pythonTimeMs alias should set Python timeout');
  assert(mem0Main.__test.liveMem0TimeoutMs({ timeoutMs: '45000', pythonTimeMs: '30000' }, { op: 'health' }) === 45000, '--timeout-ms should control total live health wait');
  assert(mem0Main.__test.liveMem0TimeoutMs({}, { op: 'list' }) === 30000, 'live list should allow slow Mem0/Qdrant startup by default');
  const liveConfigContext = { projectKnowledgeRoot: systemRoot, stateRoot: path.join(root, 'no-config-state') };
  assert(mem0Main.__test.hasExplicitLiveConfig({}, liveConfigContext) === false, 'live Mem0 operations should not treat missing config as usable');
  assert(mem0Main.__test.hasExplicitLiveConfig({ configJson: '{}' }, liveConfigContext) === false, 'empty live Mem0 config JSON should not be usable');
  assert(mem0Main.__test.hasExplicitLiveConfig({ configJson: '{"embedder":{"provider":"openai"}}' }, liveConfigContext) === true, 'non-empty live Mem0 config JSON should be usable');
  const explicitMem0Config = path.join(root, 'mem0-config.json');
  fs.writeFileSync(explicitMem0Config, JSON.stringify({ embedder: { provider: 'fastembed' }, vector_store: { provider: 'qdrant' } }), 'utf8');
  assert(mem0Main.__test.hasExplicitLiveConfig({ config: explicitMem0Config }, liveConfigContext) === true, 'explicit live Mem0 config file should be usable');
  assert(mem0Main.__test.hasExplicitLiveConfig({ config: path.join(root, 'missing-mem0-config.json') }, liveConfigContext) === false, 'missing explicit live Mem0 config file should not be usable');

  const qdrantLock = mem0Main.__test.classifyMem0RuntimeFailure({
    ok: false,
    error: '[Errno 13] Permission denied: /tmp/qdrant/.lock'
  });
  assert(qdrantLock?.diagnostic_code === 'qdrant_path_permission_denied', 'qdrant lock permission error diagnostic mismatch');
  assert(!(qdrantLock.next_commands || []).some((command) => /setup mem0-oss --live/i.test(command)), 'qdrant lock diagnostic must not suggest generic setup as a storage repair');
  assert((qdrantLock.next_commands || []).some((command) => /Do not silently move shared Mem0 provider storage/i.test(command)), 'qdrant lock diagnostic should preserve shared/project-local boundary');
  assert((qdrantLock.next_commands || []).some((command) => /--provider-scope project/i.test(command)), 'qdrant lock diagnostic should make project-local storage explicit');
  const embeddingNetwork = mem0Main.__test.classifyMem0RuntimeFailure({ ok: false, error: 'Connection error.' }, {}, { op: 'remember' });
  assert(embeddingNetwork?.diagnostic_code === 'embedding_provider_network_error', 'embedding provider network error diagnostic mismatch');
  const fastEmbedOnnx = mem0Main.__test.classifyMem0RuntimeFailure({
    ok: false,
    error: 'ONNXRuntimeError: external data path validation failed for model.onnx_data; allowed directory is blobs'
  }, {}, { op: 'list' }, fakePython);
  assert(fastEmbedOnnx?.diagnostic_code === 'fastembed_onnx_external_data_path_error', 'FastEmbed ONNX external data diagnostic mismatch');
  assert((fastEmbedOnnx.next_commands || []).some((command) => /fastembed==0\.5\.1/.test(command)), 'FastEmbed ONNX diagnostic should return pinned FastEmbed install command');
  assert(/model-cache issue/i.test(fastEmbedOnnx.diagnostic_message || ''), 'FastEmbed ONNX diagnostic should explain runtime/cache boundary');
  const fastEmbedDownloadTimeout = mem0Main.__test.classifyMem0RuntimeFailure({
    ok: false,
    error: 'Live Mem0 Python command timed out.'
  }, {
    stderr: [
      'Fetching 6 files:   0%|          | 0/6 [00:00<?, ?it/s]',
      'Authentication token is not provided. Higher rate limits are available if you authenticate with Hugging Face.'
    ].join('\n')
  }, { op: 'list' }, fakePython);
  assert(fastEmbedDownloadTimeout?.diagnostic_code === 'fastembed_model_download_timeout', 'FastEmbed model download timeout should not be classified as quota');
  assert(!/quota/i.test(fastEmbedDownloadTimeout.diagnostic_code), 'FastEmbed model download timeout leaked quota diagnostic');
  assert((fastEmbedDownloadTimeout.next_commands || []).some((command) => /--timeout-ms 300000/.test(command)), 'FastEmbed download timeout should suggest a longer explicit live timeout');
  const runtimeContext = { projectKnowledgeRoot: systemRoot };
  const embeddingSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'remember',
    status: 'error',
    diagnostic_code: 'embedding_provider_network_error',
    selected_python: fakePython,
    raw: { version: '2.0.4' },
    network_calls: 'may_call_embedding_provider'
  }, runtimeContext, { operation: 'health', checked_at: '2026-01-01T00:00:00.000Z' });
  assert(embeddingSnapshot.runtime_available === true && embeddingSnapshot.package_installed === true, 'embedding provider errors must not clear Mem0 runtime cache');
  assert(embeddingSnapshot.runtime_health === 'ok' && embeddingSnapshot.expected_version === '2.0.4', 'embedding provider error cache should preserve runtime health and expected version');
  assert(embeddingSnapshot.last_live_health_check === '2026-01-01T00:00:00.000Z', 'embedding provider error cache should preserve last live health timestamp');
  const fastEmbedOnnxSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'list',
    status: 'error',
    diagnostic_code: 'fastembed_onnx_external_data_path_error',
    selected_python: fakePython,
    raw: { version: '2.0.4' },
    network_calls: 'not_run_local_qdrant'
  }, runtimeContext, { operation: 'health', checked_at: '2026-01-01T00:00:00.000Z' });
  assert(fastEmbedOnnxSnapshot.runtime_available === true && fastEmbedOnnxSnapshot.package_installed === true, 'FastEmbed ONNX model-cache errors must not clear Mem0 runtime cache');
  assert(fastEmbedOnnxSnapshot.runtime_health === 'ok', 'FastEmbed ONNX model-cache errors should preserve runtime health');
  const fastEmbedDownloadSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'list',
    status: 'error',
    diagnostic_code: 'fastembed_model_download_timeout',
    selected_python: fakePython,
    raw: { version: '2.0.4' },
    network_calls: 'not_run_local_qdrant_may_download_local_fastembed_model'
  }, runtimeContext, { operation: 'health', checked_at: '2026-01-01T00:00:00.000Z' });
  assert(fastEmbedDownloadSnapshot.runtime_available === true && fastEmbedDownloadSnapshot.package_installed === true, 'FastEmbed model download timeout must not clear Mem0 runtime cache');
  const qdrantBlockedSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'list',
    status: 'storage_unavailable',
    diagnostic_code: 'qdrant_path_permission_denied',
    selected_python: fakePython,
    raw: { version: '2.0.4' },
    network_calls: 'not_run_local_qdrant'
  }, runtimeContext, { operation: 'health', checked_at: '2026-01-01T00:00:00.000Z' });
  assert(qdrantBlockedSnapshot.runtime_available === true && qdrantBlockedSnapshot.package_installed === true, 'Qdrant storage errors must not clear Mem0 runtime cache');
  assert(qdrantBlockedSnapshot.runtime_health === 'storage_unavailable', 'Qdrant storage errors should keep a storage-specific runtime health');
  const liveListSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'list',
    status: 'ok',
    diagnostic_code: 'mem0_available',
    selected_python: fakePython,
    raw: { version: '2.0.4', raw: { results: [{ id: 'a' }, { id: 'b' }] } },
    network_calls: 'not_run_local_qdrant'
  }, runtimeContext);
  assert(liveListSnapshot.records_count === 2, 'live list snapshot should cache records_count from Mem0 results');
  const redactionProbeSecret = ['sk', 'test-secret-that-must-not-leak'].join('-');
  const normalizedLiveRecords = mem0Main.__test.livePublicRecords({
    ok: true,
    raw: {
      raw: {
        results: [
          {
            id: 'live-record-1',
            memory: 'normalized live list memory',
            user_id: 'knowledge-repo',
            metadata: { scope: 'repo', api_key: redactionProbeSecret }
          }
        ]
      }
    }
  }, { include_text: true, user_id: 'knowledge-repo' });
  assert(normalizedLiveRecords.length === 1, 'live list should normalize Mem0 raw.raw.results into top-level records');
  assert(normalizedLiveRecords[0].id === 'live-record-1', 'live list normalized record should expose id without raw traversal');
  assert(normalizedLiveRecords[0].text === 'normalized live list memory', 'live list normalized record should expose text only when requested');
  assert(!JSON.stringify(normalizedLiveRecords).includes(redactionProbeSecret), 'live list normalized record leaked secret-like metadata');
  const normalizedLiveRecordsDataShape = mem0Main.__test.livePublicRecords({
    ok: true,
    raw: {
      raw: {
        result: {
          data: [
            {
              memory_id: 'live-record-2',
              payload: { text: 'legacy live list payload text' }
            }
          ]
        }
      }
    }
  }, { include_text: true });
  assert(normalizedLiveRecordsDataShape.length === 1, 'live list should normalize nested raw.result.data records');
  assert(normalizedLiveRecordsDataShape[0].id === 'live-record-2', 'live list should read legacy memory_id field from nested payloads');
  assert(normalizedLiveRecordsDataShape[0].text === 'legacy live list payload text', 'live list should read text from legacy payload field');
  const liveSearchSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'search',
    status: 'ok',
    query: 'needle',
    diagnostic_code: 'mem0_available',
    selected_python: fakePython,
    raw: { version: '2.0.4', raw: { results: [{ id: 'a' }] } },
    network_calls: 'may_call_embedding_provider'
  }, runtimeContext, liveListSnapshot);
  assert(liveSearchSnapshot.records_count === 2, 'live search snapshot should preserve records_count');
  assert(liveSearchSnapshot.last_retrieval_count === 1, 'live search snapshot should cache last_retrieval_count');
  assert(liveSearchSnapshot.last_retrieval_query === 'needle', 'live search snapshot should cache last_retrieval_query');
  const liveRememberSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'remember',
    status: 'ok',
    persisted: true,
    diagnostic_code: 'mem0_available',
    selected_python: fakePython,
    raw: { version: '2.0.4', raw: { results: [{ id: 'c' }] } },
    network_calls: 'may_call_embedding_provider'
  }, runtimeContext, liveListSnapshot);
  assert(liveRememberSnapshot.records_count === 3, 'live remember snapshot should increment known records_count');
  const liveForgetSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'forget',
    status: 'ok',
    deleted: true,
    diagnostic_code: 'mem0_available',
    selected_python: fakePython,
    raw: { version: '2.0.4' },
    network_calls: 'not_run_local_qdrant'
  }, runtimeContext, liveRememberSnapshot);
  assert(liveForgetSnapshot.records_count === 2, 'live forget snapshot should decrement known records_count');
  const missingPythonSnapshot = mem0Main.__test.runtimeStatusSnapshot({
    operation: 'remember',
    status: 'error',
    diagnostic_code: 'python_missing',
    selected_python: null,
    raw: {},
    network_calls: 'not_run'
  }, runtimeContext);
  assert(missingPythonSnapshot.runtime_available === false && missingPythonSnapshot.package_installed === false, 'missing Python must keep runtime unavailable');
  const shutdownNoise = [
    'Exception ignored in: <function QdrantClient.__del__ at 0x0000000000000000>',
    'Traceback (most recent call last):',
    '  File "C:\\Python\\Lib\\site-packages\\qdrant_client\\qdrant_client.py", line 169, in __del__',
    '  File "C:\\Python\\Lib\\site-packages\\qdrant_client\\local\\qdrant_local.py", line 85, in close',
    'ImportError: sys.meta_path is None, Python is likely shutting down'
  ].join('\n');
  assert(mem0Main.__test.filterSafeStderr(shutdownNoise) === '', 'safe Qdrant shutdown noise should be filtered');
  assert(mem0Main.__test.filterSafeStderr("Xet Storage is enabled for this repo, but the 'hf_xet' package is not installed. Falling back to regular HTTP download.") === '', 'safe HuggingFace hf_xet fallback warning should be filtered');
  assert(mem0Main.__test.filterSafeStderr('Failed to load spaCy lemma model: spaCy is not installed. Install it with: pip install mem0ai[nlp]') === '', 'optional spaCy warning should be filtered');
  assert(/real write failure/.test(mem0Main.__test.filterSafeStderr(`${shutdownNoise}\nreal write failure`)), 'real stderr after shutdown noise should be preserved');

  const candidateState = path.join(root, 'state selected python');
  const candidateContext = {
    projectKnowledgeRoot: systemRoot,
    stateRoot: candidateState,
    targetRoot: root,
    mode: 'repo'
  };
  const candidateDir = path.join(candidateState, 'external_memory', 'mem0');
  fs.mkdirSync(candidateDir, { recursive: true });
  fs.writeFileSync(path.join(candidateDir, 'runtime_status.json'), JSON.stringify({ selected_python: fakePython }, null, 2), 'utf8');
  const persistedCandidates = mem0Main.__test.configuredPythonCandidates({}, candidateContext);
  assert(persistedCandidates[0]?.command === fakePython, 'Mem0 live discovery should prefer cached selected_python before PATH discovery');
  const configuredPython = path.join(root, 'configured-python', 'python.exe');
  fs.writeFileSync(path.join(candidateDir, 'config.meta.json'), JSON.stringify({ python_runtime: { selected_python: configuredPython } }, null, 2), 'utf8');
  const configuredCandidates = mem0Main.__test.configuredPythonCandidates({}, candidateContext);
  assert(configuredCandidates[0]?.command === configuredPython, 'Mem0 live discovery should prefer config_meta selected_python over stale runtime_status cache');

  const mem0AdapterSource = fs.readFileSync(path.join(systemRoot, 'tools', 'memory-mem0.js'), 'utf8');
  assert(mem0AdapterSource.includes('memory.search(payload.get("query") or "", filters=user_filter(user_id))'), 'Mem0 live search should use Mem0 2.0.4 filters API');
  assert(mem0AdapterSource.includes('memory.get_all(filters=user_filter(user_id))'), 'Mem0 live list should use Mem0 2.0.4 filters API');
  assert(!/memory\.search\([^)]*,\s*user_id=user_id/.test(mem0AdapterSource), 'Mem0 live search must not use old user_id argument API');
  assert(!/memory\.get_all\(user_id=user_id/.test(mem0AdapterSource), 'Mem0 live list must not use old user_id argument API');
}

function assertMem0DocsSearchCoverage(project, state) {
  const env = {
    KNOWLEDGE_SYSTEM_ROOT: systemRoot,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: systemRoot,
    KNOWLEDGE_TARGET_ROOT: project,
    KNOWLEDGE_STATE_ROOT: state
  };
  const build = runNode(path.join(systemRoot, 'tools', 'build-search-index.js'), ['--quiet'], { env, timeout: 30000 });
  assert(build.status === 0, `build-search-index failed for Mem0 docs coverage\nstdout:\n${build.stdout}\nstderr:\n${build.stderr}`);

  const indexPath = path.join(state, 'search', 'index.json');
  assert(fs.existsSync(indexPath), 'search index missing after build-search-index');
  const index = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
  assert(index.schema_version === '3.3.0', 'search index schema_version should follow release version 3.3.0');
  assert((index.counts_by_kind?.external_memory || 0) >= 4, 'search index should count Mem0/external docs as external_memory');

  const byPath = new Map((index.documents || []).map((doc) => [doc.path, doc]));
  const requiredDocs = [
    '.knowledge/docs/mem0-install.md',
    '.knowledge/docs/memory-providers.md',
    '.knowledge/docs/external-memory.md',
    '.knowledge/docs/cookbook/10-mem0-embedding-backends.md',
    '.knowledge/docs/cookbook/11-mem0-project-local-provider.md',
    '.knowledge/docs/cookbook/12-mem0-shared-provider-storage.md'
  ];
  for (const docPath of requiredDocs) {
    const doc = byPath.get(docPath);
    assert(doc, `${docPath} missing from search index`);
    assert(doc.type === 'external_memory', `${docPath} should be indexed as external_memory`);
  }

  const search = parseJson(runNode(path.join(systemRoot, 'tools', 'search-knowledge.js'), [
    'Mem0 install receipt runtime package',
    '--json',
    '--kind=external_memory'
  ], { env, timeout: 20000 }), 'search Mem0 install docs');
  assert((search.results || []).some((doc) => doc.path === '.knowledge/docs/mem0-install.md'), 'local search should find Mem0 install page');
}

function testRecipeQuality(project, state) {
  const recipePath = path.join(systemRoot, 'docs', 'cookbook', '09-mem0-live-memory.md');
  const installDocPath = path.join(systemRoot, 'docs', 'mem0-install.md');
  const original = fs.existsSync(recipePath) ? fs.readFileSync(recipePath, 'utf8') : null;
  try {
    const envConfigPath = path.join(state, 'external_memory', 'mem0', 'config.json');
    const sharedProviderRoot = path.join(path.dirname(state), 'shared mem0 provider');
    const setup = parseJson(memoryCli(project, state, ['setup', 'mem0-oss', '--live', '--python', path.join(project, 'missing-python.exe'), '--json']), 'setup mem0 recipe flow');
    assert(setup.provider_id === 'mem0-oss', 'setup returned wrong provider');
    assert(setup.receipt_present === true, 'setup did not create or reuse receipt');
    assert(setup.setup_status === 'needs_embedding_provider_choice', 'setup without configured embeddings must require provider choice');
    assert(setup.provider_choice_required === true, 'setup should mark embedding provider choice required');
    assert(setup.embedding_provider_question?.required === true, 'setup should return required embedding provider question');
    assert((setup.next_commands || []).some((command) => command.includes('--embedder openai')), 'setup should expose OpenAI configure command');
    assert((setup.next_commands || []).some((command) => command.includes('--embedder fastembed')), 'setup should expose FastEmbed configure command');
    assert(fs.existsSync(path.join(state, 'external_memory', 'mem0', 'install_receipt.json')), 'setup receipt missing from state');
    assert(!fs.existsSync(envConfigPath), 'setup must not silently create an embedding config before user choice');
    assert(setup.agent_facing?.text?.includes('Boundary: advisory-only'), 'setup agent-facing output missing advisory boundary');
    assert(setup.agent_facing?.text?.includes('Do not silently choose'), 'setup agent-facing output missing provider-choice guard');

    const legacyReceiptState = path.join(path.dirname(state), 'state legacy mem0 receipt');
    const legacyReceiptDir = path.join(legacyReceiptState, 'external_memory', 'mem0');
    fs.mkdirSync(legacyReceiptDir, { recursive: true });
    fs.writeFileSync(path.join(legacyReceiptDir, 'install_receipt.json'), JSON.stringify({
      schema_version: '3.2.4',
      provider_id: 'mem0-oss',
      recorded_at: '2026-01-01T00:00:00.000Z',
      version: 'mem0ai==2.0.4',
      install_executed: false,
      source_of_truth: false,
      trust_effect: 'advisory_only'
    }, null, 2), 'utf8');
    const migratedReceiptSetup = parseJson(memoryCli(project, legacyReceiptState, ['setup', 'mem0-oss', '--json']), 'setup mem0 legacy receipt');
    assert(migratedReceiptSetup.receipt_action === 'migrated', 'setup should migrate old Mem0 receipt schema');
    const migratedReceipt = JSON.parse(fs.readFileSync(path.join(legacyReceiptDir, 'install_receipt.json'), 'utf8'));
    assert(migratedReceipt.schema_version === '3.3.0', 'legacy Mem0 receipt schema was not migrated to 3.3.0');
    assert(migratedReceipt.install_executed === false, 'legacy Mem0 receipt migration must not claim an install ran');
    assert(migratedReceipt.source_of_truth === false && migratedReceipt.trust_effect === 'advisory_only', 'legacy Mem0 receipt migration changed trust boundary');

    const providerHelp = parseJson(memoryCli(project, state, ['help', '--json']), 'memory-provider help');
    const providerHelpCommands = new Set((providerHelp.commands || []).map((entry) => entry.name));
    for (const command of ['setup', 'configure-embeddings', 'write-recipe', 'validate-recipe', 'status', 'status-all']) {
      assert(providerHelpCommands.has(command), `memory-provider help missing ${command}`);
    }
    assert(providerHelp.recommended_flow === 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json', 'memory-provider help missing recommended setup flow');

    const mem0Help = parseJson(mem0Cli(project, state, ['help', '--json']), 'memory-mem0 help');
    const mem0HelpCommands = new Set((mem0Help.commands || []).map((entry) => entry.name));
    for (const command of ['health', 'list', 'add', 'search', 'recall']) {
      assert(mem0HelpCommands.has(command), `memory-mem0 help missing ${command}`);
    }
    assert(mem0Help.live_requires_explicit_consent === true, 'memory-mem0 help should disclose live consent boundary');

    const configuredOpenAi = parseJson(memoryCli(project, state, [
      'configure-embeddings', 'mem0-oss',
      '--embedder', 'openai',
      '--model', 'text-embedding-3-small',
      '--shared-provider-root', sharedProviderRoot,
      '--json'
    ]), 'configure OpenAI embeddings');
    assert(configuredOpenAi.ok === true && configuredOpenAi.configuration_written === true, 'OpenAI embedding configure should write config');
    assert(configuredOpenAi.provider_scope === 'shared', 'OpenAI configure should use shared provider storage by default');
    assert(configuredOpenAi.shared_provider_root === sharedProviderRoot, 'OpenAI configure should report shared provider root');
    assert(configuredOpenAi.llm_provider?.provider === 'openai', 'configure output must distinguish LLM provider');
    assert(configuredOpenAi.embedding_provider?.provider === 'openai', 'configure output must distinguish OpenAI embedding provider');
    assert(configuredOpenAi.vector_store?.provider === 'qdrant', 'configure output must distinguish vector store');
    assert(configuredOpenAi.history_store?.provider === 'sqlite', 'configure output must distinguish history store');
    assert(configuredOpenAi.embedding_provider?.dimensions === 1536, 'OpenAI text-embedding-3-small dimensions should be 1536');
    assert(configuredOpenAi.environment_guidance?.windows_powershell?.includes('OPENAI_API_KEY'), 'OpenAI configure should return local terminal env guidance');
    let configuredConfig = JSON.parse(fs.readFileSync(envConfigPath, 'utf8'));
    assert(configuredConfig.embedder?.provider === 'openai', 'OpenAI config should set embedder provider');
    assert(configuredConfig.vector_store?.config?.embedding_model_dims === 1536, 'OpenAI config should set Qdrant dimensions');
    assert(configuredConfig.vector_store?.config?.path.startsWith(sharedProviderRoot), 'OpenAI config should use shared provider storage path');
    assert(!Object.prototype.hasOwnProperty.call(configuredConfig, 'user_id'), 'OpenAI config must not store runtime user_id');
    assert(!/api[_-]?key/i.test(JSON.stringify(configuredConfig)), 'OpenAI config must not store API keys');
    const statusAfterConfigure = parseJson(memoryCli(project, state, ['status', 'mem0-oss', '--json']), 'status mem0 after configure');
    assert(statusAfterConfigure.configured === true, 'Mem0 status should mark provider configured when config.json exists');
    assert(statusAfterConfigure.config_path === '.knowledge/external_memory/mem0/config.json', 'Mem0 status should expose configured config path');
    assert(statusAfterConfigure.provider_scope === 'shared', 'Mem0 status should honor the shared root recorded by configure-embeddings');
    assert(statusAfterConfigure.shared_provider_root === sharedProviderRoot, 'Mem0 status should preserve the configured custom shared root');
    assert(statusAfterConfigure.metadata_scope_mismatch === false, 'custom shared root should not create metadata_scope_mismatch');
    const openAiCollection = configuredOpenAi.vector_store.collection_name;
    const liveEnv = mem0Main.__test.liveProcessEnv({ config: envConfigPath }, { projectKnowledgeRoot: systemRoot });
    assert(path.basename(liveEnv.MEM0_DIR) === 'runtime', 'default MEM0_DIR should use a runtime subdirectory');
    assert(path.dirname(liveEnv.MEM0_DIR) === path.dirname(configuredConfig.vector_store.config.path), 'default MEM0_DIR should follow selected provider storage');
    assert(liveEnv.MEM0_DIR !== path.dirname(envConfigPath), 'default MEM0_DIR must not be the canonical config directory');
    assert(liveEnv.PYTHONUTF8 === '1' && liveEnv.PYTHONIOENCODING === 'utf-8', 'live Python bridge must force deterministic UTF-8 I/O');
    const unicodeLabel = '\u0413\u0440\u0430\u043c\u043c\u0430 \u0444\u0430\u0439\u043b';
    const unicodeRoot = path.dirname(project);
    const unicodeConfigPath = path.join(unicodeRoot, `unicode ${unicodeLabel}`, 'config.json');
    const unicodeQdrantPath = path.join(unicodeRoot, `unicode ${unicodeLabel}`, 'qdrant');
    fs.mkdirSync(path.dirname(unicodeConfigPath), { recursive: true });
    fs.writeFileSync(unicodeConfigPath, JSON.stringify({
      embedder: { provider: 'fastembed', config: { model: 'BAAI/bge-small-en-v1.5', embedding_dims: 384 } },
      vector_store: { provider: 'qdrant', config: { path: unicodeQdrantPath, collection_name: 'unicode_path_smoke', embedding_model_dims: 384 } },
      history_db_path: path.join(unicodeRoot, `unicode ${unicodeLabel}`, 'history.db')
    }), 'utf8');
    const encodedPayload = mem0Main.__test.encodeLivePythonPayload(
      { config: unicodeConfigPath },
      { op: 'remember', text: `memory ${unicodeLabel}` },
      { projectKnowledgeRoot: systemRoot }
    );
    assert(/^[A-Za-z0-9+/=]+$/.test(encodedPayload), 'live Python payload transport must remain ASCII-safe');
    const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString('utf8'));
    const decodedConfig = JSON.parse(decodedPayload.__knowledge_mem0_config_json);
    assert(decodedPayload.text === `memory ${unicodeLabel}`, 'live Python payload lost Unicode memory text');
    assert(decodedConfig.vector_store.config.path === unicodeQdrantPath, 'live Python payload lost Unicode Qdrant path');
    fs.writeFileSync(envConfigPath, JSON.stringify({ ...configuredConfig, user_id: 'runtime-user-id' }, null, 2), 'utf8');
    assert(mem0Main.__test.restoreCanonicalLiveConfig({ config: envConfigPath }, { projectKnowledgeRoot: systemRoot }) === true, 'canonical Mem0 config restore should report runtime-state cleanup');
    const restoredConfig = JSON.parse(fs.readFileSync(envConfigPath, 'utf8'));
    assert(!Object.prototype.hasOwnProperty.call(restoredConfig, 'user_id'), 'canonical Mem0 config restore should remove runtime user_id');
    assert(restoredConfig.vector_store?.config?.path, 'canonical Mem0 config restore should preserve vector store config');

    const setupAfterChoice = parseJson(memoryCli(project, state, ['setup', 'mem0-oss', '--live', '--python', path.join(project, 'missing-python.exe'), '--json']), 'setup mem0 after provider choice');
    assert(setupAfterChoice.setup_status === 'needs_runtime_attention', 'setup after provider choice should proceed to live health and report runtime attention');
    assert(setupAfterChoice.live_checked === true, 'setup after provider choice should run live health when --live is passed');
    assert(setupAfterChoice.live_health?.diagnostic_code === 'python_missing', 'setup after provider choice should report selected Python failure');
    assert(setupAfterChoice.provider_scope === 'shared', 'setup after provider choice should report shared provider scope');
    assert(setupAfterChoice.status?.metadata_scope_mismatch === false, 'setup should keep custom shared root metadata consistent');

    const fastEmbedEnv = {
      KNOWLEDGE_MEMORY_PROVIDER_TEST_FASTEMBED_MODELS_JSON: JSON.stringify([
        {
          model: 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2',
          dim: 384,
          size_in_GB: 0.22
        }
      ])
    };
    const blockedFastEmbed = parseJson(memoryCli(project, state, [
      'configure-embeddings',
      'mem0-oss',
      '--embedder', 'fastembed',
      '--model', 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2',
      '--collection-name', openAiCollection,
      '--json'
    ], { env: fastEmbedEnv }), 'block FastEmbed reuse of OpenAI collection');
    assert(blockedFastEmbed.ok === false && blockedFastEmbed.diagnostic_code === 'collection_reuse_blocked', 'FastEmbed configure should block OpenAI collection reuse');
    configuredConfig = JSON.parse(fs.readFileSync(envConfigPath, 'utf8'));
    assert(configuredConfig.embedder?.provider === 'openai', 'blocked FastEmbed configure must not overwrite existing config');

    const unsupportedFastEmbed = parseJson(memoryCli(project, state, [
      'configure-embeddings',
      'mem0-oss',
      '--embedder', 'fastembed',
      '--model', 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2',
      '--json'
    ], {
      env: {
        ...fastEmbedEnv,
        KNOWLEDGE_MEMORY_PROVIDER_TEST_FASTEMBED_RUNTIME_VERSION: '3.14.6'
      }
    }), 'block unsupported FastEmbed runtime');
    assert(unsupportedFastEmbed.ok === false && unsupportedFastEmbed.diagnostic_code === 'fastembed_runtime_unsupported', 'FastEmbed configure should block unsupported Python runtime before install/smoke');
    assert((unsupportedFastEmbed.next_commands || []).some((command) => /Python 3\.12/i.test(command)), 'unsupported FastEmbed runtime should point to Python 3.12');
    configuredConfig = JSON.parse(fs.readFileSync(envConfigPath, 'utf8'));
    assert(configuredConfig.embedder?.provider === 'openai', 'unsupported FastEmbed runtime must not overwrite existing config');

    const configuredFastEmbed = parseJson(memoryCli(project, state, [
      'configure-embeddings',
      'mem0-oss',
      '--embedder', 'fastembed',
      '--model', 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2',
      '--json'
    ], { env: fastEmbedEnv }), 'configure FastEmbed embeddings');
    assert(configuredFastEmbed.ok === true && configuredFastEmbed.configuration_written === true, 'FastEmbed embedding configure should write config');
    assert(configuredFastEmbed.embedding_provider?.provider === 'fastembed', 'FastEmbed configure output must set embedding provider');
    assert(configuredFastEmbed.embedding_provider?.dimensions === 384, 'FastEmbed configure should use programmatic model dimensions');
    assert(configuredFastEmbed.provider_scope === 'shared', 'FastEmbed configure should preserve shared provider storage by default');
    assert(configuredFastEmbed.vector_store?.collection_name !== openAiCollection, 'FastEmbed configure must create a distinct collection from OpenAI');
    assert((configuredFastEmbed.install_commands || []).includes('python -m pip install fastembed==0.5.1'), 'FastEmbed configure should return pinned install command');
    assert(configuredFastEmbed.smoke_commands?.add && configuredFastEmbed.smoke_commands?.search && configuredFastEmbed.smoke_commands?.recall, 'FastEmbed configure should return add/search/recall smoke commands');
    configuredConfig = JSON.parse(fs.readFileSync(envConfigPath, 'utf8'));
    assert(configuredConfig.embedder?.provider === 'fastembed', 'FastEmbed config should set embedder provider');
    assert(configuredConfig.vector_store?.config?.embedding_model_dims === 384, 'FastEmbed config should set Qdrant dimensions');
    assert(configuredConfig.vector_store?.config?.collection_name !== openAiCollection, 'FastEmbed config should not reuse OpenAI collection');
    assert(!Object.prototype.hasOwnProperty.call(configuredConfig, 'user_id'), 'FastEmbed config must not store runtime user_id');

    const projectLocalState = path.join(path.dirname(state), 'state project local mem0');
    fs.mkdirSync(projectLocalState, { recursive: true });
    const configuredProjectLocal = parseJson(memoryCli(project, projectLocalState, [
      'configure-embeddings', 'mem0-oss',
      '--embedder', 'openai',
      '--model', 'text-embedding-3-small',
      '--provider-scope', 'project',
      '--json'
    ]), 'configure project-local OpenAI embeddings');
    assert(configuredProjectLocal.provider_scope === 'project', 'project-local configure should report project scope');
    assert(configuredProjectLocal.vector_store?.path === '.knowledge/external_memory/mem0/qdrant', 'project-local configure should use repo-local qdrant display path');
    const projectLocalConfig = JSON.parse(fs.readFileSync(path.join(projectLocalState, 'external_memory', 'mem0', 'config.json'), 'utf8'));
    assert(projectLocalConfig.vector_store?.config?.path === path.join(projectLocalState, 'external_memory', 'mem0', 'qdrant'), 'project-local config should store repo-local qdrant path');

    const staleMetaState = path.join(path.dirname(state), 'state stale mem0 scope meta');
    const staleMetaDir = path.join(staleMetaState, 'external_memory', 'mem0');
    fs.mkdirSync(staleMetaDir, { recursive: true });
    fs.writeFileSync(path.join(staleMetaDir, 'config.json'), JSON.stringify({
      llm: { provider: 'openai', config: { model: 'gpt-5-mini' } },
      embedder: { provider: 'fastembed', config: { model: 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2', embedding_dims: 384 } },
      vector_store: {
        provider: 'qdrant',
        config: {
          path: path.join(staleMetaDir, 'qdrant'),
          collection_name: 'knowledge_mem0_fastembed_sentence_transformers_paraphrase_multilingual_minilm_l12_v2_384',
          embedding_model_dims: 384,
          on_disk: false
        }
      },
      history_db_path: path.join(staleMetaDir, 'history.db'),
      version: 'v1.1'
    }, null, 2), 'utf8');
    fs.writeFileSync(path.join(staleMetaDir, 'config.meta.json'), JSON.stringify({
      schema_version: '3.3.0',
      provider_id: 'mem0-oss',
      provider_scope: 'shared',
      shared_provider_root: sharedProviderRoot,
      project_storage_key: 'repo-stale-meta',
      qdrant_path: path.join(staleMetaDir, 'qdrant'),
      history_db_path: path.join(staleMetaDir, 'history.db')
    }, null, 2), 'utf8');
    const staleMetaStatus = parseJson(memoryCli(project, staleMetaState, ['status', 'mem0-oss', '--json']), 'status mem0 with stale scope metadata');
    assert(staleMetaStatus.provider_scope === 'project', 'status must follow actual Qdrant path instead of stale shared metadata');
    assert(staleMetaStatus.metadata_scope_mismatch === true, 'status should flag stale provider scope metadata');
    assert(staleMetaStatus.metadata_provider_scope === 'shared', 'status should expose stale metadata scope for diagnosis');
    assert(staleMetaStatus.path_inferred_provider_scope === 'project', 'status should expose path-inferred provider scope');
    assert(staleMetaStatus.shared_provider_root === null, 'project-local actual path must not be reported as shared root');
    assert((staleMetaStatus.warnings || []).some((warning) => /metadata says provider_scope=shared/i.test(warning)), 'stale scope metadata warning missing');

    const directInstall = parseJson(memoryCli(project, state, ['install', 'mem0-oss', '--version', 'mem0ai==2.0.4', '--yes-i-reviewed-license', '--json']), 'direct install mem0');
    assert(directInstall.agent_facing?.text?.includes('Recommended setup: node .knowledge/tools/memory-provider.js setup mem0-oss --live --json'), 'install agent-facing output missing recommended setup');
    assert(JSON.stringify(directInstall.next_commands || []) === JSON.stringify(['node .knowledge/tools/memory-provider.js setup mem0-oss --live --json']), 'install should expose exactly one recommended next command');
    assert(directInstall.agent_facing?.text?.includes('Boundary: advisory-only'), 'install agent-facing output missing advisory boundary');

    const missingPackageState = path.join(path.dirname(state), 'state missing mem0 package');
    fs.mkdirSync(missingPackageState, { recursive: true });
    parseJson(memoryCli(project, missingPackageState, [
      'configure-embeddings', 'mem0-oss',
      '--embedder', 'openai',
      '--model', 'text-embedding-3-small',
      '--shared-provider-root', path.join(path.dirname(missingPackageState), 'shared mem0 provider'),
      '--json'
    ]), 'configure OpenAI before missing package setup');
    const fakeSelectedPython = path.join(project, 'Python Env', 'python.exe');
    const missingPackageSetup = parseJson(memoryCli(project, missingPackageState, ['setup', 'mem0-oss', '--live', '--python', fakeSelectedPython, '--json'], {
      env: {
        KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: '1',
        KNOWLEDGE_MEMORY_PROVIDER_TEST_FORCE_MEM0_MISSING: '1'
      }
    }), 'setup mem0 missing package');
    assert(missingPackageSetup.setup_status === 'needs_runtime_install', 'setup without mem0ai should request runtime install');
    assert(missingPackageSetup.package_installed === false && missingPackageSetup.runtime_available === false, 'setup without mem0ai must not claim runtime/package install');
    assert(missingPackageSetup.recommended_command === `"${fakeSelectedPython}" -m pip install mem0ai==2.0.4`, 'setup without mem0ai should return exact pinned install command');
    assert(JSON.stringify(missingPackageSetup.next_commands || []) === JSON.stringify([missingPackageSetup.recommended_command]), 'setup without mem0ai should return exactly one next command');
    assert(missingPackageSetup.agent_facing?.text?.includes(`Recommended install: ${missingPackageSetup.recommended_command}`), 'setup without mem0ai agent text missing recommended install command');

    const versionMismatchState = path.join(path.dirname(state), 'state wrong mem0 package');
    fs.mkdirSync(versionMismatchState, { recursive: true });
    parseJson(memoryCli(project, versionMismatchState, [
      'configure-embeddings', 'mem0-oss',
      '--embedder', 'openai',
      '--model', 'text-embedding-3-small',
      '--shared-provider-root', path.join(path.dirname(versionMismatchState), 'shared mem0 provider'),
      '--json'
    ]), 'configure OpenAI before version mismatch setup');
    const versionMismatchSetup = parseJson(memoryCli(project, versionMismatchState, ['setup', 'mem0-oss', '--live', '--python', fakeSelectedPython, '--json'], {
      env: {
        KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: '1',
        KNOWLEDGE_MEMORY_PROVIDER_TEST_FORCE_MEM0_VERSION_MISMATCH: '1',
        KNOWLEDGE_MEMORY_PROVIDER_TEST_MEM0_VERSION: '1.9.0'
      }
    }), 'setup mem0 version mismatch');
    assert(versionMismatchSetup.setup_status === 'needs_runtime_install', 'setup with wrong mem0ai version should request runtime install');
    assert(versionMismatchSetup.package_installed === false && versionMismatchSetup.runtime_available === false, 'setup with wrong mem0ai version must not claim runtime/package install');
    assert(versionMismatchSetup.live_health?.diagnostic_code === 'mem0_version_mismatch', 'setup with wrong mem0ai version diagnostic mismatch');
    assert(versionMismatchSetup.live_health?.version === '1.9.0' && versionMismatchSetup.live_health?.expected_version === '2.0.4', 'setup with wrong mem0ai version should report actual and expected versions');
    assert(versionMismatchSetup.status?.runtime_version === '1.9.0', 'status should expose cached Mem0 runtime version after mismatch');
    assert(versionMismatchSetup.status?.expected_runtime_version === '2.0.4', 'status should expose expected Mem0 runtime version after mismatch');
    assert(versionMismatchSetup.status?.runtime_version_matches_pin === false, 'status should expose Mem0 runtime pin mismatch');
    assert(versionMismatchSetup.recommended_command === `"${fakeSelectedPython}" -m pip install mem0ai==2.0.4`, 'setup with wrong mem0ai version should return exact pinned install command');
    assert(JSON.stringify(versionMismatchSetup.next_commands || []) === JSON.stringify([versionMismatchSetup.recommended_command]), 'setup with wrong mem0ai version should return exactly one next command');

    const missingVersionState = path.join(path.dirname(state), 'state missing mem0 package version');
    fs.mkdirSync(missingVersionState, { recursive: true });
    parseJson(memoryCli(project, missingVersionState, [
      'configure-embeddings', 'mem0-oss',
      '--embedder', 'openai',
      '--model', 'text-embedding-3-small',
      '--shared-provider-root', path.join(path.dirname(missingVersionState), 'shared mem0 provider'),
      '--json'
    ]), 'configure OpenAI before missing version setup');
    const missingVersionSetup = parseJson(memoryCli(project, missingVersionState, ['setup', 'mem0-oss', '--live', '--python', fakeSelectedPython, '--json'], {
      env: {
        KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: '1',
        KNOWLEDGE_MEMORY_PROVIDER_TEST_FORCE_MEM0_VERSION_MISMATCH: '1',
        KNOWLEDGE_MEMORY_PROVIDER_TEST_MEM0_VERSION: '__missing__'
      }
    }), 'setup mem0 missing version');
    assert(missingVersionSetup.setup_status === 'needs_runtime_install', 'setup with missing mem0ai version should request runtime install');
    assert(missingVersionSetup.package_installed === false && missingVersionSetup.runtime_available === false, 'setup with missing mem0ai version must not claim runtime/package install');
    assert(missingVersionSetup.live_health?.diagnostic_code === 'mem0_version_mismatch', 'setup with missing mem0ai version diagnostic mismatch');
    assert(missingVersionSetup.live_health?.version === null && missingVersionSetup.live_health?.expected_version === '2.0.4', 'setup with missing mem0ai version should report missing actual and expected version');
    assert(missingVersionSetup.recommended_command === `"${fakeSelectedPython}" -m pip install mem0ai==2.0.4`, 'setup with missing mem0ai version should return exact pinned install command');
    assert(JSON.stringify(missingVersionSetup.next_commands || []) === JSON.stringify([missingVersionSetup.recommended_command]), 'setup with missing mem0ai version should return exactly one next command');

    const written = parseJson(memoryCli(project, state, ['write-recipe', 'mem0-oss', '--json']), 'write Mem0 recipe');
    assert(written.generated_from_template === true, 'write-recipe should report template generation');
    const first = fs.readFileSync(recipePath, 'utf8');
    const writtenAgain = parseJson(memoryCli(project, state, ['write-recipe', 'mem0-oss', '--json']), 'write Mem0 recipe again');
    assert(writtenAgain.recipe === written.recipe, 'write-recipe path changed');
    const second = fs.readFileSync(recipePath, 'utf8');
    assert(first === second, 'write-recipe output should be deterministic');
    assert(!hasEllipsisCommand(first), 'recipe must not include ellipsis commands');
    assert(first.includes('node .knowledge/tools/memory-provider.js setup mem0-oss --live --json'), 'recipe missing one recommended setup flow');
    assert(first.includes('needs_embedding_provider_choice'), 'recipe missing mandatory embedding provider choice setup status');
    assert(first.includes('must not silently choose OpenAI API or Local FastEmbed'), 'recipe missing no-silent-default policy');
    assert(first.includes('node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json'), 'recipe missing OpenAI embedding configure command');
    assert(first.includes('node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json'), 'recipe missing FastEmbed embedding configure command');
    assert(first.includes('--provider-scope project'), 'recipe missing explicit project-local provider command');
    assert(first.includes('LLM provider') && first.includes('Embedding provider') && first.includes('Vector store') && first.includes('History store'), 'recipe must distinguish provider/store layers');
    assert(first.includes('Local FastEmbed is a regular choice, not an emergency fallback'), 'recipe must present Local FastEmbed as a regular choice');
    assert(first.includes('Never reuse an OpenAI `1536`-dimension collection'), 'recipe missing collection dimension guard');
    assert(first.includes('default provider storage is shared per OS user'), 'recipe missing shared provider storage default');
    assert(first.includes('shared provider root is data storage, not a Python virtualenv'), 'recipe missing shared storage/runtime boundary');
    assert(first.includes('fastembed_onnx_external_data_path_error'), 'recipe missing FastEmbed ONNX diagnostic guidance');
    assert(first.includes('external-memory write'), 'recipe missing live write warning');
    assert(first.includes('source_of_truth: false') && first.includes('trust_effect: advisory_only'), 'recipe missing advisory-only policy');
    assert(first.includes('.knowledge/external_memory/mem0/install_receipt.json'), 'recipe missing canonical receipt path');

    assert(fs.existsSync(installDocPath), 'Mem0 install page is missing');
    const installDoc = fs.readFileSync(installDocPath, 'utf8');
    assert(installDoc.includes('node .knowledge/tools/memory-provider.js setup mem0-oss --live --json'), 'Mem0 install page missing recommended setup flow');
    assert(installDoc.includes('must not silently choose an embedding backend'), 'Mem0 install page missing no-silent-default policy');
    assert(installDoc.includes('configure-embeddings mem0-oss --embedder openai'), 'Mem0 install page missing OpenAI configure command');
    assert(installDoc.includes('configure-embeddings mem0-oss --embedder fastembed'), 'Mem0 install page missing FastEmbed configure command');
    assert(installDoc.includes('--provider-scope project'), 'Mem0 install page missing project-local explicit command');
    assert(installDoc.includes('Local FastEmbed is a normal install-time choice, not an emergency fallback'), 'Mem0 install page should not frame FastEmbed as an emergency workaround');
    assert(installDoc.includes('receipt_present') && installDoc.includes('runtime_available') && installDoc.includes('package_installed'), 'Mem0 install page missing receipt/runtime/package distinction');
    assert(installDoc.includes('Default provider storage is shared per OS user'), 'Mem0 install page missing shared storage default');
    assert(installDoc.includes('source_of_truth: false') && installDoc.includes('trust_effect: advisory_only'), 'Mem0 install page missing advisory-only boundary');
    const backendRecipePath = path.join(systemRoot, 'docs', 'cookbook', '10-mem0-embedding-backends.md');
    assert(fs.existsSync(backendRecipePath), 'Mem0 embedding backend recipe is missing');
    const backendRecipe = fs.readFileSync(backendRecipePath, 'utf8');
    assert(backendRecipe.includes('Which backend should Mem0 use for embeddings?'), 'Mem0 backend recipe missing agent question');
    assert(backendRecipe.includes('must ask the question') && backendRecipe.includes('do not silently choose'), 'Mem0 backend recipe missing required guided-choice policy');
    assert(backendRecipe.includes('OpenAI API') && backendRecipe.includes('Local FastEmbed'), 'Mem0 backend recipe missing backend choices');
    assert(backendRecipe.includes('OPENAI_API_KEY') && backendRecipe.includes('sk-...'), 'Mem0 backend recipe missing local terminal key guidance');
    assert(backendRecipe.includes('sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2'), 'Mem0 backend recipe missing multilingual-small model');
    assert(backendRecipe.includes('diagnostic_code: collection_reuse_blocked'), 'Mem0 backend recipe missing collection reuse guard');
    assert(backendRecipe.includes('--provider-scope project'), 'Mem0 backend recipe missing project-local explicit command');
    assert(fs.existsSync(path.join(systemRoot, 'docs', 'cookbook', '11-mem0-project-local-provider.md')), 'Mem0 project-local provider recipe is missing');
    const sharedRecipePath = path.join(systemRoot, 'docs', 'cookbook', '12-mem0-shared-provider-storage.md');
    assert(fs.existsSync(sharedRecipePath), 'Mem0 shared provider storage recipe is missing');
    const sharedRecipe = fs.readFileSync(sharedRecipePath, 'utf8');
    assert(sharedRecipe.includes('--provider-scope shared'), 'Mem0 shared provider recipe must use explicit shared scope for existing configs');
    assert(sharedRecipe.includes('data storage, not the Python runtime'), 'Mem0 shared provider recipe must separate storage from Python runtime');
    assert(sharedRecipe.includes('fastembed_onnx_external_data_path_error'), 'Mem0 shared provider recipe missing FastEmbed ONNX diagnostic guidance');
    assertMem0DocsSearchCoverage(project, state);

    const validated = parseJson(memoryCli(project, state, ['validate-recipe', 'mem0-oss', '--json']), 'validate Mem0 recipe');
    assert(validated.ok === true && validated.failures.length === 0, 'validate-recipe should pass generated recipe');
    assert(validated.dispatch_checked_via_help === true, 'validate-recipe should verify commands through CLI help/dispatch metadata');

    fs.writeFileSync(recipePath, `${first}\nnode .knowledge/tools/missing-tool.js nope --json\nnode .knowledge/tools/memory-provider.js setup mem0-oss --live --json\nnode .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text --scope repo --json\npython -m pip install mem0ai\n...\n`, 'utf8');
    const broken = parseJson(memoryCli(project, state, ['validate-recipe', 'mem0-oss', '--json']), 'validate broken Mem0 recipe');
    assert(broken.ok === false, 'validate-recipe should fail broken recipe');
    assert(broken.failures.some((failure) => failure.id === 'no_ellipsis'), 'validate-recipe did not catch ellipsis');
    assert(broken.failures.some((failure) => failure.id === 'command_dispatch'), 'validate-recipe did not catch missing command');
    assert(broken.failures.some((failure) => failure.id === 'single_setup_flow'), 'validate-recipe did not catch duplicate recommended setup flow');
    assert(broken.failures.some((failure) => failure.id === 'install_command_allowlist'), 'validate-recipe did not catch unsupported install command');
    assert(broken.failures.some((failure) => failure.id === 'exact_node_command_set'), 'validate-recipe did not catch node command with missing argument');

    if (original !== null) fs.writeFileSync(recipePath, original, 'utf8');
    else fs.unlinkSync(recipePath);
  } catch (error) {
    if (original !== null) fs.writeFileSync(recipePath, original, 'utf8');
    throw error;
  }
}

function main() {
  const cyrillic = '\u043f\u0430\u043c\u044f\u0442\u044c';
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `knowledge memory providers ${cyrillic} `));
  rootForCleanup = root;
  const project = path.join(root, 'repo with spaces');
  const state = path.join(root, 'state root');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });

  if (recipeQualityOnly) {
    testRecipeQuality(project, state);
    const result = {
      schema_version: '3.3.0',
      status: 'pass',
      temp_root: keepTemp ? root : null,
      temp_root_cleaned: !keepTemp,
      checks: [
        'setup mem0-oss creates receipt and requires explicit embedding provider choice',
        'shared Mem0 provider storage is default and project-local storage is explicit',
        'Mem0 config stays reproducible and runtime user state is isolated',
        'Mem0 status detects stale shared/project-local scope metadata',
        'setup mem0-oss migrates old receipt schema without install/network claims',
        'configure-embeddings writes OpenAI config without secrets or runtime user state',
        'configure-embeddings blocks reuse of an OpenAI 1536-dimension collection for FastEmbed',
        'configure-embeddings blocks unsupported FastEmbed runtime before install or smoke',
        'configure-embeddings writes FastEmbed config with programmatic dimensions and smoke commands',
        'install mem0-oss returns one recommended setup command',
        'Mem0 CLIs expose machine-readable help/dispatch metadata',
        'setup --live without mem0ai returns one exact install command',
        'setup --live with wrong mem0ai version returns one exact pinned install command',
        'setup --live with missing mem0ai version returns one exact pinned install command',
        'write-recipe generates deterministic template output',
        'validate-recipe passes generated recipe',
        'validate-recipe catches ellipsis and missing commands',
        'validate-recipe catches duplicate recommended setup flow',
        'validate-recipe catches unsupported install commands',
        'validate-recipe catches malformed node command arguments',
        'Mem0 install page documents setup, backend choice, runtime status, shared/project-local paths, and advisory boundary',
        'Mem0 embedding backend recipe documents OpenAI and Local FastEmbed guided flows',
        'Mem0 shared provider recipe documents explicit shared-scope adoption',
        'search index includes Mem0 docs as external_memory',
        'local search finds Mem0 install page',
        'recipe preserves advisory-only boundary and one recommended setup flow'
      ]
    };
    if (!keepTemp) fs.rmSync(root, { recursive: true, force: true });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const recipeQualityState = path.join(root, 'recipe quality state');
  fs.mkdirSync(recipeQualityState, { recursive: true });
  testRecipeQuality(project, recipeQualityState);

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
  assert(status.receipt_present === true && status.runtime_available === false && status.package_installed === false, 'Mem0 status must separate receipt/runtime/package install');
  assert(status.source_of_truth === false && status.trust_effect === 'advisory_only', 'external memory trust policy changed');

  const embeddingErrorState = path.join(root, 'state embedding provider cache');
  fs.mkdirSync(path.join(embeddingErrorState, 'external_memory', 'mem0'), { recursive: true });
  parseJson(memoryCli(project, embeddingErrorState, ['install', 'mem0-oss', '--version', 'mem0ai==2.0.4', '--yes-i-reviewed-license', '--json']), 'install receipt for embedding cache status');
  fs.writeFileSync(path.join(embeddingErrorState, 'external_memory', 'mem0', 'runtime_status.json'), JSON.stringify({
    schema_version: '3.3.0',
    provider_id: 'mem0-oss',
    adapter_id: 'live',
    checked_at: '2026-01-01T00:05:00.000Z',
    last_live_health_check: '2026-01-01T00:00:00.000Z',
    operation: 'recall',
    status: 'error',
    runtime_health: 'ok',
    diagnostic_code: 'embedding_provider_network_error',
    selected_python: path.join(project, 'Python Env', 'python.exe'),
    version: '2.0.4',
    expected_version: '2.0.4',
    runtime_available: true,
    package_installed: true,
    network_calls: 'may_call_embedding_provider',
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only',
    live_operations_require_explicit_consent: true
  }, null, 2), 'utf8');
  const embeddingStatus = parseJson(memoryCli(project, embeddingErrorState, ['status', 'mem0-oss', '--json']), 'status mem0 after embedding provider error cache');
  assert(embeddingStatus.status === 'available' && embeddingStatus.runtime_health === 'ok', 'embedding provider error cache must keep Mem0 status available');
  assert(embeddingStatus.runtime_available === true && embeddingStatus.package_installed === true, 'embedding provider error cache must preserve runtime/package flags');
  assert(embeddingStatus.last_live_health_check === '2026-01-01T00:00:00.000Z', 'embedding provider error cache must preserve last live health check');

  const qdrantBlockedState = path.join(root, 'state qdrant storage blocked');
  fs.mkdirSync(path.join(qdrantBlockedState, 'external_memory', 'mem0'), { recursive: true });
  parseJson(memoryCli(project, qdrantBlockedState, ['install', 'mem0-oss', '--version', 'mem0ai==2.0.4', '--yes-i-reviewed-license', '--json']), 'install receipt for qdrant blocked status');
  fs.writeFileSync(path.join(qdrantBlockedState, 'external_memory', 'mem0', 'runtime_status.json'), JSON.stringify({
    schema_version: '3.3.0',
    provider_id: 'mem0-oss',
    adapter_id: 'live',
    checked_at: '2026-01-01T00:10:00.000Z',
    last_live_health_check: '2026-01-01T00:10:00.000Z',
    operation: 'list',
    status: 'storage_unavailable',
    runtime_health: 'storage_unavailable',
    diagnostic_code: 'qdrant_path_permission_denied',
    selected_python: path.join(project, 'Python Env', 'python.exe'),
    version: '2.0.4',
    expected_version: '2.0.4',
    runtime_available: true,
    package_installed: true,
    network_calls: 'not_run_local_qdrant',
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only',
    live_operations_require_explicit_consent: true
  }, null, 2), 'utf8');
  const qdrantBlockedStatus = parseJson(memoryCli(project, qdrantBlockedState, ['status', 'mem0-oss', '--json']), 'status mem0 after qdrant storage block');
  assert(qdrantBlockedStatus.status === 'storage_unavailable', 'qdrant lock/permission status must not be reported as runtime_not_installed');
  assert(qdrantBlockedStatus.runtime_health === 'storage_unavailable', 'qdrant lock/permission status should report storage-specific runtime health');
  assert(qdrantBlockedStatus.runtime_available === true && qdrantBlockedStatus.package_installed === true, 'qdrant storage errors must preserve runtime/package availability');
  assert(qdrantBlockedStatus.diagnostic_code === 'qdrant_path_permission_denied', 'qdrant storage diagnostic should be preserved');

  const health = parseJson(mem0Cli(project, state, ['health', '--json']), 'mem0 health');
  assert(health.status === 'runtime_not_installed' && health.live_runtime_checked === false, 'Mem0 health should not claim live runtime');
  assert(health.source_of_truth === false && health.trust_effect === 'advisory_only', 'Mem0 health violated advisory-only envelope');
  assert(health.secrets_redacted === true, 'Mem0 health should keep secrets_redacted as boolean true');

  const missingPython = path.join(root, 'missing-python', 'python.exe');
  const liveMissing = parseJson(mem0Cli(project, state, ['health', '--adapter', 'live', '--python', missingPython, '--json']), 'mem0 live missing python');
  assert(liveMissing.status === 'runtime_not_installed', 'Mem0 live missing Python should stay runtime_not_installed');
  assert(liveMissing.diagnostic_code === 'python_missing', 'Mem0 live missing Python diagnostic mismatch');
  assert(liveMissing.selected_python === null, 'Mem0 live missing Python should not select an interpreter');
  assert((liveMissing.next_commands || []).some((command) => command.includes('--python')), 'Mem0 live missing Python should return --python next command');
  assert(!JSON.stringify(liveMissing).includes('spawnSync python'), 'Mem0 live missing Python leaked raw spawnSync wording');

  const liveAuto = parseJson(mem0Cli(project, state, ['health', '--adapter', 'live', '--json']), 'mem0 live auto health');
  assert(liveAuto.live_runtime_checked === true, 'Mem0 live auto health should mark live runtime checked');
  assert(['python_missing', 'python_permission_error', 'live_operation_timeout', 'python_not_usable', 'mem0_runtime_missing', 'mem0_version_mismatch', 'mem0_available', 'unknown_live_adapter_error', 'python_runtime_error', 'qdrant_path_permission_denied', 'qdrant_lock_busy', 'mem0_import_failed', 'fastembed_model_download_timeout'].includes(liveAuto.diagnostic_code), 'Mem0 live auto health diagnostic code unexpected');
  if (liveAuto.diagnostic_code === 'mem0_runtime_missing') {
    assert((liveAuto.next_commands || []).some((command) => command.includes('-m pip install mem0ai==2.0.4')), 'Mem0 missing package should include pinned pip command');
    assert(liveAuto.next_commands.length === 1, 'Mem0 missing package should include one recommended install command');
  }
  if (liveAuto.diagnostic_code === 'mem0_available') {
    assert(liveAuto.version === liveAuto.expected_version, 'Mem0 live health should report matching actual and expected versions');
    const liveStatus = parseJson(memoryCli(project, state, ['status', 'mem0-oss', '--json']), 'status mem0 after live health');
    assert(liveStatus.runtime_version === liveAuto.version, 'Mem0 status should expose cached runtime version');
    assert(liveStatus.expected_runtime_version === liveAuto.expected_version, 'Mem0 status should expose expected runtime version');
    assert(liveStatus.runtime_version_matches_pin === true, 'Mem0 status should expose runtime version pin match');
  }
  assert(!JSON.stringify(liveAuto).includes('spawnSync python'), 'Mem0 live auto health leaked raw spawnSync wording');

  const liveListMissing = parseJson(mem0Cli(project, state, ['list', '--adapter', 'live', '--yes-live-memory', '--python', missingPython, '--json']), 'mem0 live list missing python');
  assert(liveListMissing.network_calls === 'not_run_local_qdrant', 'Mem0 live list should be classified as local Qdrant without provider network');
  assert(liveListMissing.status === 'error' && liveListMissing.diagnostic_code === 'python_missing', 'Mem0 live list missing Python diagnostic mismatch');

  const liveAddMissing = parseJson(mem0Cli(project, state, ['add', '--adapter', 'live', '--yes-live-memory', '--python', missingPython, '--text', 'live classification probe', '--json']), 'mem0 live add missing python');
  assert(liveAddMissing.network_calls === 'may_call_embedding_provider', 'Mem0 live add should disclose possible embedding provider network');
  assert(liveAddMissing.persisted === false && liveAddMissing.diagnostic_code === 'python_missing', 'Mem0 live add missing Python should not persist');

  const liveSearchMissing = parseJson(mem0Cli(project, state, ['search', 'classification probe', '--adapter', 'live', '--yes-live-memory', '--python', missingPython, '--json']), 'mem0 live search missing python');
  assert(liveSearchMissing.network_calls === 'may_call_embedding_provider', 'Mem0 live search should disclose possible embedding provider network');
  assert(liveSearchMissing.operation === 'search', 'Mem0 live search should report operation=search');
  assert(liveSearchMissing.diagnostic_code === 'python_missing', 'Mem0 live search missing Python diagnostic mismatch');

  const liveRecallMissing = parseJson(mem0Cli(project, state, ['recall', 'classification probe', '--adapter', 'live', '--yes-live-memory', '--python', missingPython, '--json']), 'mem0 live recall missing python');
  assert(liveRecallMissing.network_calls === 'may_call_embedding_provider', 'Mem0 live recall should disclose possible embedding provider network');
  assert(liveRecallMissing.diagnostic_code === 'python_missing', 'Mem0 live recall missing Python diagnostic mismatch');

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
  for (const label of ['Receipt', 'Runtime', 'Runtime health', 'Runtime version', 'Boundary', 'Data path', 'Last live health']) {
    assert(html.includes(label), `inspector missing Mem0 onboarding field ${label}`);
  }
  for (const label of ['Copy install', 'Copy setup', 'Copy health', 'Copy add example', 'Copy search example', 'Copy recall example']) {
    assert(html.includes(label), `inspector missing Mem0 onboarding action ${label}`);
  }
  assert(html.includes('node .knowledge/tools/memory-provider.js setup mem0-oss --live --json'), 'inspector missing exact Mem0 setup command');
  assert(html.includes('node .knowledge/tools/memory-mem0.js health --adapter live --json'), 'inspector missing exact Mem0 health command');
  assert(html.includes('node .knowledge/tools/memory-mem0.js search &quot;advisory memory&quot; --adapter live --yes-live-memory --json'), 'inspector missing exact Mem0 search command');
  assert(html.includes('node .knowledge/tools/memory-mem0.js recall &quot;advisory memory&quot; --adapter live --yes-live-memory --json'), 'inspector missing exact Mem0 recall command');
  assert(/Copy setup/.test(html), 'inspector missing Mem0 setup onboarding action');
  assert(/live add writes external memory/.test(html), 'inspector missing Mem0 live write warning');
  assert(/advisory_only/.test(html), 'inspector missing advisory-only boundary');

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
    schema_version: '3.3.0',
    status: 'pass',
    temp_root: keepTemp ? root : null,
    temp_root_cleaned: !keepTemp,
    checks: [
      'list returns Mem0 and Pinecone',
      'preview writes no receipt',
      'install refuses without license confirmation',
      'install records receipt without claiming package install',
      'setup requires explicit Mem0 embedding provider choice before config/live checks',
      'shared Mem0 provider storage is default and project-local storage is explicit',
      'Mem0 config stays reproducible and runtime user state is isolated',
      'setup mem0-oss migrates old receipt schema without install/network claims',
      'receipt/runtime/package install fields stay distinct',
      'Mem0 runtime health reports runtime_not_installed without live checks',
      'Mem0 live health uses bounded Python discovery diagnostics',
      'Mem0 live list allows slow local Qdrant startup',
      'Mem0 live operations require explicit config before storage startup',
      'Mem0 setup enforces pinned mem0ai version',
      'Mem0 setup rejects missing mem0ai runtime version',
      'configure-embeddings blocks unsupported FastEmbed runtime before install or smoke',
      'Mem0 status and Inspector expose cached runtime version and pin match',
        'Mem0 status preserves runtime cache after embedding provider errors',
        'Mem0 status preserves runtime cache after FastEmbed ONNX model-cache errors',
        'Mem0 qdrant storage errors report storage_unavailable without clearing runtime cache',
      'Mem0 2.0.4 live search/list use filter-based API',
      'Mem0 live operation network classifications are explicit without live writes',
      'Mem0 CLIs expose machine-readable help/dispatch metadata',
      'Mem0 recipe quality gate passes',
      'Mem0 install page is covered by recipe quality gate',
      'search index includes Mem0 docs as external_memory',
      'local search finds Mem0 install page',
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
      'Inspector renders Mem0 onboarding card',
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
