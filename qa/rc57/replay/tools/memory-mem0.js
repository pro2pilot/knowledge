#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const { providerStateDir, findManifest, buildExternalMemoryReport } = require('./lib/memory-providers');
const { ensureDir, readJson, writeJsonAtomic } = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const {
  checkPythonModule,
  collectPythonCandidates,
  discoverPython,
  packageInstallCommand,
  quoteForCommand
} = require('./lib/python-discovery');
const {
  advisoryEnvelope,
  assertAdvisory,
  dryRunAdapter,
  jsonlAdapter,
  publicRecord,
  redactSecrets
} = require('./lib/memory-adapter-contract');

const DEFAULT_FAST_PYTHON_TIMEOUT_MS = 5000;
const DEFAULT_LIVE_HEALTH_TIMEOUT_MS = 30000;
const DEFAULT_LIVE_OPERATION_TIMEOUT_MS = 30000;

function numericTimeout(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function pythonTimeoutFlag(flags) {
  if (flags.pythonTimeoutMs !== undefined) return flags.pythonTimeoutMs;
  if (flags.pythonTimeMs !== undefined) return flags.pythonTimeMs;
  return undefined;
}

function normalizeDiagnosticCode(code) {
  const value = String(code || '');
  if (value === 'python_invalid') return 'python_not_usable';
  if (value === 'python_not_found') return 'python_missing';
  if (value === 'mem0_package_missing') return 'mem0_runtime_missing';
  if (value === 'python_module_error') return 'mem0_import_failed';
  if (value === 'python_timeout') return 'live_operation_timeout';
  if (value === 'mem0_storage_permission_error') return 'qdrant_path_permission_denied';
  if (value === 'mem0_runtime_error') return 'unknown_live_adapter_error';
  return value;
}

function expectedMem0Version(context) {
  try {
    const manifest = findManifest(context, 'mem0-oss');
    const pin = String(manifest.source?.version_pin || '');
    const match = pin.match(/==(.+)$/);
    return match ? match[1] : String(manifest.source?.version || '2.0.4');
  } catch {
    return '2.0.4';
  }
}

function versionMatches(actual, expected) {
  if (!actual || !expected) return false;
  const clean = (value) => String(value || '').trim().replace(/^v/i, '');
  return clean(actual) === clean(expected);
}

function adapterFile(context) {
  const manifest = findManifest(context, 'mem0-oss');
  return path.join(providerStateDir(context, manifest), 'adapter-records.jsonl');
}

function runtimeStatusFile(context) {
  const manifest = findManifest(context, 'mem0-oss');
  return path.join(providerStateDir(context, manifest), 'runtime_status.json');
}

function configMetaFile(context, flags = {}) {
  if (flags.config) return path.join(path.dirname(path.resolve(String(flags.config))), 'config.meta.json');
  const manifest = findManifest(context, 'mem0-oss');
  return path.join(providerStateDir(context, manifest), 'config.meta.json');
}

function selectedAdapter(flags) {
  return String(flags.adapter || process.env.KNOWLEDGE_MEM0_ADAPTER || 'dry-run').toLowerCase();
}

function parseMetadata(flags) {
  if (!flags.metadata && !flags.metadataJson) return {};
  const raw = flags.metadataJson || flags.metadata;
  try { return JSON.parse(String(raw)); }
  catch (error) { throw new Error(`Invalid --metadata JSON: ${error.message}`); }
}

function defaultLiveConfigPath(context) {
  const manifest = findManifest(context, 'mem0-oss');
  const candidate = path.join(providerStateDir(context, manifest), 'config.json');
  return candidate;
}

function liveConfigPath(flags, context) {
  if (flags.config) return path.resolve(String(flags.config));
  if (context) {
    const configPath = defaultLiveConfigPath(context);
    if (fs.existsSync(configPath)) return configPath;
  }
  return null;
}

function liveConfig(flags, context) {
  if (flags.configJson) return String(flags.configJson);
  const configPath = liveConfigPath(flags, context);
  if (configPath) return fs.readFileSync(configPath, 'utf8');
  return process.env.KNOWLEDGE_MEM0_CONFIG_JSON || '{}';
}

function parseLiveConfigObject(raw) {
  try {
    const parsed = JSON.parse(String(raw || '{}'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return Object.keys(parsed).length > 0 ? parsed : null;
  } catch {
    return null;
  }
}

function hasExplicitLiveConfig(flags, context) {
  if (flags.configJson) return Boolean(parseLiveConfigObject(flags.configJson));
  const configPath = liveConfigPath(flags, context);
  if (configPath) {
    if (!fs.existsSync(configPath)) return false;
    return Boolean(parseLiveConfigObject(fs.readFileSync(configPath, 'utf8')));
  }
  return Boolean(parseLiveConfigObject(process.env.KNOWLEDGE_MEM0_CONFIG_JSON || '{}'));
}

function sanitizeLiveConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) return config;
  const next = { ...config };
  delete next.user_id;
  return next;
}

function mem0RuntimeDirForConfig(configPath) {
  if (!configPath || !fs.existsSync(configPath)) return null;
  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const qdrantPath = config?.vector_store?.config?.path;
    if (qdrantPath) return path.join(path.dirname(path.resolve(qdrantPath)), 'runtime');
    if (config?.history_db_path) return path.join(path.dirname(path.resolve(config.history_db_path)), 'runtime');
  } catch {
    return null;
  }
  return null;
}

function restoreCanonicalLiveConfig(flags, context) {
  const configPath = liveConfigPath(flags, context);
  if (!configPath || !fs.existsSync(configPath)) return false;
  let config;
  try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); }
  catch { return false; }
  if (!Object.prototype.hasOwnProperty.call(config, 'user_id')) return false;
  writeJsonAtomic(configPath, sanitizeLiveConfig(config));
  return true;
}

function readJsonSoft(filePath, fallback = null) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function configuredPythonCandidates(flags, context) {
  if (flags.python || process.env.KNOWLEDGE_MEM0_PYTHON || process.env.MEM0_PYTHON) return [];
  const runtimeStatus = readJsonSoft(runtimeStatusFile(context), null);
  const configMeta = readJsonSoft(configMetaFile(context, flags), null);
  const candidates = [];
  const add = (command, source) => {
    const value = String(command || '').trim();
    if (!value) return;
    candidates.push({ command: value, source, from_config: true });
  };
  add(configMeta?.selected_python || configMeta?.python_runtime?.selected_python, 'mem0 config_meta selected_python');
  add(runtimeStatus?.selected_python, 'mem0 runtime_status selected_python');
  return candidates;
}

function mergePythonCandidates(first, second) {
  const merged = [];
  const seen = new Set();
  for (const candidate of [...(first || []), ...(second || [])]) {
    const command = String(candidate.command || '').trim();
    if (!command) continue;
    const args = Array.isArray(candidate.args) ? candidate.args.map((arg) => String(arg)) : [];
    const keyRaw = `${command}\u0000${args.join('\u0000')}`;
    const key = process.platform === 'win32' ? keyRaw.toLowerCase() : keyRaw;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(candidate);
  }
  return merged;
}

function liveProcessEnv(flags, context) {
  const env = {
    ...process.env,
    PYTHONUTF8: process.env.PYTHONUTF8 || '1',
    PYTHONIOENCODING: process.env.PYTHONIOENCODING || 'utf-8'
  };
  if (!env.MEM0_TELEMETRY) env.MEM0_TELEMETRY = 'False';
  if (!env.MEM0_TELEMETRY_SAMPLE_RATE) env.MEM0_TELEMETRY_SAMPLE_RATE = '0';
  if (flags.mem0Dir) env.MEM0_DIR = path.resolve(String(flags.mem0Dir));
  else if (!env.MEM0_DIR && flags.config) env.MEM0_DIR = mem0RuntimeDirForConfig(path.resolve(String(flags.config))) || path.join(path.dirname(path.resolve(String(flags.config))), 'runtime');
  else if (!env.MEM0_DIR && context) {
    const configPath = defaultLiveConfigPath(context);
    env.MEM0_DIR = mem0RuntimeDirForConfig(configPath) || path.join(path.dirname(configPath), 'runtime');
  }
  if (env.MEM0_DIR) ensureDir(env.MEM0_DIR);
  return env;
}

function encodeLivePythonPayload(flags, payload, context) {
  const envelope = {
    ...payload,
    __knowledge_mem0_config_json: liveConfig(flags, context)
  };
  return Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64');
}

function pythonDiscoveryOptions(flags, timeoutMs = DEFAULT_FAST_PYTHON_TIMEOUT_MS, context = null) {
  const options = {
    flags,
    timeoutMs: numericTimeout(pythonTimeoutFlag(flags), timeoutMs),
    env: process.env
  };
  if (context) {
    const preferred = configuredPythonCandidates(flags, context);
    if (preferred.length) {
      options.candidates = mergePythonCandidates(preferred, collectPythonCandidates(options));
    }
  }
  return options;
}

function liveHealthOp(payload) {
  return payload && payload.op === 'health';
}

function liveMem0TimeoutMs(flags, payload) {
  const fallback = liveHealthOp(payload) ? DEFAULT_LIVE_HEALTH_TIMEOUT_MS : DEFAULT_LIVE_OPERATION_TIMEOUT_MS;
  return numericTimeout(flags.timeoutMs, fallback);
}

function liveImportOptions(flags, payload) {
  return {
    flags,
    timeoutMs: numericTimeout(pythonTimeoutFlag(flags), liveMem0TimeoutMs(flags, payload)),
    env: process.env
  };
}

function classifyLivePythonError(error) {
  const code = error && error.code;
  if (code === 'ENOENT') return 'python_missing';
  if (code === 'ETIMEDOUT') return 'live_operation_timeout';
  if (code === 'EACCES' || code === 'EPERM') return 'python_permission_error';
  return 'python_runtime_error';
}

function friendlyLivePythonError(error, payload) {
  const code = error && error.code;
  if (code === 'ETIMEDOUT' && liveHealthOp(payload)) {
    return 'Live Mem0 health timed out while waiting for Python import. First import mem0 on Windows can be slower than warm checks.';
  }
  if (code === 'ETIMEDOUT') return 'Live Mem0 Python command timed out.';
  if (code === 'ENOENT') return 'selected Python command was not found';
  if (code === 'EACCES' || code === 'EPERM') return 'permission denied while launching selected Python';
  return error && error.message ? error.message : 'selected Python command failed';
}

function pythonInstallNextCommands(selectedPython) {
  if (!selectedPython) {
    return [
      'node .knowledge/tools/memory-mem0.js health --adapter live --python "<path-to-python.exe>" --json'
    ];
  }
  return [
    packageInstallCommand(selectedPython, 'mem0ai==2.0.4')
  ];
}

function timeoutRetryCommand(operation = 'health', selectedPython) {
  const pythonArg = selectedPython ? ` --python ${quoteForCommand(selectedPython)}` : '';
  if (operation === 'list') {
    return `node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory${pythonArg} --timeout-ms 60000 --json`;
  }
  return `node .knowledge/tools/memory-mem0.js health --adapter live${pythonArg} --timeout-ms 60000 --json`;
}

function longTimeoutRetryCommand(operation = 'list', selectedPython) {
  const base = liveOperationRetryCommand(operation, selectedPython);
  return base.replace(/ --json$/, ' --timeout-ms 300000 --json');
}

function liveOperationRetryCommand(operation = 'health', selectedPython) {
  const pythonArg = selectedPython ? ` --python ${quoteForCommand(selectedPython)}` : '';
  if (operation === 'remember') {
    return `node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 embedding backend smoke test" --scope repo${pythonArg} --json`;
  }
  if (operation === 'recall') {
    return `node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory${pythonArg} --json`;
  }
  if (operation === 'list') {
    return `node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory${pythonArg} --json`;
  }
  return `node .knowledge/tools/memory-mem0.js health --adapter live${pythonArg} --json`;
}

function fastEmbedDownloadNextCommands(selectedPython, operation = 'list') {
  return [
    'First Local FastEmbed use may download model files; keep the configured shared provider root and rerun the explicit live command with a longer timeout.',
    'Use a Python 3.12 runtime or virtualenv if the selected Python is unsupported for the pinned FastEmbed runtime.',
    longTimeoutRetryCommand(operation, selectedPython)
  ];
}

function fastEmbedOnnxNextCommands(selectedPython, operation = 'list') {
  const pythonCommand = selectedPython ? quoteForCommand(selectedPython) : 'python';
  return [
    'Use a Python 3.12 runtime or virtualenv for Local FastEmbed if the selected Python is too new or the model cache failure repeats.',
    `${pythonCommand} -m pip install mem0ai==2.0.4`,
    `${pythonCommand} -m pip install fastembed==0.5.1`,
    liveOperationRetryCommand(operation, selectedPython)
  ];
}

function liveFailureNextCommands(diagnosticCode, selectedPython, operation = 'health') {
  if (diagnosticCode === 'mem0_not_configured') {
    return [
      'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json',
      'node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json'
    ];
  }
  if (diagnosticCode === 'mem0_runtime_missing') return pythonInstallNextCommands(selectedPython);
  if (diagnosticCode === 'mem0_version_mismatch') return pythonInstallNextCommands(selectedPython);
  if (diagnosticCode === 'fastembed_model_download_timeout') return fastEmbedDownloadNextCommands(selectedPython, operation);
  if (diagnosticCode === 'fastembed_onnx_external_data_path_error') return fastEmbedOnnxNextCommands(selectedPython, operation);
  if (diagnosticCode === 'live_operation_timeout') {
    return [
      timeoutRetryCommand(operation, selectedPython)
    ];
  }
  if (diagnosticCode === 'qdrant_lock_busy') {
    return [
      'Keep shared Mem0 provider storage unless the user explicitly chooses project-local storage.',
      'Close the process holding the Qdrant lock or reboot, then rerun node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json',
      'Only after explicit user approval for project-local storage, run node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope project --json'
    ];
  }
  if (diagnosticCode === 'qdrant_path_permission_denied') {
    return [
      'Do not silently move shared Mem0 provider storage into this repository.',
      'Repair permissions or close the process holding the shared Qdrant path, then rerun node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json',
      'If the user explicitly wants project-local storage, run node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope project --json'
    ];
  }
  return ['Fix the selected Python runtime, then rerun node .knowledge/tools/memory-mem0.js health --adapter live --json'];
}

function isFastEmbedOnnxExternalDataError(text) {
  return /(?:ONNXRuntimeError|onnxruntime|model\.onnx(?:_data)?|external data path validation failed)/i.test(text) &&
    /(?:external data|onnx_data|allowed directory|blobs|model\.onnx)/i.test(text);
}

function isFastEmbedModelDownloadTimeout(text) {
  const value = String(text || '');
  return /(?:Live Mem0 Python command timed out|timed out|timeout)/i.test(value) &&
    /(?:Fetching\s+\d+\s+files|huggingface|hf_hub|hf_xet|higher rate limits|snapshot_download|download)/i.test(value) &&
    !/openai/i.test(value);
}

function classifyMem0RuntimeFailure(parsed = {}, res = {}, payload = {}, selectedPython = null) {
  const text = [
    parsed.error,
    parsed.stderr,
    parsed.stdout,
    res.stderr,
    res.stdout
  ].filter(Boolean).join('\n');
  const mayUseEmbeddingProvider = ['remember', 'recall', 'list'].includes(String(payload?.op || ''));
  if (/(?:already locked|lock busy|currently accessed|resource temporarily unavailable)/i.test(text) && /(?:qdrant|\.lock|lock[- ]?file)/i.test(text)) {
    return {
      diagnostic_code: 'qdrant_lock_busy',
      next_commands: liveFailureNextCommands('qdrant_lock_busy')
    };
  }
  if (/permission denied/i.test(text) && /(?:qdrant|\.lock|lock[- ]?file)/i.test(text)) {
    return {
      diagnostic_code: 'qdrant_path_permission_denied',
      next_commands: liveFailureNextCommands('qdrant_path_permission_denied')
    };
  }
  if (isFastEmbedOnnxExternalDataError(text)) {
    return {
      diagnostic_code: 'fastembed_onnx_external_data_path_error',
      diagnostic_message: 'Local FastEmbed reached the Mem0 runtime, but the ONNX model cache failed to load. Treat this as a Python/FastEmbed/model-cache issue, not as a shared provider root issue.',
      runtime_boundary: 'fastembed_onnx_model_runtime',
      next_commands: liveFailureNextCommands('fastembed_onnx_external_data_path_error', selectedPython, payload?.op)
    };
  }
  if (isFastEmbedModelDownloadTimeout(text)) {
    return {
      diagnostic_code: 'fastembed_model_download_timeout',
      diagnostic_message: 'Local FastEmbed reached the Mem0 runtime, but the first model download did not finish before the live command timeout. Treat this as model warmup/download timing, not as OpenAI quota.',
      runtime_boundary: 'fastembed_model_download',
      next_commands: liveFailureNextCommands('fastembed_model_download_timeout', selectedPython, payload?.op || 'list')
    };
  }
  if (/api key|credentials|OPENAI_API_KEY|authentication/i.test(text) && (/embed|embedding|openai/i.test(text) || mayUseEmbeddingProvider)) {
    return {
      diagnostic_code: 'embedding_provider_missing_credentials',
      next_commands: [
        'Set OPENAI_API_KEY in the local terminal, or configure Local FastEmbed with node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json'
      ]
    };
  }
  if (/quota|rate limit|insufficient_quota/i.test(text) && (/embed|embedding|openai/i.test(text) || mayUseEmbeddingProvider)) {
    return {
      diagnostic_code: 'embedding_provider_quota_exceeded',
      next_commands: [
        'Run the Mem0 embedding backend guided recipe, or configure Local FastEmbed with node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json'
      ]
    };
  }
  if (/network|timed out|connection|ECONNRESET|ENOTFOUND/i.test(text) && (/embed|embedding|openai/i.test(text) || mayUseEmbeddingProvider)) {
    return {
      diagnostic_code: 'embedding_provider_network_error',
      next_commands: ['Retry the explicit live command after network access is available.']
    };
  }
  return null;
}

function filterSafeStderr(value) {
  const lines = String(value || '').split(/\r?\n/);
  const kept = [];
  let droppingQdrantShutdown = false;
  for (const line of lines) {
    if (/Exception ignored while calling deallocator .*QdrantClient\.__del__/i.test(line) || /Exception ignored in:\s*<function QdrantClient\.__del__/i.test(line)) {
      droppingQdrantShutdown = true;
      continue;
    }
    if (droppingQdrantShutdown) {
      if (/Traceback|qdrant_client|qdrant_local|sys\.meta_path is None|Python is likely shutting down/i.test(line)) continue;
      droppingQdrantShutdown = false;
    }
    if (/ResourceWarning|unclosed.*(?:qdrant|client)|grpc.*shutdown/i.test(line)) continue;
    if (/Failed to load spaCy .* model: spaCy is not installed\. Install it with: pip install mem0ai\[nlp\]/i.test(line)) continue;
    if (/Xet Storage is enabled|hf_xet package is not installed|Falling back to regular HTTP download|huggingface_hub\[hf_xet\]|pip install hf_xet/i.test(line)) continue;
    kept.push(line);
  }
  return kept.join('\n').trim();
}

function liveLockRequest(context, timeoutMs) {
  return {
    context,
    rootKind: 'state',
    rootPath: context.stateRoot,
    lockName: 'memory-provider',
    purpose: LOCKS['memory-provider'].purpose,
    timeoutMs
  };
}

function isContainedLockBusyError(error) {
  return error?.code === 'lock_timeout' ||
    /Timed out waiting for knowledge lock|Lock "[^"]+" is held by pid/i.test(String(error?.message || ''));
}

function runLivePythonProcess(selectedPython, flags, payload, context, script) {
  return spawnSync(selectedPython, ['-c', script], {
    input: encodeLivePythonPayload(flags, payload, context),
    encoding: 'utf8',
    env: liveProcessEnv(flags, context),
    windowsHide: true,
    timeout: liveMem0TimeoutMs(flags, payload)
  });
}

function liveOperationUsesLocalQdrant(payload) {
  return payload && !liveHealthOp(payload);
}

function configuredEmbeddingProvider(flags, context) {
  try {
    const config = JSON.parse(liveConfig(flags, context));
    return String(config?.embedder?.provider || '').toLowerCase();
  } catch {
    return '';
  }
}

function localStorageNetworkLabel(flags, context) {
  return configuredEmbeddingProvider(flags, context) === 'fastembed'
    ? 'not_run_local_qdrant_may_download_local_fastembed_model'
    : 'not_run_local_qdrant';
}

function runLiveMem0(flags, payload, context) {
  if (
    process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE === '1' &&
    process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_FORCE_MEM0_MISSING === '1'
  ) {
    const selectedPython = String(flags.python || process.env.KNOWLEDGE_MEM0_PYTHON || process.env.MEM0_PYTHON || 'python');
    return redactSecrets({
      ok: false,
      diagnostic_code: 'mem0_runtime_missing',
      error: 'Mem0 Python package is not importable.',
      python_discovery: {
        status: 'found',
        diagnostic_code: 'python_available',
        selected: {
          command: selectedPython,
          source: 'test hook',
          explicit: Boolean(flags.python),
          status: 'ok',
          diagnostic_code: 'python_available',
          executable: selectedPython
        },
        candidates_checked: 1,
        candidates: []
      },
      selected_python: selectedPython,
      next_commands: liveFailureNextCommands('mem0_runtime_missing', selectedPython, payload?.op)
    });
  }
  if (
    process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE === '1' &&
    process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_FORCE_MEM0_VERSION_MISMATCH === '1'
  ) {
    const selectedPython = String(flags.python || process.env.KNOWLEDGE_MEM0_PYTHON || process.env.MEM0_PYTHON || 'python');
    const expectedVersion = expectedMem0Version(context);
    const actualVersion = process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_MEM0_VERSION === '__missing__'
      ? null
      : process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_MEM0_VERSION || '1.0.0';
    return redactSecrets({
      ok: false,
      diagnostic_code: 'mem0_version_mismatch',
      error: `Mem0 Python package version ${actualVersion} does not match required ${expectedVersion}.`,
      version: actualVersion,
      expected_version: expectedVersion,
      python_discovery: {
        status: 'found',
        diagnostic_code: 'python_available',
        selected: {
          command: selectedPython,
          source: 'test hook',
          explicit: Boolean(flags.python),
          status: 'ok',
          diagnostic_code: 'python_available',
          executable: selectedPython
        },
        candidates_checked: 1,
        candidates: []
      },
      selected_python: selectedPython,
      next_commands: liveFailureNextCommands('mem0_version_mismatch', selectedPython, payload?.op)
    });
  }
  const discovery = discoverPython(pythonDiscoveryOptions(flags, DEFAULT_FAST_PYTHON_TIMEOUT_MS, context));
  if (!discovery.selected) {
    const diagnosticCode = normalizeDiagnosticCode(discovery.diagnostic_code || 'python_not_found');
    return redactSecrets({
      ok: false,
      diagnostic_code: diagnosticCode,
      error: 'No usable Python runtime was found by bounded discovery.',
      python_discovery: discovery,
      selected_python: null,
      next_commands: diagnosticCode === 'python_missing'
        ? (discovery.next_commands || pythonInstallNextCommands(null))
        : liveFailureNextCommands(diagnosticCode, null, payload?.op)
    });
  }
  const selectedPython = discovery.selected.executable || discovery.selected.command;
  const moduleCheck = checkPythonModule(selectedPython, 'mem0', liveImportOptions(flags, payload));
  if (!moduleCheck.ok) {
    const diagnosticCode = normalizeDiagnosticCode(moduleCheck.diagnostic_code === 'mem0_package_missing' ? 'mem0_package_missing' : moduleCheck.diagnostic_code);
    return redactSecrets({
      ok: false,
      diagnostic_code: diagnosticCode,
      error: moduleCheck.error || 'Mem0 Python package is not importable.',
      python_discovery: discovery,
      selected_python: selectedPython,
      next_commands: liveFailureNextCommands(diagnosticCode, selectedPython, payload?.op)
    });
  }
  const expectedVersion = expectedMem0Version(context);
  if (!versionMatches(moduleCheck.version, expectedVersion)) {
    return redactSecrets({
      ok: false,
      diagnostic_code: 'mem0_version_mismatch',
      error: `Mem0 Python package version ${moduleCheck.version} does not match required ${expectedVersion}.`,
      version: moduleCheck.version || null,
      expected_version: expectedVersion,
      python_discovery: discovery,
      selected_python: selectedPython,
      next_commands: liveFailureNextCommands('mem0_version_mismatch', selectedPython, payload?.op)
    });
  }
  if (liveHealthOp(payload)) {
    return redactSecrets({
      ok: true,
      operation: 'health',
      diagnostic_code: 'mem0_available',
      python_discovery: discovery,
      selected_python: selectedPython,
      next_commands: [],
      version: moduleCheck.version || null,
      expected_version: expectedVersion
    });
  }
  if (!hasExplicitLiveConfig(flags, context)) {
    return redactSecrets({
      ok: false,
      operation: payload?.op || null,
      diagnostic_code: 'mem0_not_configured',
      error: 'Live Mem0 operation requires explicit provider config. Run setup/configure so Mem0 does not fall back to default storage.',
      python_discovery: discovery,
      selected_python: selectedPython,
      next_commands: liveFailureNextCommands('mem0_not_configured', selectedPython, payload?.op),
      version: moduleCheck.version || null,
      expected_version: expectedVersion
    });
  }
  const script = String.raw`
import base64, json, os, sys, warnings
warnings.filterwarnings("ignore", category=ResourceWarning, message=r".*(unclosed|qdrant|client).*")
payload_raw = base64.b64decode((sys.stdin.read() or "").strip() or "e30=").decode("utf-8")
payload = json.loads(payload_raw or "{}")
try:
    import mem0
    from mem0 import Memory
except Exception as exc:
    print(json.dumps({"ok": False, "error": "mem0 import failed: " + str(exc)}))
    sys.exit(0)

def make_memory():
    config_json = payload.get("__knowledge_mem0_config_json") or os.environ.get("KNOWLEDGE_MEM0_CONFIG_JSON") or "{}"
    config = json.loads(config_json)
    if hasattr(Memory, "from_config"):
        return Memory.from_config(config) if config else Memory()
    try:
        return Memory(config=config) if config else Memory()
    except TypeError:
        return Memory()

def user_filter(user_id):
    return {"user_id": user_id} if user_id else {}

try:
    op = payload.get("op")
    user_id = payload.get("user_id") or "knowledge-repo"
    if op == "health":
        result = {"ok": True, "version": getattr(mem0, "__version__", None), "operation": op}
    else:
        memory = make_memory()
        if op == "remember":
            text = payload.get("text") or ""
            result = memory.add(text, user_id=user_id, infer=bool(payload.get("infer", False)))
            result = {"ok": True, "operation": op, "raw": result}
        elif op == "recall":
            result = memory.search(payload.get("query") or "", filters=user_filter(user_id))
            result = {"ok": True, "operation": op, "raw": result}
        elif op == "list":
            result = memory.get_all(filters=user_filter(user_id))
            result = {"ok": True, "operation": op, "raw": result}
        elif op == "forget":
            memory.delete(memory_id=payload.get("id"))
            result = {"ok": True, "operation": op, "deleted": True}
        else:
            result = {"ok": False, "error": "unknown op"}
        for close_name in ("close", "shutdown"):
            close = getattr(memory, close_name, None)
            if callable(close):
                close()
    print(json.dumps(result, default=str))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
`;
  let res;
  try {
    res = liveOperationUsesLocalQdrant(payload)
      ? withContainedLock(
        liveLockRequest(context, numericTimeout(flags.lockTimeoutMs, 10000)),
        () => runLivePythonProcess(selectedPython, flags, payload, context, script)
      )
      : runLivePythonProcess(selectedPython, flags, payload, context, script);
  } catch (error) {
    restoreCanonicalLiveConfig(flags, context);
    const lockBusy = isContainedLockBusyError(error);
    return redactSecrets({
      ok: false,
      diagnostic_code: lockBusy ? 'qdrant_lock_busy' : 'unknown_live_adapter_error',
      error: error.message,
      python_discovery: discovery,
      selected_python: selectedPython,
      next_commands: liveFailureNextCommands(lockBusy ? 'qdrant_lock_busy' : 'unknown_live_adapter_error', selectedPython, payload?.op),
      version: moduleCheck.version || null
    });
  }
  restoreCanonicalLiveConfig(flags, context);
  let parsed = {};
  try { parsed = JSON.parse((res.stdout || '').trim() || '{}'); }
  catch { parsed = { ok: false, stdout: (res.stdout || '').trim() }; }
  if (res.error) {
    parsed.ok = false;
    parsed.diagnostic_code = classifyLivePythonError(res.error);
    parsed.error = friendlyLivePythonError(res.error, payload);
    parsed.next_commands = liveFailureNextCommands(parsed.diagnostic_code, selectedPython, payload?.op);
  }
  const stderr = filterSafeStderr(res.stderr);
  if (stderr) parsed.stderr = stderr.slice(0, 2000);
  const runtimeFailure = classifyMem0RuntimeFailure(parsed, res, payload, selectedPython);
  if (!parsed.ok && runtimeFailure) {
    for (const key of ['diagnostic_code', 'diagnostic_message', 'runtime_boundary', 'next_commands']) {
      if (runtimeFailure[key] !== undefined) parsed[key] = runtimeFailure[key];
    }
  }
  const diagnosticCode = normalizeDiagnosticCode(parsed.ok ? 'mem0_available' : (parsed.diagnostic_code || 'mem0_runtime_error'));
  return redactSecrets({
    ...parsed,
    diagnostic_code: diagnosticCode,
    python_discovery: discovery,
    selected_python: selectedPython,
    next_commands: parsed.next_commands || (parsed.ok ? [] : liveFailureNextCommands(diagnosticCode, selectedPython, payload?.op)),
    version: parsed.version || moduleCheck.version || null
  });
}

function liveHealthWarnings(raw) {
  if (raw.ok) return [];
  if (raw.diagnostic_code === 'mem0_runtime_missing') {
    return ['Python was found, but mem0ai is not installed in that Python environment.'];
  }
  if (raw.diagnostic_code === 'mem0_version_mismatch') {
    const actual = raw.version || 'unknown';
    const expected = raw.expected_version || expectedMem0Version();
    return [`Python has mem0ai ${actual}, but .knowledge requires mem0ai ${expected}.`];
  }
  if (raw.diagnostic_code === 'mem0_not_configured') {
    return ['Live Mem0 runtime is installed, but no provider config is present. Run setup/configure before add/search/list.'];
  }
  if (raw.diagnostic_code === 'live_operation_timeout') {
    return ['Live Mem0 health timed out. First import mem0 on Windows can be slower than warm checks; the default live health timeout is 30000 ms.'];
  }
  if (raw.diagnostic_code === 'qdrant_lock_busy' || raw.diagnostic_code === 'qdrant_path_permission_denied') {
    return ['Live Mem0 runtime could import, but its storage backend reported a qdrant lock/permission error. Configure writable persistent storage and rerun the live command.'];
  }
  return ['Live Mem0 runtime was not available or not configured.'];
}

function isQdrantStorageDiagnostic(value) {
  return ['qdrant_lock_busy', 'qdrant_path_permission_denied'].includes(String(value || ''));
}

function liveAdapter(flags, context) {
  const providerId = 'mem0-oss';
  const adapterId = 'live';
  function requireConsent(operation) {
    if (operation === 'health') return;
    if (!flags.yesLiveMemory && process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE !== '1') {
      throw new Error(`${operation} with --adapter live requires --yes-live-memory`);
    }
  }
  return {
    health() {
      const raw = runLiveMem0(flags, { op: 'health' }, context);
      const storageUnavailable = isQdrantStorageDiagnostic(raw.diagnostic_code);
      return advisoryEnvelope(providerId, adapterId, 'health', {
        status: raw.ok ? 'available' : (storageUnavailable ? 'storage_unavailable' : 'runtime_not_installed'),
        runtime_health: raw.ok ? 'ok' : (storageUnavailable ? 'storage_unavailable' : 'not_available'),
        live_runtime_checked: true,
        network_calls: 'not_run',
        diagnostic_code: raw.diagnostic_code || (raw.ok ? 'mem0_available' : 'runtime_not_installed'),
        version: raw.version || null,
        expected_version: raw.expected_version || null,
        selected_python: raw.selected_python || null,
        python_discovery: raw.python_discovery || null,
        next_commands: raw.next_commands || [],
        raw: raw.ok ? { ok: true, version: raw.version || null, expected_version: raw.expected_version || null } : {
          ok: false,
          diagnostic_code: raw.diagnostic_code || 'runtime_not_installed',
          version: raw.version || null,
          expected_version: raw.expected_version || null,
          error: raw.error || 'Live Mem0 runtime was not available or not configured.'
        },
        warnings: liveHealthWarnings(raw)
      });
    },
    remember(input = {}) {
      requireConsent('remember');
      const raw = runLiveMem0(flags, { op: 'remember', text: input.text, user_id: input.user_id, infer: Boolean(flags.infer) }, context);
      return advisoryEnvelope(providerId, adapterId, 'remember', {
        status: raw.ok ? 'ok' : 'error',
        persisted: Boolean(raw.ok),
        network_calls: 'may_call_embedding_provider',
        diagnostic_code: raw.diagnostic_code || (raw.ok ? 'mem0_available' : 'mem0_runtime_error'),
        selected_python: raw.selected_python || null,
        python_discovery: raw.python_discovery || null,
        next_commands: raw.next_commands || [],
        raw,
        warnings: ['Live Mem0 writes remain advisory-only and cannot raise .knowledge trust.']
      });
    },
    recall(input = {}) {
      requireConsent('recall');
      const raw = runLiveMem0(flags, { op: 'recall', query: input.query, user_id: input.user_id }, context);
      return advisoryEnvelope(providerId, adapterId, 'recall', {
        status: raw.ok ? 'ok' : 'error',
        query: input.query || '',
        network_calls: 'may_call_embedding_provider',
        diagnostic_code: raw.diagnostic_code || (raw.ok ? 'mem0_available' : 'mem0_runtime_error'),
        selected_python: raw.selected_python || null,
        python_discovery: raw.python_discovery || null,
        next_commands: raw.next_commands || [],
        raw,
        warnings: ['Live Mem0 retrieval is advisory-only; verify against code/tests/evidence before use.']
      });
    },
    search(input = {}) {
      requireConsent('search');
      const raw = runLiveMem0(flags, { op: 'recall', query: input.query, user_id: input.user_id }, context);
      return advisoryEnvelope(providerId, adapterId, 'search', {
        status: raw.ok ? 'ok' : 'error',
        query: input.query || '',
        network_calls: 'may_call_embedding_provider',
        diagnostic_code: raw.diagnostic_code || (raw.ok ? 'mem0_available' : 'mem0_runtime_error'),
        selected_python: raw.selected_python || null,
        python_discovery: raw.python_discovery || null,
        next_commands: raw.next_commands || [],
        raw,
        warnings: ['Live Mem0 retrieval is advisory-only; verify against code/tests/evidence before use.']
      });
    },
    list(input = {}) {
      requireConsent('list');
      const raw = runLiveMem0(flags, { op: 'list', user_id: input.user_id }, context);
      const records = livePublicRecords(raw, input);
      return advisoryEnvelope(providerId, adapterId, 'list', {
        status: raw.ok ? 'ok' : 'error',
        records_count: records.length,
        records,
        results: records,
        network_calls: localStorageNetworkLabel(flags, context),
        diagnostic_code: raw.diagnostic_code || (raw.ok ? 'mem0_available' : 'mem0_runtime_error'),
        selected_python: raw.selected_python || null,
        python_discovery: raw.python_discovery || null,
        next_commands: raw.next_commands || [],
        raw
      });
    },
    forget(input = {}) {
      requireConsent('forget');
      const raw = runLiveMem0(flags, { op: 'forget', id: input.id, user_id: input.user_id }, context);
      return advisoryEnvelope(providerId, adapterId, 'forget', {
        status: raw.ok ? 'ok' : 'error',
        deleted: Boolean(raw.deleted),
        network_calls: localStorageNetworkLabel(flags, context),
        diagnostic_code: raw.diagnostic_code || (raw.ok ? 'mem0_available' : 'mem0_runtime_error'),
        selected_python: raw.selected_python || null,
        python_discovery: raw.python_discovery || null,
        next_commands: raw.next_commands || [],
        raw
      });
    },
    exportRedacted() {
      return advisoryEnvelope(providerId, adapterId, 'export-redacted', {
        status: 'ok',
        content_included: false,
        records: [],
        warnings: ['Live Mem0 export is intentionally not implemented in free/core to avoid leaking memory content.']
      });
    }
  };
}

function adapterFor(context, flags) {
  const adapter = selectedAdapter(flags);
  if (adapter === 'test') return jsonlAdapter('mem0-oss', 'test-jsonl', adapterFile(context));
  if (adapter === 'live') return liveAdapter(flags, context);
  return dryRunAdapter('mem0-oss', 'dry-run', 'runtime_not_installed');
}

function inputFromFlags(flags, positional) {
  return {
    text: flags.text || positional.slice(1).join(' '),
    query: positional.slice(1).join(' ') || flags.query,
    id: flags.id,
    scope: flags.scope || 'repo',
    user_id: flags.userId || flags.user || process.env.KNOWLEDGE_MEMORY_USER_ID || 'knowledge-repo',
    include_text: Boolean(flags.includeText),
    metadata: parseMetadata(flags),
    override_attempt: Boolean(flags.overrideAttempt || flags.contradictsSource)
  };
}

function withStatus(result, context) {
  if (result.adapter_id === 'live') {
    const filePath = runtimeStatusFile(context);
    ensureDir(path.dirname(filePath));
    writeJsonAtomic(filePath, runtimeStatusSnapshot(result, context, readJson(filePath, null)));
  }
  if (['remember', 'forget'].includes(result.operation) && result.adapter_id === 'test-jsonl') {
    buildExternalMemoryReport(context, { write: true });
  }
  return assertAdvisory(result);
}

function syncReport(context, adapterId) {
  const report = buildExternalMemoryReport(context, { write: true });
  return advisoryEnvelope('mem0-oss', adapterId, 'sync-report', {
    status: 'ok',
    report: {
      maintenance: 'maintenance/external_memory_status.json',
      metrics: 'metrics/external_memory.json',
      override_attempts_blocked: report.metrics?.override_attempts_blocked || 0
    }
  });
}

function asRecordArray(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return [];
  const candidates = [
    value?.results,
    value?.result,
    value?.data,
    value?.items,
    value?.records,
    value?.memories,
    value?.output,
    value?.payload
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate;
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      const nested = asRecordArray(candidate);
      if (nested.length) return nested;
    }
  }
  return [];
}

function liveResultItems(result) {
  const candidates = [
    result,
    result?.raw,
    result?.raw?.raw,
    result?.raw?.result
  ];
  for (const candidate of candidates) {
    const found = asRecordArray(candidate);
    if (found.length) return found;
  }
  return [];
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== '');
}

function liveItemText(item) {
  return firstDefined(
    item?.memory,
    item?.text,
    item?.content,
    item?.value,
    item?.payload?.text,
    item?.payload?.memory,
    item?.metadata?.text,
    item?.content_text,
    item?.result?.text
  );
}

function liveItemMetadata(item) {
  const metadata = item?.metadata && typeof item.metadata === 'object' && !Array.isArray(item.metadata)
    ? { ...item.metadata }
    : {};
  for (const key of ['text', 'memory']) delete metadata[key];
  return redactSecrets(metadata);
}

function publicLiveRecord(item, input = {}) {
  const text = liveItemText(item);
  return {
    id: String(firstDefined(item?.id, item?.memory_id, item?.memoryId, item?.uuid, item?.record_id, item?.metadata?.id, item?.metadata?.memory_id, '')),
    provider_id: 'mem0-oss',
    scope: firstDefined(item?.metadata?.scope, input.scope, 'repo'),
    user_id: firstDefined(item?.user_id, item?.metadata?.user_id, input.user_id, null),
    created_at: firstDefined(item?.created_at, item?.createdAt, item?.metadata?.created_at, item?.result?.created_at, null),
    updated_at: firstDefined(item?.updated_at, item?.updatedAt, item?.metadata?.updated_at, item?.result?.updated_at, null),
    text: input.include_text && text !== undefined ? String(text) : undefined,
    metadata: liveItemMetadata(item),
    score: item?.score,
    source_of_truth: false,
    trust_effect: 'advisory_only',
    override_attempt: false
  };
}

function livePublicRecords(result, input = {}) {
  return liveResultItems(result)
    .map((item) => publicLiveRecord(item, input))
    .filter((record) => record.id);
}

function runtimeStatusSnapshot(result, context, previous = null) {
  const diagnosticCode = result.diagnostic_code || 'mem0_available';
  const statusValue = String(result.status || '').toLowerCase();
  const runtimeVersion = result.version || result.raw?.version || result.raw?.raw?.version || null;
  const expectedVersion = result.expected_version || result.raw?.expected_version || result.raw?.raw?.expected_version || (runtimeVersion ? expectedMem0Version(context) : null);
  const checkedAt = new Date().toISOString();
  const storageUnavailable = isQdrantStorageDiagnostic(diagnosticCode);
  const runtimeStillAvailable = [
    'mem0_available',
    'fastembed_onnx_external_data_path_error',
    'fastembed_model_download_timeout',
    'mem0_not_configured',
    'embedding_provider_missing_credentials',
    'embedding_provider_quota_exceeded',
    'embedding_provider_network_error',
    'qdrant_lock_busy',
    'qdrant_path_permission_denied'
  ].includes(diagnosticCode);
  const runtimeAvailable = (['available', 'ok'].includes(statusValue) && diagnosticCode === 'mem0_available') ||
    (runtimeStillAvailable && Boolean(runtimeVersion || result.selected_python || result.raw?.selected_python));
  const resultCount = liveResultItems(result).length;
  const previousRecordsCount = Number(previous?.records_count || 0);
  const previousRetrievalCount = Number(previous?.last_retrieval_count || 0);
  const recordsCount = result.operation === 'list' && result.status === 'ok'
    ? resultCount
    : (result.operation === 'remember' && result.persisted && previous?.records_count !== undefined
      ? previousRecordsCount + 1
      : (result.operation === 'forget' && result.deleted && previous?.records_count !== undefined
        ? Math.max(0, previousRecordsCount - 1)
        : previousRecordsCount));
  const lastRetrievalCount = ['search', 'recall'].includes(result.operation) && result.status === 'ok'
    ? resultCount
    : previousRetrievalCount;
  return {
    schema_version: '3.3.0',
    provider_id: 'mem0-oss',
    adapter_id: 'live',
    checked_at: checkedAt,
    last_live_health_check: result.operation === 'health'
      ? checkedAt
      : previous?.last_live_health_check || (previous?.operation === 'health' ? previous?.checked_at || null : null),
    operation: result.operation,
    status: result.status,
    runtime_health: result.runtime_health || (storageUnavailable ? 'storage_unavailable' : (runtimeAvailable ? 'ok' : 'not_available')),
    diagnostic_code: diagnosticCode,
    selected_python: result.selected_python || null,
    version: runtimeVersion,
    expected_version: expectedVersion,
    runtime_available: runtimeAvailable,
    package_installed: runtimeAvailable,
    network_calls: result.network_calls || 'not_run',
    records_count: recordsCount,
    last_retrieval_count: lastRetrievalCount,
    last_retrieval_query: ['search', 'recall'].includes(result.operation) ? result.query || null : previous?.last_retrieval_query || null,
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only',
    live_operations_require_explicit_consent: true
  };
}

function print(result, json) {
  console.log(JSON.stringify(result, null, 2));
}

function help() {
  return {
    schema_version: '3.3.0',
    tool: 'memory-mem0.js',
    usage: 'node .knowledge/tools/memory-mem0.js <command> [query] [options] --json',
    commands: [
      { name: 'health', usage: 'node .knowledge/tools/memory-mem0.js health --adapter live --json', network_calls: 'not_run' },
      { name: 'list', usage: 'node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json', network_calls: 'not_run_local_qdrant_may_download_local_fastembed_model' },
      { name: 'add', usage: 'node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json', network_calls: 'may_call_embedding_provider' },
      { name: 'remember', usage: 'node .knowledge/tools/memory-mem0.js remember --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json', network_calls: 'may_call_embedding_provider' },
      { name: 'search', usage: 'node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json', network_calls: 'may_call_embedding_provider' },
      { name: 'recall', usage: 'node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json', network_calls: 'may_call_embedding_provider' },
      { name: 'delete', usage: 'node .knowledge/tools/memory-mem0.js delete --adapter live --yes-live-memory --id <memory-id> --json', network_calls: 'not_run_local_qdrant_may_download_local_fastembed_model' },
      { name: 'forget', usage: 'node .knowledge/tools/memory-mem0.js forget --adapter live --yes-live-memory --id <memory-id> --json', network_calls: 'not_run_local_qdrant_may_download_local_fastembed_model' },
      { name: 'sync-report', usage: 'node .knowledge/tools/memory-mem0.js sync-report --json', network_calls: 'not_run' },
      { name: 'export-redacted', usage: 'node .knowledge/tools/memory-mem0.js export-redacted --json', network_calls: 'not_run' },
      { name: 'help', usage: 'node .knowledge/tools/memory-mem0.js help --json', network_calls: 'not_run' }
    ],
    live_requires_explicit_consent: true,
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  };
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const flags = parsed.flags;
  const command = parsed.positional[0] || (flags.help ? 'help' : 'health');
  if (flags.help || command === 'help') {
    const result = help();
    print(result, Boolean(flags.json));
    return result;
  }
  const context = resolveKnowledgeContext(flags);
  const adapter = adapterFor(context, flags);
  const input = inputFromFlags(flags, parsed.positional);
  let result;
  if (command === 'health') result = adapter.health(input);
  else if (command === 'add' || command === 'remember') result = adapter.remember(input);
  else if (command === 'search') result = typeof adapter.search === 'function' ? adapter.search(input) : { ...adapter.recall(input), operation: 'search' };
  else if (command === 'recall') result = adapter.recall(input);
  else if (command === 'list') result = adapter.list(input);
  else if (command === 'delete' || command === 'forget') result = adapter.forget(input);
  else if (command === 'sync-report') result = syncReport(context, adapter.adapterId);
  else if (command === 'export-redacted') result = adapter.exportRedacted(input);
  else throw new Error(`Unknown Mem0 command: ${command}`);

  result = withStatus(result, context);
  print(result, Boolean(flags.json));
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const parsed = parseCliArgs(process.argv.slice(2));
    const result = advisoryEnvelope('mem0-oss', selectedAdapter(parsed.flags), 'error', { status: 'error', error: error.message });
    if (parsed.flags.json) console.log(JSON.stringify(result, null, 2));
    else console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = main;
module.exports.adapterFor = adapterFor;
module.exports.publicRecord = publicRecord;
module.exports.__test = {
  classifyMem0RuntimeFailure,
  configuredPythonCandidates,
  filterSafeStderr,
  liveImportOptions,
  liveMem0TimeoutMs,
  liveProcessEnv,
  encodeLivePythonPayload,
  hasExplicitLiveConfig,
  isContainedLockBusyError,
  livePublicRecords,
  mem0RuntimeDirForConfig,
  normalizeDiagnosticCode,
  pythonDiscoveryOptions,
  restoreCanonicalLiveConfig,
  runtimeStatusSnapshot
};
