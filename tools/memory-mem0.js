#!/usr/bin/env node
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const { providerStateDir, findManifest, buildExternalMemoryReport } = require('./lib/memory-providers');
const {
  checkPythonModule,
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
  return code === 'python_invalid' ? 'python_not_usable' : code;
}

function adapterFile(context) {
  const manifest = findManifest(context, 'mem0-oss');
  return path.join(providerStateDir(context, manifest), 'adapter-records.jsonl');
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

function liveConfig(flags) {
  if (flags.configJson) return String(flags.configJson);
  if (flags.config) {
    const fs = require('fs');
    return fs.readFileSync(path.resolve(String(flags.config)), 'utf8');
  }
  return process.env.KNOWLEDGE_MEM0_CONFIG_JSON || '{}';
}

function pythonDiscoveryOptions(flags, timeoutMs = DEFAULT_FAST_PYTHON_TIMEOUT_MS) {
  return {
    flags,
    timeoutMs: numericTimeout(pythonTimeoutFlag(flags), timeoutMs),
    env: process.env
  };
}

function liveHealthOp(payload) {
  return payload && payload.op === 'health';
}

function liveMem0TimeoutMs(flags, payload) {
  const fallback = liveHealthOp(payload) ? DEFAULT_LIVE_HEALTH_TIMEOUT_MS : DEFAULT_FAST_PYTHON_TIMEOUT_MS;
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
  if (code === 'ENOENT') return 'python_not_found';
  if (code === 'ETIMEDOUT') return 'python_timeout';
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
      'Install Python or pass --python "<path-to-python.exe>"',
      'node .knowledge/tools/memory-mem0.js health --adapter live --python "<path-to-python.exe>" --json'
    ];
  }
  return [
    packageInstallCommand(selectedPython, 'mem0ai==2.0.4'),
    'node .knowledge/tools/memory-mem0.js health --adapter live --json'
  ];
}

function liveFailureNextCommands(diagnosticCode, selectedPython) {
  if (diagnosticCode === 'mem0_package_missing') return pythonInstallNextCommands(selectedPython);
  if (diagnosticCode === 'python_timeout') {
    const pythonArg = selectedPython ? ` --python ${quoteForCommand(selectedPython)}` : '';
    return [
      'Retry once after Python warms up; first import mem0 on Windows can be slower than normal.',
      `node .knowledge/tools/memory-mem0.js health --adapter live${pythonArg} --timeout-ms 60000 --json`
    ];
  }
  if (diagnosticCode === 'mem0_storage_permission_error') {
    return [
      'Configure Mem0/Qdrant to use a writable persistent storage directory, then rerun the live command.',
      'Check directory permissions for qdrant lock files; .knowledge will not delete locks or repair permissions automatically.'
    ];
  }
  return ['Fix the selected Python runtime, then rerun node .knowledge/tools/memory-mem0.js health --adapter live --json'];
}

function classifyMem0RuntimeFailure(parsed = {}, res = {}) {
  const text = [
    parsed.error,
    parsed.stderr,
    parsed.stdout,
    res.stderr,
    res.stdout
  ].filter(Boolean).join('\n');
  if (/permission denied/i.test(text) && /(?:qdrant|\.lock|lock[- ]?file)/i.test(text)) {
    return {
      diagnostic_code: 'mem0_storage_permission_error',
      next_commands: liveFailureNextCommands('mem0_storage_permission_error')
    };
  }
  return null;
}

function runLiveMem0(flags, payload) {
  const discovery = discoverPython(pythonDiscoveryOptions(flags));
  if (!discovery.selected) {
    const diagnosticCode = normalizeDiagnosticCode(discovery.diagnostic_code || 'python_not_found');
    return redactSecrets({
      ok: false,
      diagnostic_code: diagnosticCode,
      error: 'No usable Python runtime was found by bounded discovery.',
      python_discovery: discovery,
      selected_python: null,
      next_commands: diagnosticCode === 'python_not_found'
        ? (discovery.next_commands || pythonInstallNextCommands(null))
        : liveFailureNextCommands(diagnosticCode, null)
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
      next_commands: liveFailureNextCommands(diagnosticCode, selectedPython)
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
      version: moduleCheck.version || null
    });
  }
  const script = String.raw`
import json, os, sys
payload = json.loads(sys.stdin.read() or "{}")
try:
    import mem0
    from mem0 import Memory
except Exception as exc:
    print(json.dumps({"ok": False, "error": "mem0 import failed: " + str(exc)}))
    sys.exit(0)

def make_memory():
    config = json.loads(os.environ.get("KNOWLEDGE_MEM0_CONFIG_JSON") or "{}")
    if hasattr(Memory, "from_config"):
        return Memory.from_config(config) if config else Memory()
    try:
        return Memory(config=config) if config else Memory()
    except TypeError:
        return Memory()

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
            result = memory.search(payload.get("query") or "", user_id=user_id)
            result = {"ok": True, "operation": op, "raw": result}
        elif op == "list":
            result = memory.get_all(user_id=user_id)
            result = {"ok": True, "operation": op, "raw": result}
        elif op == "forget":
            memory.delete(memory_id=payload.get("id"))
            result = {"ok": True, "operation": op, "deleted": True}
        else:
            result = {"ok": False, "error": "unknown op"}
        close = getattr(memory, "close", None)
        if callable(close):
            close()
    print(json.dumps(result, default=str))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
`;
  const res = spawnSync(selectedPython, ['-c', script], {
    input: JSON.stringify(payload),
    encoding: 'utf8',
    env: {
      ...process.env,
      KNOWLEDGE_MEM0_CONFIG_JSON: liveConfig(flags)
    },
    windowsHide: true,
    timeout: liveMem0TimeoutMs(flags, payload)
  });
  let parsed = {};
  try { parsed = JSON.parse((res.stdout || '').trim() || '{}'); }
  catch { parsed = { ok: false, stdout: (res.stdout || '').trim() }; }
  if (res.error) {
    parsed.ok = false;
    parsed.diagnostic_code = classifyLivePythonError(res.error);
    parsed.error = friendlyLivePythonError(res.error, payload);
    parsed.next_commands = liveFailureNextCommands(parsed.diagnostic_code, selectedPython);
  }
  if (res.stderr) parsed.stderr = res.stderr.trim().slice(0, 2000);
  const runtimeFailure = classifyMem0RuntimeFailure(parsed, res);
  if (!parsed.ok && runtimeFailure) {
    parsed.diagnostic_code = runtimeFailure.diagnostic_code;
    parsed.next_commands = runtimeFailure.next_commands;
  }
  const diagnosticCode = normalizeDiagnosticCode(parsed.ok ? 'mem0_available' : (parsed.diagnostic_code || 'mem0_runtime_error'));
  return redactSecrets({
    ...parsed,
    diagnostic_code: diagnosticCode,
    python_discovery: discovery,
    selected_python: selectedPython,
    next_commands: parsed.next_commands || (parsed.ok ? [] : liveFailureNextCommands(diagnosticCode, selectedPython)),
    version: parsed.version || moduleCheck.version || null
  });
}

function liveHealthWarnings(raw) {
  if (raw.ok) return [];
  if (raw.diagnostic_code === 'mem0_package_missing') {
    return ['Python was found, but mem0ai is not installed in that Python environment.'];
  }
  if (raw.diagnostic_code === 'python_timeout') {
    return ['Live Mem0 health timed out. First import mem0 on Windows can be slower than warm checks; the default live health timeout is 30000 ms.'];
  }
  if (raw.diagnostic_code === 'mem0_storage_permission_error') {
    return ['Live Mem0 runtime could import, but its storage backend reported a qdrant lock/permission error. Configure writable persistent storage and rerun the live command.'];
  }
  return ['Live Mem0 runtime was not available or not configured.'];
}

function liveAdapter(flags) {
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
      const raw = runLiveMem0(flags, { op: 'health' });
      return advisoryEnvelope(providerId, adapterId, 'health', {
        status: raw.ok ? 'available' : 'runtime_not_installed',
        runtime_health: raw.ok ? 'ok' : 'not_available',
        live_runtime_checked: true,
        diagnostic_code: raw.diagnostic_code || (raw.ok ? 'mem0_available' : 'runtime_not_installed'),
        selected_python: raw.selected_python || null,
        python_discovery: raw.python_discovery || null,
        next_commands: raw.next_commands || [],
        raw: raw.ok ? { ok: true, version: raw.version || null } : {
          ok: false,
          diagnostic_code: raw.diagnostic_code || 'runtime_not_installed',
          error: raw.error || 'Live Mem0 runtime was not available or not configured.'
        },
        warnings: liveHealthWarnings(raw)
      });
    },
    remember(input = {}) {
      requireConsent('remember');
      const raw = runLiveMem0(flags, { op: 'remember', text: input.text, user_id: input.user_id, infer: Boolean(flags.infer) });
      return advisoryEnvelope(providerId, adapterId, 'remember', {
        status: raw.ok ? 'ok' : 'error',
        persisted: Boolean(raw.ok),
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
      const raw = runLiveMem0(flags, { op: 'recall', query: input.query, user_id: input.user_id });
      return advisoryEnvelope(providerId, adapterId, 'recall', {
        status: raw.ok ? 'ok' : 'error',
        query: input.query || '',
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
      const raw = runLiveMem0(flags, { op: 'list', user_id: input.user_id });
      return advisoryEnvelope(providerId, adapterId, 'list', {
        status: raw.ok ? 'ok' : 'error',
        diagnostic_code: raw.diagnostic_code || (raw.ok ? 'mem0_available' : 'mem0_runtime_error'),
        selected_python: raw.selected_python || null,
        python_discovery: raw.python_discovery || null,
        next_commands: raw.next_commands || [],
        raw
      });
    },
    forget(input = {}) {
      requireConsent('forget');
      const raw = runLiveMem0(flags, { op: 'forget', id: input.id, user_id: input.user_id });
      return advisoryEnvelope(providerId, adapterId, 'forget', {
        status: raw.ok ? 'ok' : 'error',
        deleted: Boolean(raw.deleted),
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
  if (adapter === 'live') return liveAdapter(flags);
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

function print(result, json) {
  console.log(JSON.stringify(result, null, 2));
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const flags = parsed.flags;
  const command = parsed.positional[0] || 'health';
  const context = resolveKnowledgeContext(flags);
  const adapter = adapterFor(context, flags);
  const input = inputFromFlags(flags, parsed.positional);
  let result;
  if (command === 'health') result = adapter.health(input);
  else if (command === 'add' || command === 'remember') result = adapter.remember(input);
  else if (command === 'search' || command === 'recall') result = adapter.recall(input);
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
  liveImportOptions,
  liveMem0TimeoutMs,
  normalizeDiagnosticCode,
  pythonDiscoveryOptions
};
