'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const PYTHON_PROBE = [
  'import json, sys',
  'print(json.dumps({"ok": True, "executable": sys.executable, "version": list(sys.version_info[:3]), "prefix": sys.prefix}, default=str))'
].join('; ');

function normalizeKey(value, platform = process.platform) {
  const text = String(value || '').trim();
  return platform === 'win32' ? text.toLowerCase() : text;
}

function quoteForCommand(value) {
  const text = String(value || '');
  return /\s/.test(text) ? `"${text.replace(/"/g, '\\"')}"` : text;
}

function safeExists(filePath) {
  try { return fs.existsSync(filePath); } catch { return false; }
}

function safeReaddir(dirPath) {
  try { return fs.readdirSync(dirPath, { withFileTypes: true }); } catch { return []; }
}

function addCandidate(candidates, seen, candidate, platform = process.platform) {
  const command = String(candidate.command || '').trim();
  if (!command) return;
  const key = normalizeKey(command, platform);
  if (seen.has(key)) return;
  seen.add(key);
  candidates.push({
    command,
    source: candidate.source || 'unknown',
    explicit: Boolean(candidate.explicit),
    from_launcher: Boolean(candidate.from_launcher),
    from_standard_path: Boolean(candidate.from_standard_path)
  });
}

function addPythonFromDir(candidates, seen, dirPath, source, platform) {
  if (!dirPath) return;
  const exe = platform === 'win32' ? 'python.exe' : 'python';
  addCandidate(candidates, seen, { command: path.join(dirPath, exe), source, from_standard_path: true }, platform);
}

function addChildrenMatching(candidates, seen, root, dirPattern, childRel, source, platform) {
  if (!root || !safeExists(root)) return;
  for (const entry of safeReaddir(root)) {
    if (!entry.isDirectory() || !dirPattern.test(entry.name)) continue;
    addCandidate(candidates, seen, {
      command: path.join(root, entry.name, childRel),
      source,
      from_standard_path: true
    }, platform);
  }
}

function addFilesMatching(candidates, seen, root, filePattern, source, platform) {
  if (!root || !safeExists(root)) return;
  for (const entry of safeReaddir(root)) {
    if (!entry.isFile() || !filePattern.test(entry.name)) continue;
    addCandidate(candidates, seen, {
      command: path.join(root, entry.name),
      source,
      from_standard_path: true
    }, platform);
  }
}

function extractPythonExePaths(text) {
  const paths = [];
  const re = /(?:[A-Za-z]:\\|\\\\)[^\r\n]*?python(?:\d+(?:\.\d+)*)?\.exe/gi;
  let match;
  while ((match = re.exec(String(text || '')))) {
    paths.push(match[0].trim());
  }
  return paths;
}

function runCommand(command, args, options = {}) {
  const runner = options.runCommand || ((cmd, argv, runOptions) => spawnSync(cmd, argv, runOptions));
  return runner(command, args, {
    encoding: 'utf8',
    env: options.env || process.env,
    windowsHide: true,
    timeout: Number(options.timeoutMs || 5000),
    shell: false
  });
}

function addLauncherCandidates(candidates, seen, options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== 'win32') return;
  const commands = [
    ['py', ['list', '-f', 'exe', '-1'], 'windows_py_list'],
    ['py', ['list', '--format=exe', '--one'], 'windows_py_list'],
    ['py', ['-0p'], 'windows_py_legacy_list'],
    ['pymanager', ['list', '-f', 'exe', '-1'], 'windows_pymanager_list'],
    ['pymanager', ['list', '--format=exe', '--one'], 'windows_pymanager_list']
  ];
  for (const [command, args, source] of commands) {
    const res = runCommand(command, args, options);
    if (res.error || res.status !== 0) continue;
    const output = `${res.stdout || ''}\n${res.stderr || ''}`;
    for (const pythonPath of extractPythonExePaths(output)) {
      addCandidate(candidates, seen, {
        command: pythonPath,
        source,
        from_launcher: true
      }, platform);
    }
  }
}

function addStandardWindowsCandidates(candidates, seen, options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  if (platform !== 'win32') return;

  addChildrenMatching(candidates, seen, path.join(env.LOCALAPPDATA || '', 'Programs', 'Python'), /^Python/i, 'python.exe', 'windows_localappdata_programs_python', platform);
  addChildrenMatching(candidates, seen, env.ProgramFiles, /^Python/i, 'python.exe', 'windows_program_files_python', platform);
  addChildrenMatching(candidates, seen, env['ProgramFiles(x86)'], /^Python/i, 'python.exe', 'windows_program_files_x86_python', platform);
  addFilesMatching(candidates, seen, path.join(env.LOCALAPPDATA || '', 'Python', 'bin'), /^python(?:\d+(?:\.\d+)*)?\.exe$/i, 'windows_python_manager_bin', platform);

  const systemDrive = env.SystemDrive || 'C:';
  addChildrenMatching(candidates, seen, `${systemDrive}\\`, /^Python/i, 'python.exe', 'windows_system_drive_python', platform);

  for (const base of [env.USERPROFILE, env.LOCALAPPDATA, env.ProgramData]) {
    for (const name of ['miniconda3', 'anaconda3', 'miniforge3', 'mambaforge']) {
      addPythonFromDir(candidates, seen, base ? path.join(base, name) : '', `windows_${name}`, platform);
    }
  }
}

function addStandardPosixCandidates(candidates, seen, options = {}) {
  const platform = options.platform || process.platform;
  if (platform === 'win32') return;
  for (const command of ['python3', 'python']) {
    addCandidate(candidates, seen, { command, source: 'path_command' }, platform);
  }
}

function collectPythonCandidates(options = {}) {
  const flags = options.flags || {};
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const candidates = [];
  const seen = new Set();

  if (flags.python) addCandidate(candidates, seen, { command: flags.python, source: 'cli --python', explicit: true }, platform);
  if (env.KNOWLEDGE_MEM0_PYTHON) addCandidate(candidates, seen, { command: env.KNOWLEDGE_MEM0_PYTHON, source: 'KNOWLEDGE_MEM0_PYTHON', explicit: true }, platform);
  if (env.MEM0_PYTHON) addCandidate(candidates, seen, { command: env.MEM0_PYTHON, source: 'MEM0_PYTHON', explicit: true }, platform);

  const venv = env.VIRTUAL_ENV || '';
  const conda = env.CONDA_PREFIX || '';
  if (venv) addPythonFromDir(candidates, seen, platform === 'win32' ? path.join(venv, 'Scripts') : path.join(venv, 'bin'), 'VIRTUAL_ENV', platform);
  if (conda) addPythonFromDir(candidates, seen, conda, 'CONDA_PREFIX', platform);

  for (const command of platform === 'win32' ? ['python', 'python3'] : []) {
    addCandidate(candidates, seen, { command, source: 'path_command' }, platform);
  }
  addStandardPosixCandidates(candidates, seen, options);
  addLauncherCandidates(candidates, seen, options);
  addStandardWindowsCandidates(candidates, seen, options);

  return candidates;
}

function isPathLike(command, platform = process.platform) {
  if (path.isAbsolute(command)) return true;
  if (platform === 'win32' && /^[A-Za-z]:\\/.test(command)) return true;
  return command.includes('/') || command.includes('\\');
}

function classifyError(error) {
  const code = error && error.code;
  if (code === 'ENOENT') return 'python_not_found';
  if (code === 'ETIMEDOUT') return 'python_timeout';
  if (code === 'EACCES' || code === 'EPERM') return 'python_permission_error';
  return 'python_invalid';
}

function friendlyError(error) {
  const code = error && error.code;
  if (code === 'ENOENT') return 'candidate command was not found';
  if (code === 'ETIMEDOUT') return 'candidate command timed out';
  if (code === 'EACCES' || code === 'EPERM') return 'permission denied while launching candidate';
  return 'candidate could not be launched';
}

function validatePythonCandidate(candidate, options = {}) {
  const platform = options.platform || process.platform;
  const command = candidate.command;
  if (isPathLike(command, platform) && !safeExists(command)) {
    return { ...candidate, status: 'not_found', diagnostic_code: 'python_not_found', error: 'candidate path does not exist' };
  }
  const res = runCommand(command, ['-c', PYTHON_PROBE], options);
  if (res.error) {
    return { ...candidate, status: 'error', diagnostic_code: classifyError(res.error), error: friendlyError(res.error) };
  }
  const stdout = String(res.stdout || '').trim();
  let parsed = null;
  try { parsed = JSON.parse(stdout || '{}'); } catch {}
  if (res.status !== 0 || !parsed?.ok || !parsed.executable) {
    const stderr = String(res.stderr || '').trim().slice(0, 500);
    return {
      ...candidate,
      status: 'error',
      diagnostic_code: res.status === 0 ? 'python_invalid' : 'python_not_usable',
      exit_code: res.status,
      error: stderr || stdout.slice(0, 500) || 'candidate did not return Python probe JSON'
    };
  }
  return {
    ...candidate,
    status: 'ok',
    diagnostic_code: 'python_available',
    executable: parsed.executable,
    version: Array.isArray(parsed.version) ? parsed.version.join('.') : String(parsed.version || ''),
    prefix: parsed.prefix || null,
    windows_apps_alias: platform === 'win32' && /\\WindowsApps\\/i.test(String(parsed.executable || command))
  };
}

function chooseDiagnostic(results) {
  if (results.some((item) => item.diagnostic_code === 'python_permission_error')) return 'python_permission_error';
  if (results.some((item) => item.diagnostic_code === 'python_timeout')) return 'python_timeout';
  if (results.some((item) => item.diagnostic_code === 'python_not_usable' || item.diagnostic_code === 'python_invalid')) return 'python_not_usable';
  return 'python_not_found';
}

function discoveryNextCommands() {
  return [
    'Install Python or pass --python "<path-to-python.exe>"',
    'node .knowledge/tools/memory-mem0.js health --adapter live --python "<path-to-python.exe>" --json'
  ];
}

function discoverPython(options = {}) {
  const candidates = options.candidates || collectPythonCandidates(options);
  const validate = options.validateCandidate || ((candidate) => validatePythonCandidate(candidate, options));
  const results = [];
  for (const candidate of candidates) {
    const result = validate(candidate);
    results.push(result);
    if (result.status === 'ok') {
      return {
        status: 'found',
        diagnostic_code: 'python_available',
        selected: result,
        candidates_checked: results.length,
        candidates: results
      };
    }
    if (candidate.explicit) {
      return {
        status: 'not_found',
        diagnostic_code: result.diagnostic_code || 'python_not_found',
        selected: null,
        candidates_checked: results.length,
        candidates: results,
        next_commands: discoveryNextCommands()
      };
    }
  }
  return {
    status: 'not_found',
    diagnostic_code: chooseDiagnostic(results),
    selected: null,
    candidates_checked: results.length,
    candidates: results,
    next_commands: discoveryNextCommands()
  };
}

function checkPythonModule(pythonCommand, moduleName, options = {}) {
  const script = [
    'import importlib, json',
    `module = importlib.import_module(${JSON.stringify(moduleName)})`,
    'print(json.dumps({"ok": True, "version": getattr(module, "__version__", None)}, default=str))'
  ].join('; ');
  const res = runCommand(pythonCommand, ['-c', script], options);
  if (res.error) return { ok: false, diagnostic_code: classifyError(res.error), error: friendlyError(res.error) };
  let parsed = null;
  try { parsed = JSON.parse(String(res.stdout || '').trim() || '{}'); } catch {}
  if (res.status === 0 && parsed?.ok) return { ok: true, version: parsed.version || null };
  const text = `${res.stderr || ''}\n${res.stdout || ''}`;
  const missing = /ModuleNotFoundError|No module named/i.test(text);
  return {
    ok: false,
    diagnostic_code: missing ? `${moduleName}_package_missing` : 'python_module_error',
    error: text.trim().slice(0, 1000) || `import ${moduleName} failed`
  };
}

function packageInstallCommand(pythonCommand, packageSpec) {
  return `${quoteForCommand(pythonCommand)} -m pip install ${packageSpec}`;
}

module.exports = {
  PYTHON_PROBE,
  collectPythonCandidates,
  discoverPython,
  validatePythonCandidate,
  checkPythonModule,
  packageInstallCommand,
  extractPythonExePaths,
  quoteForCommand
};
