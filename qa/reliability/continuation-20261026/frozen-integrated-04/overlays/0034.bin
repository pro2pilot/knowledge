'use strict';

// This is the executable-primitive guard for the fixed, native-guarded macOS
// operation writer. It is NOT a JavaScript sandbox: repository code is never
// evaluated in this process. The native launcher must first verify that this
// entire package (including this entrypoint and its dependency graph) is
// administrator-owned, immutable to the project identity, and outside the
// writable workspace. All project commands belong to the separate RUID scope.
// Install before loading any other package module, so no dependency can retain
// a pre-guard launch primitive. The authority sentinel uses a different role.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');
const childProcess = require('node:child_process');
const workerThreads = require('node:worker_threads');
const cluster = require('node:cluster');
const fail = code => Object.assign(new Error(code), { code });
const PACKAGE_ROOT = path.resolve(__dirname, '../..');
const forbiddenBuiltins = new Set(['module', 'vm', 'worker_threads', 'cluster',
  'inspector', 'inspector/promises', 'repl', 'test', 'test/reporters', 'sqlite']);
const builtins = new Set(Module.builtinModules.map(name => name.replace(/^node:/, '')));
let installed = null;

function lock(object, key, value) {
  const current = Object.getOwnPropertyDescriptor(object, key);
  if (current && !current.configurable && (!current.writable || current.get || current.set)) {
    if (current.value !== value) throw fail('macos_worker_envelope_primitive_locked');
    return;
  }
  Object.defineProperty(object, key, { value, enumerable: current?.enumerable ?? true,
    writable: false, configurable: false });
}

function inside(root, file) {
  const relative = path.relative(root, file);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

function ordinaryFile(file, maximum = 16 * 1024 * 1024) {
  if (typeof file !== 'string' || file !== path.resolve(file) || !inside(PACKAGE_ROOT, file)) {
    throw fail('macos_worker_module_forbidden');
  }
  let current = PACKAGE_ROOT;
  for (const part of ['', ...path.relative(PACKAGE_ROOT, path.dirname(file)).split(path.sep).filter(Boolean)]) {
    if (part) current = path.join(current, part);
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw fail('macos_worker_module_forbidden');
  }
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > maximum ||
      fs.realpathSync(file) !== file) throw fail('macos_worker_module_forbidden');
  return stat;
}

function nativeAllowed(file) {
  const binary = path.join(PACKAGE_ROOT, 'tools/lib/native', `${process.platform}-${process.arch}`, 'lock-publication.node');
  if (file !== binary) throw fail('macos_worker_native_forbidden');
  ordinaryFile(binary);
  const manifestFile = path.join(path.dirname(binary), 'lock-publication.manifest.json');
  const sourceFile = path.join(PACKAGE_ROOT, 'tools/native/lock-publication.c');
  ordinaryFile(manifestFile, 16384);ordinaryFile(sourceFile, 262144);
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const digest = value => crypto.createHash('sha256').update(value).digest('hex');
  const bytes = fs.readFileSync(binary);
  if (manifest.schema_version !== 'knowledge-lock-native-binary.v1' || manifest.platform !== process.platform ||
      manifest.architecture !== process.arch || manifest.binary !== 'lock-publication.node' || manifest.napi_version !== 8 ||
      manifest.binary_bytes !== bytes.length || manifest.binary_sha256 !== digest(bytes) ||
      manifest.source_sha256 !== digest(fs.readFileSync(sourceFile))) throw fail('macos_worker_native_forbidden');
}

function checkedModule(file) {
  ordinaryFile(file);
  const extension = path.extname(file);
  if (extension === '.node') nativeAllowed(file);
  else if (!['.js', '.cjs', '.json'].includes(extension)) throw fail('macos_worker_module_forbidden');
  return file;
}

function checkedBuiltin(request) {
  const name = request.replace(/^node:/, '');
  if (!builtins.has(name) || name.startsWith('internal/') || name.startsWith('_') || forbiddenBuiltins.has(name)) {
    throw fail('macos_worker_module_forbidden');
  }
  return name;
}

function install(options = {}) {
  if (!options || typeof options !== 'object' || options.protectedRoot !== PACKAGE_ROOT ||
      fs.realpathSync(PACKAGE_ROOT) !== PACKAGE_ROOT) throw fail('macos_worker_envelope_root_invalid');
  if (installed) return installed;

  // The main fixed entrypoint is necessarily cached; only it and this module
  // may precede installation. Builtins have no entries in require.cache.
  for (const file of Object.keys(require.cache)) {
    if (file !== __filename && file !== require.main?.filename) throw fail('macos_worker_envelope_late_install');
  }
  if (require.main) checkedModule(require.main.filename);
  checkedModule(__filename);

  const denySpawn = () => { throw fail('macos_worker_spawn_forbidden'); };
  const denyBinding = () => { throw fail('macos_worker_binding_forbidden'); };
  for (const key of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) lock(childProcess, key, denySpawn);
  lock(childProcess.ChildProcess.prototype, 'spawn', denySpawn);
  lock(workerThreads, 'Worker', denySpawn);
  lock(cluster, 'fork', denySpawn);
  lock(process, 'binding', denyBinding);
  lock(process, '_linkedBinding', denyBinding);
  if (typeof process.execve === 'function') lock(process, 'execve', denySpawn);

  const originalDlopen = process.dlopen;
  lock(process, 'dlopen', function guardedDlopen(target, file, flags) {
    nativeAllowed(file);
    return originalDlopen.call(process, target, file, flags);
  });

  const originalLoad = Module._load;
  const originalResolve = Module._resolveFilename;
  lock(Module, '_load', function guardedLoad(request, parent, isMain) {
    if (typeof request !== 'string' || request.includes('\0')) throw fail('macos_worker_module_forbidden');
    const name = request.replace(/^node:/, '');
    if (request.startsWith('node:') || builtins.has(name)) checkedBuiltin(request);
    else checkedModule(originalResolve.call(Module, request, parent, isMain));
    return originalLoad.call(Module, request, parent, isMain);
  });

  const originalModuleLoad = Module.prototype.load;
  lock(Module.prototype, 'load', function guardedModuleLoad(file) {
    checkedModule(file);return originalModuleLoad.call(this, file);
  });
  const originalCompile = Module.prototype._compile;
  lock(Module.prototype, '_compile', function guardedCompile(content, file) {
    checkedModule(file);
    // Prevent a caller from using a protected filename as cover for generated
    // or project-supplied source through the CommonJS compilation interface.
    if (typeof content !== 'string' || content !== fs.readFileSync(file, 'utf8')) throw fail('macos_worker_module_forbidden');
    return originalCompile.call(this, content, file);
  });

  if (typeof process.getBuiltinModule === 'function') {
    lock(process, 'getBuiltinModule', name => {
      checkedBuiltin(name);return originalLoad.call(Module, name, module, false);
    });
  }
  // Keep any later ESM view of the builtins consistent with the guarded CJS
  // exports. The fixed operation graph itself contains no dynamic import/eval.
  Module.syncBuiltinESMExports();
  installed = Object.freeze({ schema_version: 'knowledge-macos-worker-envelope.v1',
    protected_root: PACKAGE_ROOT, subprocess_policy: 'deny_all', repository_modules: 'deny_all' });
  return installed;
}

module.exports = Object.freeze({ install });
