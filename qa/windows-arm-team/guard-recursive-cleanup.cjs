'use strict';
// QA cooperative deletion guard for fs.rmSync(recursive:true) in this process.
// Not an OS sandbox, not a guard for arbitrary APIs/descendants, not race-proof.
const fs = require('node:fs'), path = require('node:path'), cp = require('node:child_process');
const { threadId, isMainThread } = require('node:worker_threads');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const requested = process.env.KNOWLEDGE_QA_OWNED_TEMP;
const samePath = (a, b) => process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
const within = (parent, child) => {
  const p = process.platform === 'win32' ? parent.toLowerCase() : parent, c = process.platform === 'win32' ? child.toLowerCase() : child;
  return c.startsWith(p + path.sep);
};
function lexical(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.length > 1024 || value.startsWith('\\\\') || !samePath(path.resolve(value), value)) fail('D5_GUARD_PATH');
  const rest = value.slice(path.parse(value).root.length);
  for (const part of rest.split(path.sep)) {
    if (!part || part === '.' || part === '..' || /[\x00-\x1f<>"|?*~]/.test(part) || part.includes(':') || /[. ]$/.test(part) ||
        /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)) fail('D5_GUARD_PATH');
  }
}
function id(stat) { return `${stat.dev}:${stat.ino}`; }
function physical(value, allowMissing = false) {
  const chain = []; let item = value;
  for (;;) { chain.push(item); const parent = path.dirname(item); if (parent === item) break; item = parent; }
  let missing = false;
  for (const current of chain.reverse()) {
    if (missing) continue;
    let st;
    try { st = fs.lstatSync(current, { bigint: true }); }
    catch (error) { if (allowMissing && error.code === 'ENOENT') { missing = true; continue; } throw error; }
    if (st.isSymbolicLink() || !samePath(fs.realpathSync.native(current), current)) fail('D5_GUARD_ALIAS');
  }
  return !missing;
}
lexical(requested); physical(requested);
const root = fs.realpathSync.native(requested), rootStat = fs.lstatSync(root, { bigint: true });
if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail('D5_GUARD_ROOT');
const rootId = id(rootStat);
const powershell = process.env.KNOWLEDGE_QA_PWSH_EXE;
if (process.platform === 'win32') { lexical(powershell); physical(powershell); if (!fs.lstatSync(powershell).isFile()) fail('D5_GUARD_PWSH'); }
function rootUnchanged() { physical(root); const current = fs.lstatSync(root, { bigint: true }); if (!current.isDirectory() || id(current) !== rootId) fail('D5_GUARD_ROOT_CHANGED'); }
function windowsReparseInspection(target) {
  if (process.platform !== 'win32') return;
  const env = Object.create(null);
  for (const key of ['SystemRoot', 'WINDIR', 'SystemDrive', 'COMSPEC', 'PATHEXT']) if (process.env[key]) env[key] = process.env[key];
  env.TEMP = root; env.TMP = root;
  let result;
  try { result = cp.spawnSync(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'guard-path-check.ps1'), '-Root', root, '-Target', target],
    { env, cwd: root, windowsHide: true, timeout: 5000, maxBuffer: 4096, encoding: 'utf8' }); }
  catch { fail('D5_GUARD_REPARSE_INSPECTOR'); }
  if (result.error || result.signal || result.status !== 0 || result.stdout.trim() !== 'D5_PHYSICAL_PATH_OK' || result.stderr.trim()) fail('D5_GUARD_REPARSE_INSPECTOR');
}
function captureTree(target) {
  const rows = []; let count = 0;
  function walk(current, depth) {
    if (++count > 20000 || depth > 64) fail('D5_GUARD_TREE_LIMIT');
    lexical(current); physical(current); const st = fs.lstatSync(current, { bigint: true });
    if (st.isSymbolicLink() || !(st.isDirectory() || st.isFile()) || st.isFile() && st.nlink !== 1n) fail('D5_GUARD_NONREGULAR');
    const row = { path: current, identity: id(st), directory: st.isDirectory() };
    if (row.directory) for (const name of fs.readdirSync(current)) walk(path.join(current, name), depth + 1);
    rows.push(row);
  }
  walk(target, 0); return rows;
}
const originalRmSync = fs.rmSync;
fs.rmSync = function guardedRmSync(target, options) {
  if (!options?.recursive) return originalRmSync.call(fs, target, options);
  lexical(target);
  if (!within(root, target)) fail('D5_GUARD_OUTSIDE');
  rootUnchanged(); const exists = physical(target, !!options.force);
  windowsReparseInspection(target); rootUnchanged();
  if (!exists) return; // A checked missing force target is a no-op; no second recursive OS traversal.
  const rows = captureTree(target);
  for (const row of rows) {
    rootUnchanged(); physical(row.path);
    const current = fs.lstatSync(row.path, { bigint: true });
    if (id(current) !== row.identity || current.isSymbolicLink() || current.isDirectory() !== row.directory) fail('D5_GUARD_IDENTITY_CHANGED');
    if (row.directory) {
      if (fs.readdirSync(row.path).length) fail('D5_GUARD_NEW_CHILD');
      fs.rmdirSync(row.path);
    } else {
      if (!current.isFile() || current.nlink !== 1n) fail('D5_GUARD_NONREGULAR');
      // Preserve read-only files on error; no broad chmod or retry semantics.
      fs.unlinkSync(row.path);
    }
  }
};
Object.defineProperty(globalThis, Symbol.for('knowledge.d5.guard'), { value: Object.freeze({ version: 2, root, recursiveOnly: true, notSandbox: true }), writable: false });
const proof = process.env.KNOWLEDGE_QA_GUARD_PROOF;
if (proof) {
  lexical(proof); physical(path.dirname(proof));
  if (samePath(proof, root) || within(root, proof)) fail('D5_GUARD_PROOF_LOCATION');
  let st; try { st = fs.lstatSync(proof, { bigint: true }); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (st && (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1n || st.size > 65536n)) fail('D5_GUARD_PROOF_FILE');
  const fd = fs.openSync(proof, fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
  try {
    if (st && id(fs.fstatSync(fd, { bigint: true })) !== id(st)) fail('D5_GUARD_PROOF_CHANGED');
    fs.writeSync(fd, JSON.stringify({ event: 'guard_loaded', version: 2, pid: process.pid, threadId, isMainThread,
      node_test_context: typeof process.env.NODE_TEST_CONTEXT === 'string', root_dev: String(rootStat.dev), root_ino: String(rootStat.ino),
      recursive_only: true, os_sandbox: false, windows_reparse_inspector: process.platform === 'win32' }) + '\n');
  } finally { fs.closeSync(fd); }
}
