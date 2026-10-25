'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { test } = require('node:test');

const copy = require('../tools/lib/verification-isolated-copy');

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function makeTemp(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-isolated-copy-'));
  t.after(() => {
    const tempRoot = fs.realpathSync(os.tmpdir());
    const resolved = fs.realpathSync(root);
    const relative = path.relative(tempRoot, resolved);
    assert(relative && relative !== '..' && !relative.startsWith(`..${path.sep}`));
    assert(!path.isAbsolute(relative));
    assert(path.basename(resolved).startsWith('knowledge-isolated-copy-'));
    assert(!fs.lstatSync(resolved).isSymbolicLink());
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  return root;
}

function projectAt(root) {
  const project = path.join(root, 'project');
  fs.mkdirSync(project);
  return project;
}

function ensurePortableTempPermissions(t, create, what) {
  try {
    create();
  } catch (error) {
    if (process.platform === 'win32' && error.code === 'EPERM') {
      t.skip(`${what} could not be created without Windows privilege (EPERM)`);
      return false;
    }
    throw error;
  }
  return true;
}

test('plans a required source manifest and transfers bytes, chunks, and empty directories', async t => {
  const root = makeTemp(t);
  const project = projectAt(root);
  const source = Buffer.alloc(150_123);
  for (let i = 0; i < source.length; i++) source[i] = i % 251;
  fs.writeFileSync(path.join(project, 'src.bin'), source, { mode: 0o640 });
  fs.mkdirSync(path.join(project, 'empty', 'nested'), { recursive: true });
  fs.writeFileSync(path.join(project, 'README.md'), 'portable copy\n', { mode: 0o644 });

  const before = new Map(['src.bin', 'README.md'].map(name => {
    const file = path.join(project, name);
    const stat = fs.statSync(file);
    return [name, { bytes: fs.readFileSync(file), dev: String(stat.dev), ino: String(stat.ino),
      mode: stat.mode, mtimeMs: stat.mtimeMs }];
  }));
  const plan = await copy.planProject(project, { required: ['src.bin', 'README.md'] });

  assert.equal(plan.schema_version, copy.SCHEMA);
  assert.equal(plan.no_writeback, true);
  assert.deepEqual(plan.files.map(file => file.path), ['README.md', 'src.bin']);
  assert.deepEqual(plan.directories, ['empty', 'empty/nested']);
  assert.equal(plan.total_bytes, Buffer.byteLength('portable copy\n') + source.length);
  assert.equal(plan.files.find(file => file.path === 'src.bin').sha256, sha256(source));
  const manifestRows = plan.files.map(({ path: name, bytes, sha256: digest, mode }) =>
    ({ bytes, mode, path: name, sha256: digest }));
  assert.equal(plan.manifest_sha256, sha256(Buffer.from(JSON.stringify(manifestRows), 'utf8')));
  assert.equal(plan.manifest_sha256, copy.manifestDigest(plan.files));
  assert.equal(plan.directories_sha256, sha256(Buffer.from(JSON.stringify(plan.directories), 'utf8')));
  assert.equal(plan.directories_sha256, copy.directoriesDigest(plan.directories));
  assert.deepEqual(await copy.snapshotCopy(project, ['src.bin', 'README.md']), plan.files
    .map(file => ({ path: file.path, sha256: file.sha256 })));

  const received = new Map();
  const directories = [];
  const operations = [];
  let current;
  let sealed = false;
  const result = await copy.transferProject(plan, async message => {
    operations.push(message.op);
    if (message.op === 'mkdir') directories.push(message.path);
    if (message.op === 'put_begin') {
      current = { path: message.path, mode: message.mode, bytes: message.bytes,
        sha256: message.sha256, chunks: [] };
    } else if (message.op === 'put_chunk') {
      assert.equal(message.path, current.path);
      assert.equal(message.offset, current.chunks.reduce((n, chunk) => n + chunk.length, 0));
      current.chunks.push(Buffer.from(message.data, 'base64'));
    } else if (message.op === 'put_commit') {
      const bytes = Buffer.concat(current.chunks);
      assert.equal(current.path, message.path);
      assert.equal(bytes.length, current.bytes);
      assert.equal(sha256(bytes), current.sha256);
      received.set(current.path, { bytes, mode: current.mode });
      current = undefined;
    } else if (message.op === 'seal') {
      assert.equal(message.manifest_sha256, plan.manifest_sha256);
      assert.equal(message.directories_sha256, plan.directories_sha256);
      sealed = true;
    }
  });

  assert.deepEqual(directories, plan.directories);
  assert.equal(received.get('src.bin').bytes.length, source.length);
  assert.equal(operations.filter(op => op === 'put_chunk').length, 4);
  assert.deepEqual(received.get('src.bin').bytes, source);
  assert.deepEqual(received.get('README.md').bytes, Buffer.from('portable copy\n'));
  assert(received.get('src.bin').mode === 0o755 || received.get('src.bin').mode === 0o644);
  assert.equal(sealed, true);
  assert.equal(operations.at(-1), 'seal');
  assert.deepEqual(result, { files: plan.files.length, bytes: plan.total_bytes,
    manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256 });

  for (const [name, expected] of before) {
    const file = path.join(project, name);
    const after = fs.statSync(file);
    assert.deepEqual(fs.readFileSync(file), expected.bytes);
    assert.equal(String(after.dev), expected.dev);
    assert.equal(String(after.ino), expected.ino);
    assert.equal(after.mode, expected.mode);
    assert.equal(after.mtimeMs, expected.mtimeMs);
  }
});

test('excludes repository state and secrets, and refuses required excluded paths', async t => {
  const root = makeTemp(t);
  const project = projectAt(root);
  fs.mkdirSync(path.join(project, '.git', 'objects'), { recursive: true });
  fs.mkdirSync(path.join(project, '.knowledge', 'maintenance'), { recursive: true });
  fs.writeFileSync(path.join(project, '.git', 'objects', 'object'), 'git');
  fs.writeFileSync(path.join(project, '.knowledge', 'maintenance', 'receipt.json'), '{}');
  fs.writeFileSync(path.join(project, '.env'), 'TOKEN=not-a-real-secret');
  fs.writeFileSync(path.join(project, 'id_ed25519'), 'not-a-real-key');
  fs.writeFileSync(path.join(project, '.env.example'), 'SAFE=example');
  fs.writeFileSync(path.join(project, 'src.js'), 'module.exports = 1;\n');

  const plan = await copy.planProject(project, { required: ['src.js'] });
  assert.deepEqual(plan.files.map(file => file.path), ['.env.example', 'src.js']);
  assert.deepEqual(plan.skipped, [
    { path: '.env', reason: 'secret_configuration' },
    { path: '.git', reason: 'git_metadata' },
    { path: '.knowledge/maintenance', reason: 'knowledge_runtime_state' },
    { path: 'id_ed25519', reason: 'sensitive_file' }
  ]);
  for (const required of ['.env', '.git/objects/object', '.knowledge/maintenance/receipt.json', 'id_ed25519']) {
    await assert.rejects(copy.planProject(project, { required: [required] }), {
      code: 'verification_copy_required_source_excluded'
    });
  }
});

test('detects a source changed after planning before sending its file data', async t => {
  const root = makeTemp(t);
  const project = projectAt(root);
  const source = path.join(project, 'input.txt');
  fs.writeFileSync(source, 'before');
  const plan = await copy.planProject(project, { required: ['input.txt'] });
  fs.writeFileSync(source, 'after!');

  const operations = [];
  await assert.rejects(copy.transferProject(plan, async message => operations.push(message)), {
    code: 'verification_copy_source_changed'
  });
  assert.deepEqual(operations, []);
  assert.equal(fs.readFileSync(source, 'utf8'), 'after!');
});

test('rejects links, supported special files, traversal, and canonical aliases', async t => {
  const root = makeTemp(t);
  const project = projectAt(root);
  const target = path.join(project, 'target.txt');
  fs.writeFileSync(target, 'target');

  await t.test('symbolic links', async st => {
    const link = path.join(project, 'link.txt');
    if (!ensurePortableTempPermissions(st, () => fs.symlinkSync(target, link, 'file'), 'symbolic link')) return;
    try { await assert.rejects(copy.planProject(project), { code: 'verification_copy_source_unsafe' }); }
    finally { fs.rmSync(link, { force: true }); }
  });
  await t.test('hardlinks', async st => {
    const link = path.join(project, 'hardlink.txt');
    if (!ensurePortableTempPermissions(st, () => fs.linkSync(target, link), 'hardlink')) return;
    try { await assert.rejects(copy.planProject(project), { code: 'verification_copy_source_unsafe' }); }
    finally { fs.rmSync(link, { force: true }); }
  });
  if (process.platform === 'win32') {
    await t.test('special files', st => st.skip('Windows does not expose a project-local FIFO through Node filesystem APIs'));
  } else await t.test('special files', async st => {
    const fifo = path.join(project, 'pipe');
    let server;
    try {
      execFileSync('mkfifo', [fifo], { stdio: 'ignore' });
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      server = net.createServer();
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(fifo, resolve);
      });
    }
    try {
      await assert.rejects(copy.planProject(project), { code: 'verification_copy_source_unsafe' });
    } finally {
      if (server) await new Promise(resolve => server.close(resolve));
      fs.rmSync(fifo, { force: true });
    }
  });

  for (const name of ['../outside', 'a/../b', 'a\\b', 'cafe\u0301.txt', 'bad.']) {
    assert.throws(() => copy.relativeName(name), { code: 'verification_copy_path_unsupported' }, name);
  }

  const upper = path.join(project, 'Case.txt');
  const lower = path.join(project, 'case.txt');
  fs.writeFileSync(upper, 'upper');
  try {
    fs.writeFileSync(lower, 'lower', { flag: 'wx' });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const names = fs.readdirSync(project);
  if (names.includes('Case.txt') && names.includes('case.txt')) {
    await assert.rejects(copy.planProject(project), { code: 'verification_copy_path_collision' });
  } else {
    // On a case-insensitive filesystem both spellings resolve to one source;
    // there is no pair of entries for the planner to import ambiguously.
    assert.equal(names.filter(name => name.toLowerCase() === 'case.txt').length, 1);
  }
});

test('enforces file-count and byte limits and stops at a finite checkpoint', async t => {
  const root = makeTemp(t);
  const project = projectAt(root);
  fs.writeFileSync(path.join(project, 'a'), '1234');
  fs.writeFileSync(path.join(project, 'b'), '5');

  await assert.rejects(copy.planProject(project, { limits: { max_files: 1 } }), {
    code: 'verification_copy_limit_exceeded'
  });
  await assert.rejects(copy.planProject(project, { limits: { max_bytes: 4, max_file_bytes: 4 } }), {
    code: 'verification_copy_limit_exceeded'
  });
  assert.throws(() => copy.limits({ max_file_bytes: 5, max_bytes: 4 }), {
    code: 'verification_copy_limits_invalid'
  });

  let checkpoints = 0;
  const stop = Object.assign(new Error('cancelled by finite checkpoint'), { code: 'test_checkpoint_cancelled' });
  await assert.rejects(copy.planProject(project, {
    checkpoint() { if (++checkpoints === 3) throw stop; }
  }), error => error === stop);
  assert.equal(checkpoints, 3);
});

test('copies declared Knowledge sources and refuses leases, caches, and unknown state roots', async t => {
  const root = makeTemp(t), project = projectAt(root);
  const accepted = ['.knowledge/tools/check.js', '.knowledge/docs/guide.md', '.knowledge/package.json', '.knowledge/Quick-Start.md'];
  const excluded = ['.knowledge/locks/v1/sync.lock/owner.json', '.knowledge/inspector/data.json',
    '.knowledge/search/index.json', '.knowledge/freshness.json', '.knowledge/events/receipt.json',
    '.knowledge/modules/module.json', '.knowledge/external_memory/providers.json', '.knowledge/future-state/secret.json',
    'nested/.Knowledge/locks/owner.json', 'nested/.SSH/key.txt'];
  for (const name of [...accepted, ...excluded]) {
    fs.mkdirSync(path.dirname(path.join(project, name)), { recursive: true });
    fs.writeFileSync(path.join(project, name), 'fixture');
  }
  const plan = await copy.planProject(project, { required: accepted });
  assert.deepEqual(plan.files.map(file => file.path).sort(), accepted.sort());
  const sent = [];
  await copy.transferProject(plan, async message => sent.push(message));
  assert(sent.some(message => message.op === 'seal'));
  assert(!sent.some(message => excluded.includes(message.path)));
  for (const name of excluded) {
    await assert.rejects(copy.planProject(project, { required: [name] }), {
      code: 'verification_copy_required_source_excluded'
    });
    assert.equal(fs.readFileSync(path.join(project, name), 'utf8'), 'fixture');
  }
});

test('accepts exact file and total byte limits, including an empty file', async t => {
  const root = makeTemp(t);
  const project = projectAt(root);
  const empty = path.join(project, 'empty.txt');
  const full = path.join(project, 'full.txt');
  fs.writeFileSync(empty, Buffer.alloc(0));
  fs.writeFileSync(full, '12345');
  const plan = await copy.planProject(project, { required: ['empty.txt', 'full.txt'],
    limits: { max_files: 2, max_bytes: 5, max_file_bytes: 5 } });
  assert.equal(plan.files.length, 2);
  assert.equal(plan.total_bytes, 5);
  assert.equal(plan.files.find(file => file.path === 'empty.txt').bytes, 0);
  assert.equal(plan.files.find(file => file.path === 'empty.txt').sha256, sha256(Buffer.alloc(0)));

  const operations = [];
  await copy.transferProject(plan, async message => operations.push(message));
  assert.deepEqual(operations.filter(message => message.path === 'empty.txt').map(message => message.op),
    ['put_begin', 'put_commit']);
  assert.equal(operations.filter(message => message.op === 'seal').length, 1);
});

test('snapshot and transfer readback reject substituted links without changing the external source', async t => {
  for (const kind of ['symbolic link', 'hardlink']) {
    await t.test(kind, async st => {
      const root = makeTemp(st);
      const project = projectAt(root);
      const sourcePath = path.join(project, 'input.bin');
      const outsidePath = path.join(root, 'outside.bin');
      const original = Buffer.from('pinned bytes');
      fs.writeFileSync(sourcePath, original);
      fs.writeFileSync(outsidePath, original);
      const plan = await copy.planProject(project, { required: ['input.bin'] });
      fs.rmSync(sourcePath);

      try {
        if (kind === 'symbolic link') fs.symlinkSync(outsidePath, sourcePath, 'file');
        else fs.linkSync(outsidePath, sourcePath);
      } catch (error) {
        if (process.platform === 'win32' && error.code === 'EPERM') {
          st.skip(`${kind} could not be created without Windows privilege (EPERM)`);
          return;
        }
        throw error;
      }

      await assert.rejects(copy.snapshotCopy(project, ['input.bin']), {
        code: 'verification_copy_source_unsafe'
      });
      const requests = [];
      await assert.rejects(copy.transferProject(plan, async message => requests.push(message)), {
        code: 'verification_copy_source_unsafe'
      });
      assert.deepEqual(requests, []);
      assert.deepEqual(fs.readFileSync(outsidePath), original);
    });
  }
});

test('transfer cancellation and RPC failure never seal or write back to the source', async t => {
  const root = makeTemp(t);
  const project = projectAt(root);
  const bytes = Buffer.alloc(180_000, 0x5a);
  const source = path.join(project, 'large.bin');
  fs.writeFileSync(source, bytes, { mode: 0o640 });
  const original = fs.statSync(source);
  const plan = await copy.planProject(project, { required: ['large.bin'] });

  let firstChunkSent = false;
  const cancelledOps = [];
  await assert.rejects(copy.transferProject(plan, async message => {
    cancelledOps.push(message.op);
    if (message.op === 'put_chunk') firstChunkSent = true;
  }, {
    checkpoint() { if (firstChunkSent) throw Object.assign(new Error('transfer cancelled'), { code: 'test_checkpoint_cancelled' }); }
  }), { code: 'test_checkpoint_cancelled' });
  assert.equal(cancelledOps.filter(op => op === 'put_chunk').length, 1);
  assert(!cancelledOps.includes('seal'));

  const failedOps = [];
  await assert.rejects(copy.transferProject(plan, async message => {
    failedOps.push(message.op);
    if (message.op === 'put_chunk') throw Object.assign(new Error('broker unavailable'), { code: 'test_rpc_failed' });
  }), { code: 'test_rpc_failed' });
  assert(!failedOps.includes('seal'));
  assert(!failedOps.includes('put_commit'));
  const after = fs.statSync(source);
  assert.deepEqual(fs.readFileSync(source), bytes);
  assert.equal(String(after.dev), String(original.dev));
  assert.equal(String(after.ino), String(original.ino));
  assert.equal(after.mode, original.mode);
  assert.equal(after.mtimeMs, original.mtimeMs);
});

test('physical plan rejects root, ancestor and parent replacement even with unchanged file inodes', async t => {
  for (const kind of ['root', 'ancestor', 'parent']) await t.test(kind, async st => {
    const root = makeTemp(st), container = path.join(root, 'container');
    fs.mkdirSync(container);
    const project = projectAt(container), parent = path.join(project, 'src');
    fs.mkdirSync(parent); fs.writeFileSync(path.join(parent, 'input.js'), 'same physical file');
    const plan = await copy.planProject(project, { required: ['src/input.js'], cwd: 'src' });
    const inode = fs.statSync(path.join(parent, 'input.js'), { bigint: true }).ino;
    if (kind === 'root') {
      fs.renameSync(project, path.join(root, 'prior-root')); fs.mkdirSync(project);
      fs.renameSync(path.join(root, 'prior-root', 'src'), parent);
    } else if (kind === 'ancestor') {
      fs.renameSync(container, path.join(root, 'prior-container')); fs.mkdirSync(container);
      fs.renameSync(path.join(root, 'prior-container', 'project'), project);
    } else {
      fs.renameSync(parent, path.join(root, 'prior-parent')); fs.mkdirSync(parent);
      fs.renameSync(path.join(root, 'prior-parent', 'input.js'), path.join(parent, 'input.js'));
    }
    assert.equal(fs.statSync(path.join(parent, 'input.js'), { bigint: true }).ino, inode);
    const requests = [];
    await assert.rejects(copy.transferProject(plan, async request => requests.push(request)), { code: 'verification_copy_source_changed' });
    assert.deepEqual(requests, []);
  });
});

test('whole-project readback rejects entry additions and required cwd exclusion', async t => {
  const root = makeTemp(t), project = projectAt(root);
  fs.mkdirSync(path.join(project, 'cwd')); fs.writeFileSync(path.join(project, 'input.js'), 'initial');
  const plan = await copy.planProject(project, { required: ['input.js'], cwd: 'cwd' });
  await copy.verifyProjectPlan(plan);
  fs.writeFileSync(path.join(project, 'extra.js'), 'added during command');
  await assert.rejects(copy.verifyProjectPlan(plan), { code: 'verification_copy_source_changed' });
  fs.rmSync(path.join(project, 'extra.js'));
  fs.writeFileSync(path.join(project, '.env'), 'not-a-real-secret');
  await copy.verifyProjectPlan(plan); // excluded state is not execution input
  fs.mkdirSync(path.join(project, '.git'));
  await assert.rejects(copy.planProject(project, { cwd: '.git' }), { code: 'verification_copy_required_cwd_excluded' });
  await assert.rejects(copy.planProject(project, { cwd: 'missing' }), { code: 'verification_copy_required_cwd_excluded' });
});

test('source mutation during transfer RPC prevents sealing', async t => {
  const root = makeTemp(t), project = projectAt(root);
  const source = path.join(project, 'input.js'); fs.writeFileSync(source, 'before');
  const plan = await copy.planProject(project), requests = [];
  await assert.rejects(copy.transferProject(plan, async request => {
    requests.push(request.op);
    if (request.op === 'put_commit') fs.writeFileSync(source, 'after!');
  }), { code: 'verification_copy_source_changed' });
  assert(requests.includes('put_commit')); assert(!requests.includes('seal'));
  assert.equal(fs.readFileSync(source, 'utf8'), 'after!');
});

test('snapshot rejects a workspace root alias', async t => {
  const root = makeTemp(t), project = projectAt(root), alias = path.join(root, 'alias');
  fs.writeFileSync(path.join(project, 'input.js'), 'snapshot');
  if (!ensurePortableTempPermissions(t, () => fs.symlinkSync(project, alias, 'dir'), 'directory symlink')) return;
  await assert.rejects(copy.snapshotCopy(alias, ['input.js']), { code: 'verification_copy_source_unsafe' });
  assert.equal((await copy.snapshotCopy(project, ['input.js']))[0].sha256, sha256(Buffer.from('snapshot')));
});

test('snapshot rejects a parent replacement during read even when the file inode is preserved', {
  skip: process.platform === 'win32' ? 'Windows prevents renaming a parent of the open source file; the pre-open replacement is tested separately' : false
}, async t => {
  const root = makeTemp(t), project = projectAt(root), parent = path.join(project, 'src');
  fs.mkdirSync(parent); fs.writeFileSync(path.join(parent, 'input.js'), 'same source inode');
  let changed = false;
  await assert.rejects(copy.snapshotCopy(project, ['src/input.js'], {
    checkpoint() {
      if (changed) return;
      changed = true;
      fs.renameSync(parent, path.join(root, 'prior-parent')); fs.mkdirSync(parent);
      fs.renameSync(path.join(root, 'prior-parent', 'input.js'), path.join(parent, 'input.js'));
    }
  }), { code: 'verification_copy_source_changed' });
  assert.equal(changed, true);
});

test('snapshot rejects a parent replacement between binding and open with the same file inode', async t => {
  const root = makeTemp(t), project = projectAt(root), parent = path.join(project, 'src');
  const source = path.join(parent, 'input.js'), prior = path.join(root, 'prior-parent');
  fs.mkdirSync(parent); fs.writeFileSync(source, 'same source inode');
  const beforeFile = fs.statSync(source, { bigint: true });
  const beforeParent = fs.statSync(parent, { bigint: true });
  const realOpen = fs.promises.open;
  let replaced = false;
  fs.promises.open = async function (file, ...args) {
    if (!replaced && file === source) {
      fs.renameSync(parent, prior); fs.mkdirSync(parent);
      fs.renameSync(path.join(prior, 'input.js'), source);
      const afterFile = fs.statSync(source, { bigint: true });
      const afterParent = fs.statSync(parent, { bigint: true });
      assert.deepEqual([afterFile.dev, afterFile.ino], [beforeFile.dev, beforeFile.ino]);
      assert.notDeepEqual([afterParent.dev, afterParent.ino], [beforeParent.dev, beforeParent.ino]);
      replaced = true;
    }
    return realOpen.call(fs.promises, file, ...args);
  };
  try {
    await assert.rejects(copy.snapshotCopy(project, ['src/input.js']), { code: 'verification_copy_source_changed' });
    assert.equal(replaced, true);
  } finally {
    fs.promises.open = realOpen;
  }
});

test('whole-project readback rejects deleted required files and replaced empty working directories', async t => {
  const root = makeTemp(t), project = projectAt(root), source = path.join(project, 'input.js'), cwd = path.join(project, 'empty');
  fs.mkdirSync(cwd); fs.writeFileSync(source, 'bound input');
  const plan = await copy.planProject(project, { required: ['input.js'], cwd: 'empty' });
  fs.renameSync(cwd, path.join(root, 'prior-cwd')); fs.mkdirSync(cwd);
  await assert.rejects(copy.verifyProjectPlan(plan), { code: 'verification_copy_source_changed' });
  fs.rmdirSync(cwd); fs.renameSync(path.join(root, 'prior-cwd'), cwd);
  await copy.verifyProjectPlan(plan);
  fs.rmSync(source);
  await assert.rejects(copy.verifyProjectPlan(plan), { code: 'verification_copy_source_changed' });
});

test('source mutation while seal waits prevents reporting a successful current transfer', async t => {
  const root = makeTemp(t), project = projectAt(root), source = path.join(project, 'input.js');
  fs.writeFileSync(source, 'before');
  const plan = await copy.planProject(project), requests = [];
  await assert.rejects(copy.transferProject(plan, async request => {
    requests.push(request.op);
    if (request.op === 'seal') fs.writeFileSync(source, 'after!');
  }), { code: 'verification_copy_source_changed' });
  assert.equal(requests.filter(op => op === 'seal').length, 1);
  assert.equal(fs.readFileSync(source, 'utf8'), 'after!');
});

test('copy manifest physical binding rejects changed caller identity metadata', async t => {
  const root = makeTemp(t), project = projectAt(root);
  fs.writeFileSync(path.join(project, 'input.js'), 'bound');
  const plan = await copy.planProject(project);
  plan.files[0].identity.ino = '1';
  const requests = [];
  await assert.rejects(copy.transferProject(plan, async request => requests.push(request)), { code: 'verification_copy_manifest_invalid' });
  assert.deepEqual(requests, []);
});

test('regular-file to FIFO race cannot block the open before fstat rejection', async t => {
  if (process.platform === 'win32') { t.skip('FIFO replacement is a POSIX filesystem scenario'); return; }
  const root = makeTemp(t), project = projectAt(root), file = path.join(project, 'input.js');
  fs.writeFileSync(file, 'before FIFO substitution');
  const originalOpen = fs.promises.open; let substituted = false;
  fs.promises.open = async function (name, ...args) {
    if (name === file && !substituted) {
      substituted = true; fs.rmSync(file); execFileSync('mkfifo', [file], { stdio: 'ignore' });
    }
    return originalOpen.call(this, name, ...args);
  };
  try { await assert.rejects(copy.planProject(project), { code: 'verification_copy_source_changed' }); }
  finally { fs.promises.open = originalOpen; }
  assert.equal(substituted, true);
  assert.equal(fs.statSync(file).isFIFO(), true);
});
