#!/usr/bin/env node
'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { spawn, spawnSync } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');
const targetVersion = JSON.parse(fs.readFileSync(path.join(systemRoot, 'package.json'), 'utf8')).version || '3.3.0';
const previousVersion = '3.2.4';
const keepTemp = process.argv.includes('--keep-temp');
let tempRoot = null;

function assert(condition, message, details = null) {
  if (!condition) {
    const error = new Error(message);
    if (details) error.details = details;
    throw error;
  }
}

function copySystemRoot(src, dest) {
  fs.cpSync(src, dest, {
    recursive: true,
    filter: (entry) => {
      const rel = path.relative(src, entry).replace(/\\/g, '/');
      if (!rel) return true;
      if (rel === 'dist' || rel.startsWith('dist/')) return false;
      if (rel === '.self-test-tmp' || rel.startsWith('.self-test-tmp/')) return false;
      if (rel === '.qa-tmp' || rel.startsWith('.qa-tmp/')) return false;
      if (rel === '.lock' || rel.startsWith('.lock/')) return false;
      if (rel === 'benchmark-runs' || rel.startsWith('benchmark-runs/')) return false;
      if (rel === 'maintenance/install-backups' || rel.startsWith('maintenance/install-backups/')) return false;
      if (rel === 'maintenance/update-downloads' || rel.startsWith('maintenance/update-downloads/')) return false;
      if (rel === 'node_modules' || rel.startsWith('node_modules/')) return false;
      if (rel === '.git' || rel.startsWith('.git/')) return false;
      return true;
    }
  });
}

function writePackageVersion(root, version) {
  const pkgPath = path.join(root, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  pkg.version = version;
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');
  const configPath = path.join(root, 'config.yaml');
  if (fs.existsSync(configPath)) {
    const config = fs.readFileSync(configPath, 'utf8').replace(/^version:\s*.*$/m, `version: ${version}`);
    fs.writeFileSync(configPath, config, 'utf8');
  }
  // This fixture models a coherent installed predecessor.  Keep every
  // versioned JSON schema at the fixture package version so the update
  // validator does not mistake copied current-source metadata for a future
  // installation.
  const rewriteSchemas = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const filePath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        rewriteSchemas(filePath);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
      try {
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && typeof parsed.schema_version === 'string') {
          parsed.schema_version = version;
          fs.writeFileSync(filePath, JSON.stringify(parsed, null, 2) + '\n', 'utf8');
        }
      } catch {
        // Fixture metadata may include intentionally non-JSON files with a
        // .json suffix; leave those unchanged.
      }
    }
  };
  rewriteSchemas(root);
  if (version !== targetVersion) {
    const manifestPath = path.join(root, 'install-manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const releaseNotes = manifest.release_contract?.public_release_note_paths;
    if (Array.isArray(releaseNotes) && releaseNotes.length === 1) {
      const previousNote = `.release-notes/v${version}.md`;
      const currentNote = path.join(root, releaseNotes[0]);
      const previousNotePath = path.join(root, previousNote);
      fs.renameSync(currentNote, previousNotePath);
      manifest.release_contract.public_release_note_paths = [previousNote];
      fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    }
  }
}

function runNode(args, cwd, options = {}) {
  return spawnSync(process.execPath, args, {
    cwd,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 300000
  });
}

function parseJson(res, label) {
  assert(res.status === 0, `${label} failed`, { stdout: res.stdout, stderr: res.stderr, exit: res.status });
  try { return JSON.parse((res.stdout || '').trim()); }
  catch (error) { throw new Error(`${label} did not emit JSON: ${error.message}\n${res.stdout}`); }
}

function eocdOffset(buffer) {
  for (let i = buffer.length - 22; i >= 0; i -= 1) {
    if (buffer.readUInt32LE(i) === 0x06054b50) return i;
  }
  throw new Error('ZIP end of central directory not found.');
}

function extractZip(zipPath, dest) {
  const buffer = fs.readFileSync(zipPath);
  const eocd = eocdOffset(buffer);
  const count = buffer.readUInt16LE(eocd + 10);
  let ptr = buffer.readUInt32LE(eocd + 16);
  const destRoot = path.resolve(dest);
  for (let i = 0; i < count; i += 1) {
    if (buffer.readUInt32LE(ptr) !== 0x02014b50) throw new Error(`Invalid central directory header at ${ptr}`);
    const method = buffer.readUInt16LE(ptr + 10);
    const compressedSize = buffer.readUInt32LE(ptr + 20);
    const nameLength = buffer.readUInt16LE(ptr + 28);
    const extraLength = buffer.readUInt16LE(ptr + 30);
    const commentLength = buffer.readUInt16LE(ptr + 32);
    const localOffset = buffer.readUInt32LE(ptr + 42);
    const name = buffer.slice(ptr + 46, ptr + 46 + nameLength).toString('utf8');
    if (buffer.readUInt32LE(localOffset) !== 0x04034b50) throw new Error(`Invalid local header for ${name}`);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.slice(dataStart, dataStart + compressedSize);
    const body = method === 0 ? compressed : zlib.inflateRawSync(compressed);
    const target = path.resolve(destRoot, name);
    if (target !== destRoot && !target.startsWith(destRoot + path.sep)) throw new Error(`Unsafe zip entry: ${name}`);
    if (!name.endsWith('/')) {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, body);
    }
    ptr += 46 + nameLength + extraLength + commentLength;
  }
}

function requestJson(port, method, requestPath, token = null, body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : '';
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: requestPath,
      method,
      headers: {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {})
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk.toString(); });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch {}
        resolve({ status: res.statusCode, json, body: data });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForServer(port, child) {
  let lastError = null;
  for (let i = 0; i < 80; i += 1) {
    if (child.exitCode !== null) throw new Error(`Inspector exited early with ${child.exitCode}`);
    try {
      const res = await requestJson(port, 'GET', '/api/session');
      if (res.status === 200 && res.json?.token) return res.json;
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  throw lastError || new Error('Inspector did not become ready.');
}

async function waitForExit(child) {
  for (let i = 0; i < 50; i += 1) {
    if (child.exitCode !== null) return child.exitCode;
    await delay(100);
  }
  child.kill();
  throw new Error('Inspector did not exit after shutdown.');
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-update-e2e-'));
  tempRoot = root;
  const releaseSource = path.join(root, 'release-source');
  const oldSource = path.join(root, 'old-source');
  const repo = path.join(root, 'repo');
  const oldKnowledge = path.join(repo, '.knowledge');
  const releaseZip = path.join(root, `knowledge-v${targetVersion}.zip`);
  const oldZip = path.join(root, `knowledge-v${previousVersion}.zip`);
  let child = null;
  try {
    copySystemRoot(systemRoot, releaseSource);
    writePackageVersion(releaseSource, targetVersion);
    const packaged = parseJson(runNode(['tools/package-release.js', '--json', '--out', releaseZip], releaseSource), 'package release fixture');
    assert(packaged.status === 'ok' && fs.existsSync(releaseZip), 'fixture release zip was not created', packaged);

    copySystemRoot(systemRoot, oldSource);
    writePackageVersion(oldSource, previousVersion);
    const oldPackaged = parseJson(runNode(['tools/package-release.js', '--json', '--out', oldZip], oldSource), 'package previous release fixture');
    assert(oldPackaged.status === 'ok' && fs.existsSync(oldZip), 'previous fixture release zip was not created', oldPackaged);

    fs.mkdirSync(repo, { recursive: true });
    fs.writeFileSync(path.join(repo, 'README.md'), '# update e2e fixture\n', 'utf8');
    extractZip(oldZip, repo);
    fs.mkdirSync(path.join(oldKnowledge, 'wiki'), { recursive: true });
    fs.writeFileSync(path.join(oldKnowledge, 'wiki', 'curated-note.md'), '# curated\nkeep me\n', 'utf8');

    const port = 21000 + Math.floor(Math.random() * 20000);
    child = spawn(process.execPath, [
      path.join(oldKnowledge, 'inspector.js'),
      '--port', String(port),
      '--system-root', oldKnowledge,
      '--project-knowledge-root', oldKnowledge,
      '--target-root', repo,
      '--state-root', oldKnowledge
    ], {
      cwd: repo,
      env: {
        ...process.env,
        KNOWLEDGE_UPDATE_MOCK_LATEST: targetVersion,
        KNOWLEDGE_UPDATE_LOCAL_ZIP: releaseZip,
        KNOWLEDGE_INSPECTOR_NO_OPEN: '1',
        KNOWLEDGE_FLOW_NO_OPEN: '1'
      },
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const session = await waitForServer(port, child);
    const status = await requestJson(port, 'GET', '/api/update/status', session.token);
    assert(status.status === 200 && status.json?.status?.status === 'update_available', 'launch update check did not report update_available', status);
    assert(status.json.status.latest_version === targetVersion, 'latest version mismatch', status.json.status);
    assert(status.json.status.auto_check_on_inspector_open === true, 'update status should expose auto-check-on-start mode');
    assert(status.json.status.auto_update === false, 'update status must not imply automatic update apply');
    assert(status.json.status.update_apply_requires_confirmation === true, 'update apply should require confirmation');

    const page = await requestJson(port, 'GET', `/?token=${session.token}`);
    assert(page.status === 200 && page.body.includes('update-banner available'), 'Home update banner should be visibly available');
    assert(page.body.includes('id="updateApplyButton"') && page.body.includes('>Update</button>'), 'Home update banner should expose one Update button');
    assert(page.body.includes('id="updateAutoCheckMode"') && page.body.includes('Auto-check: On'), 'Home update banner should expose auto-check mode');
    assert(page.body.includes('Checks on Inspector start') || page.body.includes('checks for new releases when it starts'), 'Home update banner should explain start-up checks');
    assert(!page.body.includes('data-update-action="status"') && !page.body.includes('data-update-action="dry-run"'), 'Home update banner should not expose extra update action buttons');
    assert(page.body.includes('data-shutdown="true"'), 'Turn off button is missing in live Inspector');
    const deniedAutoCheck = await requestJson(port, 'POST', '/api/update/auto-check', null, { enabled: false });
    assert(deniedAutoCheck.status === 401, 'auto-check toggle should require the session token');
    const autoCheckOff = await requestJson(port, 'POST', '/api/update/auto-check', session.token, { enabled: false });
    assert(autoCheckOff.status === 200 && autoCheckOff.json?.status?.auto_check_on_inspector_open === false, 'auto-check toggle did not turn off start-up checks');
    const autoCheckOn = await requestJson(port, 'POST', '/api/update/auto-check', session.token, { enabled: true });
    assert(autoCheckOn.status === 200 && autoCheckOn.json?.status?.auto_check_on_inspector_open === true, 'auto-check toggle did not turn start-up checks back on');

    const dryRun = await requestJson(port, 'POST', '/api/update/dry-run', session.token, {});
    assert(dryRun.status === 200 && dryRun.json?.dry_run?.status === 'dry_run_ready', 'update dry-run did not prepare a plan', dryRun);
    assert(dryRun.json.prepared?.validation?.ok === true, 'release artifact validation did not pass in dry-run', dryRun.json.prepared);

    const apply = await requestJson(port, 'POST', '/api/update/apply', session.token, { confirm: true, expectedVersion: targetVersion });
    assert(apply.status === 200 && apply.json?.ok === true, 'update apply did not succeed', apply);
    assert(apply.json.apply?.verify?.ok === true, 'verify-upgrade did not pass after apply', apply.json.apply);
    const updateReport = apply.json.apply?.apply?.json;
    assert(updateReport?.runtime_regeneration?.bootstrap_required === true, 'uninitialized update did not select flow import bootstrap', updateReport);
    assert(updateReport?.curated_preservation_proof?.changed_files_count === 0, 'post-check curated preservation proof failed', updateReport?.curated_preservation_proof);
    assert(updateReport?.backup_verification?.safe_to_remove === true, 'update backup was not verified as safe to remove', updateReport?.backup_verification);
    assert(apply.json.status?.status === 'up_to_date', 'apply response did not expose refreshed up_to_date status', apply.json.status);
    assert(apply.json.status?.current_version === targetVersion, 'apply response current version was not refreshed', apply.json.status);

    const installedPkg = JSON.parse(fs.readFileSync(path.join(oldKnowledge, 'package.json'), 'utf8'));
    assert(installedPkg.version === targetVersion, 'installed package version was not updated');
    const statusAfterApply = await requestJson(port, 'GET', '/api/update/status', session.token);
    assert(statusAfterApply.status === 200 && statusAfterApply.json?.status?.status === 'up_to_date', 'current live session did not report up_to_date after apply', statusAfterApply);
    assert(statusAfterApply.json.status.current_version === targetVersion, 'current live session did not report refreshed current version', statusAfterApply.json.status);
    const pageAfterApply = await requestJson(port, 'GET', `/?token=${session.token}`);
    assert(pageAfterApply.status === 200 && pageAfterApply.body.includes('data-current-version="' + targetVersion + '"'), 'current live Inspector page did not render refreshed current version');
    assert(pageAfterApply.body.includes('>Up to date</button>') && !pageAfterApply.body.includes('update-banner available'), 'current live Inspector page did not render applied update state');
    assert(fs.readFileSync(path.join(oldKnowledge, 'wiki', 'curated-note.md'), 'utf8').includes('keep me'), 'curated wiki content was not preserved');
    assert(!fs.existsSync(path.join(repo, 'maintenance')), 'update or launcher created root-level maintenance folder');

    const shutdown = await requestJson(port, 'POST', '/api/shutdown', session.token, {});
    assert(shutdown.status === 200 && shutdown.json?.status === 'shutting_down', 'shutdown endpoint did not acknowledge');
    const exitCode = await waitForExit(child);
    assert(exitCode === 0, `Inspector exited with ${exitCode}`);
    child = null;

    console.log(JSON.stringify({
      schema_version: targetVersion,
      status: 'pass',
      previous_version: previousVersion,
      target_version: targetVersion,
      checks: [
        'mock release zip built',
        'Inspector launch check reports update_available',
        'Home update banner is visible',
        'Home update banner exposes one Update button',
        'Home update banner exposes auto-check mode',
        'auto-check mode toggles through token-protected API',
        'dry-run downloads, validates and plans update',
        'apply updates system files',
        'uninitialized install selects flow import bootstrap',
        'post-check curated preservation proof passes',
        'backup receives safe-to-remove verification receipt',
        'current Inspector session shows refreshed update state after apply',
        'verify-upgrade passes',
        'curated wiki content preserved',
        'root-level maintenance folder not created',
        'shutdown endpoint releases Inspector process'
      ]
    }, null, 2));
  } finally {
    if (child) child.kill();
    if (!keepTemp) fs.rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  if (keepTemp && tempRoot) console.error(`temp_root=${tempRoot}`);
  if (error.details) console.error(JSON.stringify(error.details, null, 2));
  process.exit(1);
});
