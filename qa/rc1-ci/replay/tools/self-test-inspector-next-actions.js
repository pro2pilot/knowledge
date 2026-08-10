#!/usr/bin/env node
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');
const packageJsonPath = path.join(systemRoot, 'package.json');
const packageJson = fs.existsSync(packageJsonPath) ? JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) : {};
const schemaVersion = packageJson.version || '3.3.0';
const keepTemp = process.argv.includes('--keep-temp');

function rmWithRetry(targetPath, attempts = 8) {
  for (let i = 0; i < attempts; i += 1) {
    try {
      fs.rmSync(targetPath, { recursive: true, force: true });
      return;
    } catch (error) {
      if (i === attempts - 1) return;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150);
    }
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function safeWriteJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function copyKnowledgeSystem(destination) {
  const excluded = new Set([
    '.git',
    '.lock',
    '.runtime',
    '.qa-tmp',
    '.self-test-tmp',
    'benchmark-runs',
    'dist',
    'exports',
    'external_memory',
    'inspector',
    'metrics',
    'node_modules',
    'search'
  ]);
  fs.cpSync(systemRoot, destination, {
    recursive: true,
    filter(source) {
      const relative = path.relative(systemRoot, source).replace(/\\/g, '/');
      if (!relative) return true;
      return !excluded.has(relative.split('/')[0]);
    }
  });
}

function runNode(cwd, args, label) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    encoding: 'utf8',
    windowsHide: true
  });
  if (result.status !== 0) {
    throw new Error(`${label} failed\nSTDOUT:\n${result.stdout || ''}\nSTDERR:\n${result.stderr || ''}`);
  }
  return result;
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function fetchText(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
      });
      response.on('end', () => {
        resolve({ status: response.statusCode, body });
      });
    });
    request.once('error', reject);
    request.setTimeout(5000, () => {
      request.destroy(new Error(`Timed out fetching ${url}`));
    });
  });
}

async function waitForSession(baseUrl) {
  const deadline = Date.now() + 15000;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetchText(`${baseUrl}/api/session`);
      if (response.status === 200) {
        const parsed = JSON.parse(response.body);
        if (parsed.token) return parsed.token;
      }
      lastError = new Error(`session status ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw lastError || new Error('Inspector session token was not issued');
}

async function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-inspector-next-actions-'));
  const projectRoot = path.join(tempRoot, 'project');
  const knowledgeRoot = path.join(projectRoot, '.knowledge');
  let serverProcess = null;

  try {
    copyKnowledgeSystem(knowledgeRoot);

    fs.mkdirSync(path.join(projectRoot, 'WEB'), { recursive: true });
    fs.writeFileSync(
      path.join(projectRoot, 'WEB', 'pro2pilot-knowledge-page-spec.md'),
      '# Inspector link smoke target\n\nThis file is opened through /api/files/open.\n',
      'utf8'
    );
    const outsideRoot = path.join(tempRoot, 'outside-workspace');
    fs.mkdirSync(outsideRoot, { recursive: true });
    fs.writeFileSync(
      path.join(outsideRoot, 'inspector-secret.txt'),
      'must-not-cross-inspector-containment',
      'utf8'
    );
    fs.symlinkSync(
      outsideRoot,
      path.join(projectRoot, 'linked-outside'),
      process.platform === 'win32' ? 'junction' : 'dir'
    );
    fs.symlinkSync(
      path.join(outsideRoot, 'inspector-secret.txt'),
      path.join(projectRoot, 'linked-secret.txt'),
      'file'
    );

    const webModule = {
      module_id: 'web',
      name: 'WEB',
      path: 'WEB/',
      card: '.knowledge/modules/web.json',
      confidence: 'medium',
      current_trust_level: 'routing_trusted',
      key_files: ['WEB/pro2pilot-knowledge-page-spec.md'],
      evidence_files: [],
      verification_status: 'routing_verified'
    };

    safeWriteJson(path.join(knowledgeRoot, 'modules', 'web.json'), webModule);
    safeWriteJson(path.join(knowledgeRoot, 'modules', 'module_registry.json'), {
      schema_version: schemaVersion,
      modules: [webModule]
    });
    safeWriteJson(path.join(knowledgeRoot, 'maintenance', 'trust_report.json'), {
      schema_version: schemaVersion,
      status: 'healthy',
      quality_score: 100,
      modules: {},
      issues: []
    });

    runNode(knowledgeRoot, [
      path.join(knowledgeRoot, 'tools', 'build-wiki-graph.js'),
      '--quiet',
      '--system-root',
      knowledgeRoot,
      '--target-root',
      projectRoot,
      '--project-knowledge-root',
      knowledgeRoot,
      '--state-root',
      knowledgeRoot
    ], 'build-wiki-graph');
    runNode(knowledgeRoot, [
      path.join(knowledgeRoot, 'tools', 'build-visual-inspector.js'),
      '--quiet',
      '--system-root',
      knowledgeRoot,
      '--target-root',
      projectRoot,
      '--project-knowledge-root',
      knowledgeRoot,
      '--state-root',
      knowledgeRoot
    ], 'build-visual-inspector');

    const port = await getFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    serverProcess = spawn(process.execPath, [
      path.join(knowledgeRoot, 'tools', 'serve-inspector.js'),
      '--host',
      '127.0.0.1',
      '--port',
      String(port),
      '--system-root',
      knowledgeRoot,
      '--target-root',
      projectRoot,
      '--project-knowledge-root',
      knowledgeRoot,
      '--state-root',
      knowledgeRoot,
      '--json'
    ], {
      cwd: knowledgeRoot,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    serverProcess.stdout.on('data', () => {});
    serverProcess.stderr.on('data', () => {});

    const token = await waitForSession(baseUrl);
    const inspectorHtml = await fetchText(`${baseUrl}/?token=${encodeURIComponent(token)}`);
    assert(inspectorHtml.status === 200, `Inspector HTML returned ${inspectorHtml.status}`);
    assert(inspectorHtml.body.includes('module:web'), 'Inspector HTML did not render module:web');
    assert(inspectorHtml.body.includes('/api/files/open?path='), 'Inspector HTML did not render /api/files/open links');
    assert(inspectorHtml.body.includes('data-open-path'), 'Inspector HTML did not render open-path metadata');
    assert(inspectorHtml.body.includes('data-file-preview-drawer="true"'), 'Inspector HTML did not render inline file preview drawer');
    assert(inspectorHtml.body.includes('openInspectorFile(pathValue'), 'Inspector HTML did not wire Next action links to inline preview');
    assert(inspectorHtml.body.includes("fetch('/api/files/open?path='+encodeURIComponent(pathValue)"), 'Inspector preview did not fetch /api/files/open from the client');
    assert(inspectorHtml.body.includes('data-file-preview-copy-code="true"'), 'Inspector preview missing VS Code command copy control');
    assert(!/data-open-path="[^"]+"[^>]*target="_blank"/.test(inspectorHtml.body), 'Next action links should not leave Inspector by default');
    assert(inspectorHtml.body.includes('.knowledge/modules/web.json'), 'Inspector HTML did not include module card open path');
    assert(inspectorHtml.body.includes('WEB/pro2pilot-knowledge-page-spec.md'), 'Inspector HTML did not include spec file open path');

    const moduleOpen = await fetchText(`${baseUrl}/api/files/open?path=${encodeURIComponent('.knowledge/modules/web.json')}&token=${encodeURIComponent(token)}`);
    assert(moduleOpen.status === 200, `Module card open returned ${moduleOpen.status}`);
    assert(moduleOpen.body.includes('"module_id"') && moduleOpen.body.includes('"web"'), 'Module card open body did not contain web module JSON');

    const specOpen = await fetchText(`${baseUrl}/api/files/open?path=${encodeURIComponent('WEB/pro2pilot-knowledge-page-spec.md')}&token=${encodeURIComponent(token)}`);
    assert(specOpen.status === 200, `Spec file open returned ${specOpen.status}`);
    assert(specOpen.body.includes('Inspector link smoke target'), 'Spec file open body did not contain expected target text');

    const unauthenticatedOpen = await fetchText(`${baseUrl}/api/files/open?path=${encodeURIComponent('.knowledge/modules/web.json')}`);
    assert(unauthenticatedOpen.status === 401, `Unauthenticated open should be rejected, got ${unauthenticatedOpen.status}`);

    const traversalOpen = await fetchText(`${baseUrl}/api/files/open?path=${encodeURIComponent('../../AGENTS.md')}&token=${encodeURIComponent(token)}`);
    assert(traversalOpen.status !== 200, `Traversal open should not succeed, got ${traversalOpen.status}`);

    const junctionOpen = await fetchText(`${baseUrl}/api/files/open?path=${encodeURIComponent('linked-outside/inspector-secret.txt')}&token=${encodeURIComponent(token)}`);
    assert(
      junctionOpen.status !== 200 &&
      !junctionOpen.body.includes('must-not-cross-inspector-containment'),
      `Junction escape should not succeed, got ${junctionOpen.status}`
    );

    const symlinkOpen = await fetchText(`${baseUrl}/api/files/open?path=${encodeURIComponent('linked-secret.txt')}&token=${encodeURIComponent(token)}`);
    assert(
      symlinkOpen.status !== 200 &&
      !symlinkOpen.body.includes('must-not-cross-inspector-containment'),
      `File symlink escape should not succeed, got ${symlinkOpen.status}`
    );

    console.log(JSON.stringify({
      schema_version: schemaVersion,
      status: 'pass',
      checks: [
        'live Inspector session token acquired',
        'Trust Graph module next-action paths rendered',
        'inline file preview drawer rendered',
        'Next action links are intercepted inside Inspector',
        'client preview fetches /api/files/open',
        'VS Code code -g copy command exposed',
        'module card opened through /api/files/open',
        'project spec opened through /api/files/open',
        'unauthenticated file open rejected',
        'path traversal rejected',
        'junction escape rejected',
        'file symlink escape rejected'
      ]
    }, null, 2));
  } catch (error) {
    console.error(JSON.stringify({
      schema_version: schemaVersion,
      status: 'fail',
      error: error.message
    }, null, 2));
    process.exitCode = 1;
  } finally {
    if (serverProcess && serverProcess.exitCode === null) {
      serverProcess.kill();
    }
    if (!keepTemp) {
      rmWithRetry(tempRoot);
    }
  }
}

main();
