#!/usr/bin/env node
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { resolveKnowledgeContext } = require('./lib/path-context');
const recording = require('./lib/recording-blockers');
const { recordingSecretPaths, secretPaths } = require('./lib/repair-on-touch');

const systemRoot = path.resolve(process.env.KNOWLEDGE_RECORDING_TEST_SYSTEM_ROOT || path.resolve(__dirname, '..'));
const workspaceRoot = path.resolve(systemRoot, '..');
const fixtureBase = path.join(workspaceRoot, '.qa-tmp', 'a344-recording-blockers');
const candidate = 'docs/' + ['sk', 'live', 'G'.repeat(33)].join('_') + '.md'; // Deliberately artificial privacy fixture; never a provider credential.
const secondCandidate = 'docs/' + ['sk', 'test', 'L'.repeat(39)].join('_') + '.md'; // Deliberately artificial second privacy fixture.

function check(value, message) {
  assert.ok(value, message);
}

function makeContext(root, options = {}) {
  const targetRoot = path.join(root, options.targetName || 'repo');
  const stateRoot = path.join(root, options.stateName || 'state');
  const projectKnowledgeRoot = options.projectKnowledgeRoot || path.join(root, 'project-knowledge');
  fs.mkdirSync(targetRoot, { recursive: true });
  fs.mkdirSync(projectKnowledgeRoot, { recursive: true });
  return {
    context: resolveKnowledgeContext({
      __skipCli: true,
      systemRoot,
      projectKnowledgeRoot,
      targetRoot,
      stateRoot
    }),
    targetRoot,
    stateRoot
  };
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || workspaceRoot,
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 120000,
    env: {
      ...process.env,
      KNOWLEDGE_AGENT_ID: 'a344-inspector',
      KNOWLEDGE_USER_LANGUAGE: 'ru',
      KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1',
      ...(options.env || {})
    }
  });
  if (result.error) throw result.error;
  return result;
}

function cliArgs(targetRoot, stateRoot, projectKnowledgeRoot = systemRoot) {
  return [
    '--system-root', systemRoot,
    '--project-knowledge-root', projectKnowledgeRoot,
    '--target-root', targetRoot,
    '--state-root', stateRoot,
    '--json'
  ];
}

function runJson(command, args, options = {}) {
  const result = run(process.execPath, [command, ...args], options);
  let value;
  try { value = JSON.parse(String(result.stdout || '').trim()); }
  catch { throw new Error(`${path.basename(command)} returned invalid JSON (exit ${result.status}).`); }
  return { ...result, value };
}

function expectRejected(fn, expectedCode) {
  let error;
  try { fn(); } catch (caught) { error = caught; }
  check(error, `Expected rejection ${expectedCode}.`);
  if (expectedCode) check(error.code === expectedCode || String(error.message).includes(expectedCode), `Expected ${expectedCode}, got ${error.code || error.message}.`);
  return error;
}

function exerciseRegistryAndCli(root) {
  const { context, targetRoot, stateRoot } = makeContext(root);
  fs.mkdirSync(path.dirname(path.join(targetRoot, candidate)), { recursive: true });
  fs.writeFileSync(path.join(targetRoot, candidate), 'synthetic test fixture\n', 'utf8');
  fs.writeFileSync(path.join(targetRoot, secondCandidate), 'synthetic second fixture\n', 'utf8');
  const sessionA = `ATW-${crypto.randomBytes(32).toString('hex')}`;
  const sessionB = `ATW-${crypto.randomBytes(32).toString('hex')}`;

  const registered = recording.registerBlocker(context, {
    kind: 'suspected_secret', value: candidate, field: '$.source_files[0]', session_id: sessionA, language: 'ru'
  });
  check(registered.status === 'ok' && registered.blocker.preview === '********', 'Secret-shaped path preview must be masked.');
  check(registered.blocker.allowed_actions.includes('once') && registered.blocker.allowed_actions.includes('project'), 'Existing repository path should permit only the offered explicit scopes.');
  check(registered.chat_notice.includes('Запись') && registered.blocker.notice_language === 'ru', 'Blocker notice should follow Russian user language.');
  check(!registered.chat_notice.includes(candidate), 'Russian chat notice leaked the path value.');

  const list = recording.listBlockers(context);
  check(list.status === 'ok' && list.language === 'ru', 'Registry list should return localized status.');
  check(!JSON.stringify(list).includes(candidate) && !JSON.stringify(list).includes('value_sha256'), 'Public blocker list leaked value data or its digest.');
  const resolvedOnce = recording.resolveBlocker(context, {
    id: registered.blocker.id, scope: 'once', reason: 'Synthetic fixture approval', confirmed: true
  });
  check(resolvedOnce.status === 'ok', 'One-time override was rejected.');
  const registryPath = path.join(stateRoot, 'maintenance', 'recording_blockers.json');
  const approvedRegistry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  check(approvedRegistry.overrides.at(-1)?.reason === recording.OVERRIDE_REASON_CODE,
    'Approved override persisted free-text instead of the stable reason code.');
  check(!fs.readFileSync(registryPath, 'utf8').includes('Synthetic fixture approval'),
    'Approved override left its free-text reason in the registry.');
  check(recording.listBlockers(context).overrides.at(-1)?.reason === recording.OVERRIDE_REASON_CODE,
    'Override listing did not return the stable safe reason code.');
  check(recording.approvedRepositoryPath(context, candidate, sessionA), 'One-time override did not match its workflow.');
  check(!recording.approvedRepositoryPath(context, candidate, sessionB), 'One-time override was reused by another workflow.');
  check(!recording.approvedRepositoryPath(context, secondCandidate, sessionA), 'One-time override expanded beyond the exact approved path.');
  check(secretPaths(candidate).length > 0, 'Approved path must remain secret-shaped for privacy masking.');
  check(recordingSecretPaths({ api_key: candidate }, { context, sessionId: sessionA }).includes('$.api_key'), 'A path approval must never override a secret-key field.');

  const second = recording.registerBlocker(context, {
    value: secondCandidate, field: '$.source_files[0]', session_id: sessionA, language: 'ru'
  });
  const resolvedProject = recording.resolveBlocker(context, {
    id: second.blocker.id, scope: 'project', reason: 'Synthetic project approval', confirmed: true
  });
  check(resolvedProject.status === 'ok' && recording.approvedRepositoryPath(context, secondCandidate, sessionB), 'Project override should be exact-path scoped and reusable across workflows.');
  check(recording.revokeOverride(context, { id: resolvedProject.override_id, confirmed: true }).status === 'ok', 'Project override revoke failed.');
  check(!recording.approvedRepositoryPath(context, secondCandidate, sessionA), 'Revoked project override still applies.');

  for (const unsafeReason of [
    'approved because password=hunter2',
    'Approved local file with github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  ]) {
    const pending = recording.registerBlocker(context, {
      value: secondCandidate, field: '$.unsafe_reason_fixture', session_id: sessionB
    }).blocker;
    const rejected = recording.resolveBlocker(context, {
      id: pending.id, scope: 'project', reason: unsafeReason, confirmed: true
    });
    check(rejected.status === 'rejected' && rejected.reason === 'safe_reason_required',
      `Secret-bearing confirmation reason was not rejected: ${unsafeReason.split(/[= ]/)[0]}`);
  }

  const legacyRegistry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  const legacyOverride = legacyRegistry.overrides.at(-1);
  legacyOverride.reason = 'Legacy unsafe note: password=hunter2';
  fs.writeFileSync(registryPath, JSON.stringify(legacyRegistry, null, 2), 'utf8');
  const safeLegacyList = recording.listBlockers(context);
  const safeLegacyOverride = safeLegacyList.overrides.find((item) => item.id === legacyOverride.id);
  check(safeLegacyOverride?.reason === recording.OVERRIDE_REASON_CODE,
    'Legacy free-text override reason was not replaced in the public listing.');
  check(!JSON.stringify(safeLegacyList).includes('Legacy unsafe note') && !JSON.stringify(safeLegacyList).includes('hunter2'),
    'Legacy free-text override reason leaked through the public listing.');

  const arbitrarySecret = recording.registerBlocker(context, {
    value: ['sk', 'live', 'H'.repeat(35)].join('_'), field: '$.task', session_id: sessionA, language: 'ru' // Deliberately artificial privacy fixture; never a provider credential.
  });
  check(arbitrarySecret.blocker.allowed_actions.length === 0, 'Non-path secret value must not receive an override action.');
  check(recording.resolveBlocker(context, { id: arbitrarySecret.blocker.id, scope: 'project', reason: 'test', confirmed: true }).status === 'rejected', 'Non-path secret value must not be overridable.');

  const userScope = recording.registerBlocker(context, { kind: 'user_scope', value: '.knowledge', field: 'task_record', language: 'ru' });
  check(userScope.blocker.allowed_actions.length === 0, 'User-scope blocker must not expose resolve actions.');
  check(recording.resolveBlocker(context, { id: userScope.blocker.id, scope: 'project', reason: 'test', confirmed: true }).status === 'rejected', 'User-scope blocker must not be overridable.');

  const cliList = runJson(path.join(systemRoot, 'tools', 'recording-blockers.js'), ['list', ...cliArgs(targetRoot, stateRoot)]);
  check(cliList.status === 0 && cliList.value.status === 'ok' && cliList.value.language === 'ru', 'CLI list did not return the real Russian registry.');
  check(!JSON.stringify(cliList.value).includes(candidate), 'CLI list exposed the synthetic secret-shaped path.');
  const cliBlocker = recording.registerBlocker(context, {
    value: candidate, field: '$.cli_fixture', session_id: sessionA, language: 'ru'
  }).blocker;
  const cliResolve = runJson(path.join(systemRoot, 'tools', 'recording-blockers.js'), [
    'resolve', `--id=${cliBlocker.id}`, '--scope=once', '--reason=Synthetic fixture approval', '--confirmed=true', ...cliArgs(targetRoot, stateRoot)
  ]);
  check(cliResolve.status === 0 && cliResolve.value.status === 'ok', 'CLI resolve did not use the real registry backend.');
  check(recording.approvedRepositoryPath(context, candidate, sessionA), 'CLI one-time resolve did not create the scoped override.');
  const cliRevoke = runJson(path.join(systemRoot, 'tools', 'recording-blockers.js'), [
    'revoke', `--id=${cliResolve.value.override_id}`, '--confirmed=true', ...cliArgs(targetRoot, stateRoot)
  ]);
  check(cliRevoke.status === 0 && cliRevoke.value.status === 'ok', 'CLI revoke did not use the real registry backend.');
  const cliRevokedOverride = recording.listBlockers(context).overrides.find((item) => item.id === cliResolve.value.override_id);
  check(cliRevokedOverride?.status === 'revoked', 'CLI revoke left its one-time override active.');

  const secretField = recording.registerBlocker(context, {
    value: candidate, field: '$.api_token', session_id: sessionA, language: 'ru'
  });
  check(secretField.blocker.field === '$.api_token' && secretField.blocker.allowed_actions.length === 0,
    'Safe configuration field name should remain visible without an override action.');
  const credentialField = recording.registerBlocker(context, {
    value: candidate, field: '$.ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456', session_id: sessionA, language: 'ru'
  });
  check(credentialField.blocker.field === 'task_record' && credentialField.blocker.allowed_actions.length === 0,
    `Credential-shaped field name was exposed or given an override action: ${JSON.stringify(credentialField.blocker)}`);

  verifyUnsafeRegistryFixtures(root);
  verifyUnsafeRepositoryPaths(context, targetRoot);
  verifyNoWriteScope(root);
  return { context, targetRoot, stateRoot, sessionA, sessionB };
}

function verifyUnsafeRegistryFixtures(root) {
  const malformed = makeContext(root, { targetName: 'malformed-repo', stateName: 'malformed-state' });
  const registryPath = path.join(malformed.stateRoot, 'maintenance', 'recording_blockers.json');
  fs.mkdirSync(path.dirname(registryPath), { recursive: true });
  fs.writeFileSync(registryPath, '{not-json', 'utf8');
  expectRejected(() => recording.listBlockers(malformed.context));

  const hardlinked = makeContext(root, { targetName: 'hardlink-repo', stateName: 'hardlink-state' });
  const hardlinkPath = path.join(hardlinked.stateRoot, 'maintenance', 'recording_blockers.json');
  fs.mkdirSync(path.dirname(hardlinkPath), { recursive: true });
  fs.writeFileSync(hardlinkPath, JSON.stringify({ schema_version: recording.SCHEMA, blockers: [], overrides: [] }), 'utf8');
  const linkedCopy = path.join(root, 'recording-registry-hardlink.json');
  fs.linkSync(hardlinkPath, linkedCopy);
  try { expectRejected(() => recording.listBlockers(hardlinked.context), 'recording_registry_unsafe'); }
  finally { fs.unlinkSync(linkedCopy); }

  const symlinked = makeContext(root, { targetName: 'symlink-repo', stateName: 'symlink-state' });
  const symlinkPath = path.join(symlinked.stateRoot, 'maintenance', 'recording_blockers.json');
  const external = path.join(root, 'external-recording-registry.json');
  fs.mkdirSync(path.dirname(symlinkPath), { recursive: true });
  fs.writeFileSync(external, JSON.stringify({ schema_version: recording.SCHEMA, blockers: [], overrides: [] }), 'utf8');
  fs.symlinkSync(external, symlinkPath, 'file');
  expectRejected(() => recording.listBlockers(symlinked.context));
}

function verifyUnsafeRepositoryPaths(context, targetRoot) {
  const file = path.join(targetRoot, 'docs', 'regular.txt');
  fs.writeFileSync(file, 'fixture', 'utf8');
  const hardlink = path.join(targetRoot, 'docs', 'hardlink.txt');
  fs.linkSync(file, hardlink);
  check(!recording.repositoryPath(context, 'docs/hardlink.txt'), 'Hardlinked repository path was accepted.');
  const symlink = path.join(targetRoot, 'docs', 'symlink.txt');
  fs.symlinkSync(file, symlink, 'file');
  check(!recording.repositoryPath(context, 'docs/symlink.txt'), 'Symlink repository path was accepted.');
  check(!recording.repositoryPath(context, '../outside.txt'), 'Parent traversal was accepted as a repository path.');
}

function verifyNoWriteScope(root) {
  const targetRoot = path.join(root, 'no-write-repo');
  const stateRoot = path.join(root, 'no-write-state');
  fs.mkdirSync(targetRoot, { recursive: true });
  const result = runJson(path.join(systemRoot, 'tools', 'agent-task.js'), [
    'begin', '--task=synthetic no-write policy check', '--scope-module=workspace', '--scope-path=README.md',
    '--knowledge-write-allowed=false', '--language=ru', ...cliArgs(targetRoot, stateRoot)
  ]);
  check(result.value.status === 'blocked' && result.value.recording_status === 'blocked_by_user_scope', 'knowledge-write-allowed=false did not fail closed with user-scope status.');
  check(result.value.recording_blockers?.[0]?.allowed_actions?.length === 0 && result.value.chat_notice?.includes('Запись'), 'No-write user-scope notice or action boundary was incorrect.');
  check(!fs.existsSync(stateRoot), 'knowledge-write-allowed=false wrote task state.');
}

function request(port, method, route, token, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body);
    const req = http.request({
      hostname: '127.0.0.1', port, path: route, method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {})
      }
    }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk.toString(); });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(text); } catch {}
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function waitForInspector(child, readOutput) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Inspector exited during fixture startup (${child.exitCode}).`);
    const match = readOutput().match(/\{\s*"ok"\s*:\s*true,[\s\S]*?\}/);
    if (match) {
      try {
        const parsed = JSON.parse(match[0]);
        if (parsed.ok && parsed.port && parsed.session_token) return parsed;
      } catch {}
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('Inspector did not become ready for the recording action fixture.');
}

async function verifyInspectorActionIntegration(fixture) {
  const { context, targetRoot, stateRoot, sessionA } = fixture;
  const blocker = recording.registerBlocker(context, {
    value: candidate, field: '$.inspector_fixture', session_id: sessionA, language: 'ru'
  }).blocker;
  const child = spawn(process.execPath, [
    path.join(systemRoot, 'tools', 'serve-inspector.js'), '--port', '0',
    '--system-root', systemRoot, '--project-knowledge-root', systemRoot,
    '--target-root', targetRoot, '--state-root', stateRoot
  ], {
    cwd: workspaceRoot,
    windowsHide: true,
    env: { ...process.env, KNOWLEDGE_AGENT_ID: 'a344-inspector', KNOWLEDGE_USER_LANGUAGE: 'ru', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  try {
    const launch = await waitForInspector(child, () => stdout);
    const unauthenticated = await request(launch.port, 'POST', '/api/actions/recording.blockers/run', null, {});
    check(unauthenticated.status === 401, 'Inspector recording action bypassed session-token authentication.');
    const listed = await request(launch.port, 'POST', '/api/actions/recording.blockers/run', launch.session_token, {});
    check(listed.status === 200 && listed.json?.run?.status === 'passed', 'Inspector did not execute the real recording list action.');
    const result = listed.json.run.result;
    const row = result.blockers.find((item) => item.id === blocker.id);
    check(result.language === 'ru' && row?.preview === '********' && row.chat_notice.includes('Запись'), 'Inspector list action did not preserve masked Russian blocker details.');
    check(!listed.text.includes(candidate), 'Inspector list action response leaked the exact path value.');
    const unconfirmed = await request(launch.port, 'POST', '/api/actions/recording.resolve/run', launch.session_token, {
      id: blocker.id, scope: 'once', reason: 'synthetic fixture'
    });
    check(unconfirmed.status === 409 && unconfirmed.json?.run?.status === 'needs_confirmation', 'Inspector recording mutation bypassed explicit confirmation.');
    const resolved = await request(launch.port, 'POST', '/api/actions/recording.resolve/run', launch.session_token, {
      id: blocker.id, scope: 'once', reason: 'Synthetic Inspector fixture approval', confirmed: true
    });
    check(resolved.status === 200 && resolved.json?.run?.status === 'passed', 'Inspector did not dispatch the confirmed resolve to the real backend.');
    check(recording.approvedRepositoryPath(context, candidate, sessionA), 'Inspector one-time resolve did not bind to the blocker workflow.');
    const refreshed = await request(launch.port, 'POST', '/api/actions/recording.blockers/run', launch.session_token, {});
    const actionOverrideId = resolved.json?.run?.result?.override_id;
    check(/^EX-[a-f0-9]{64}$/.test(String(actionOverrideId || '')) &&
      resolved.json?.run?.result?.scope === 'once' && resolved.json?.run?.result?.retry_required === true,
    'Inspector resolve did not return the safe exact override identifier and scope.');
    const actionOverride = refreshed.json?.run?.result?.overrides?.find((item) => item.id === actionOverrideId);
    check(actionOverride?.scope === 'once' && actionOverride.created_at,
      `Inspector list action dropped one-task scope or confirmation time: ${JSON.stringify(refreshed.json?.run?.result?.overrides)}`);
    const override = recording.listBlockers(context).overrides.find((item) => item.blocker_id === blocker.id);
    check(override?.status === 'active' && override.scope === 'once', 'Inspector resolve did not create a one-task active override.');
    const revoked = await request(launch.port, 'POST', '/api/actions/recording.revoke/run', launch.session_token, {
      id: override.id, confirmed: true
    });
    check(revoked.status === 200 && revoked.json?.run?.status === 'passed', 'Inspector did not dispatch the confirmed revoke to the real backend.');
    const revokedOverride = recording.listBlockers(context).overrides.find((item) => item.id === override.id);
    check(revokedOverride?.status === 'revoked', 'Inspector revoke did not restore the strict block for its own override.');
  } catch (error) {
    throw new Error(`${error.message}\nstdout:\n${stdout}\nstderr:\n${stderr}`);
  } finally {
    child.kill();
    await new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once('exit', resolve);
      setTimeout(resolve, 1000);
    });
  }
}

function prepareGitFixture(targetRoot) {
  const init = run('git', ['init', '--quiet'], { cwd: targetRoot });
  check(init.status === 0, 'Could not initialize local-only task fixture repository.');
  fs.writeFileSync(path.join(targetRoot, 'README.md'), 'Synthetic recording blocker fixture.\n', 'utf8');
  const add = run('git', ['add', 'README.md'], { cwd: targetRoot });
  check(add.status === 0, 'Could not stage local task fixture.');
  const commit = run('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture', '--quiet'], { cwd: targetRoot });
  check(commit.status === 0, 'Could not commit local task fixture.');
}

function verifyWorkflowRetry(root) {
  const targetRoot = path.join(root, 'workflow-repo');
  const stateRoot = path.join(root, 'workflow-state');
  const projectKnowledgeRoot = path.join(root, 'workflow-project-knowledge');
  fs.mkdirSync(targetRoot, { recursive: true });
  fs.mkdirSync(projectKnowledgeRoot, { recursive: true });
  check(path.resolve(projectKnowledgeRoot) !== path.resolve(systemRoot) &&
    fs.readdirSync(projectKnowledgeRoot).length === 0,
  'Workflow fixture must start with an isolated empty project knowledge root.');
  prepareGitFixture(targetRoot);
  const sourceFile = path.join(targetRoot, candidate);
  fs.mkdirSync(path.dirname(sourceFile), { recursive: true });
  fs.writeFileSync(sourceFile, 'synthetic content only\n', 'utf8');
  fs.writeFileSync(path.join(targetRoot, 'physical-fixture-test.js'),
    'const fs=require("fs"); const file="physical-count.txt"; const n=fs.existsSync(file)?Number(fs.readFileSync(file,"utf8")):0; fs.writeFileSync(file,String(n+1)); process.stdout.write("synthetic KVE pass\\n");\n', 'utf8');
  const addSources = run('git', ['add', candidate, 'physical-fixture-test.js'], { cwd: targetRoot });
  check(addSources.status === 0, 'Could not stage the synthetic task source and physical test script.');
  const commitSources = run('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'add test fixture', '--quiet'], { cwd: targetRoot });
  check(commitSources.status === 0, 'Could not commit the synthetic task source and test script.');
  const baseFlags = cliArgs(targetRoot, stateRoot, projectKnowledgeRoot);
  const begin = runJson(path.join(systemRoot, 'tools', 'agent-task.js'), [
    'begin', '--task=verify synthetic recording preflight behavior', '--scope-module=workspace', '--scope-path=README.md',
    '--language=ru', ...baseFlags
  ], { cwd: targetRoot, timeout: 180000 });
  check(begin.status === 0 && begin.value.status === 'ready' && begin.value.workflow_id,
    'Synthetic task workflow did not begin cleanly: ' + JSON.stringify({status:begin.status,value:begin.value,stderr:begin.stderr}));
  const workflowId = begin.value.workflow_id;
  const routeSha = begin.value.route?.first_read?.sha256;
  check(typeof routeSha === 'string' && /^[a-f0-9]{64}$/.test(routeSha), 'Synthetic task route did not return a first-read SHA.');
  check(typeof begin.value.route.first_read.content === 'string' && begin.value.route.first_read.content.length > 0, 'Synthetic task route did not return its first-read body.');
  const requestPath = path.join(targetRoot, 'finish-request.json');
  const requestBody = {
    schema_version: 'knowledge-agent-task-finish-request.v1',
    route_first_read_sha256: routeSha,
    source_files: [candidate],
    tests_to_run: [{ argv: ['node', 'physical-fixture-test.js'], cwd: '.', timeout_ms: 30000 }],
    primary_summary: 'Physical single-command fixture for recording preflight.',
    run_release_flow: false
  };
  fs.writeFileSync(requestPath, `${JSON.stringify(requestBody, null, 2)}\n`, 'utf8');
  const finishArgs = ['finish', `--workflow-id=${workflowId}`, '--request=finish-request.json', ...baseFlags];
  const blocked = runJson(path.join(systemRoot, 'tools', 'agent-task.js'), finishArgs, { cwd: targetRoot, timeout: 180000 });
  check(blocked.status === 2 && blocked.value.error?.code === 'recording_blocked', 'Secret-shaped source path did not block the initial task finish.');
  const row = blocked.value.recording_blockers?.[0];
  check(row?.preview === '********' && row.allowed_actions.includes('once'), 'Blocked finish did not expose a masked one-time-capable path row.');
  check(!JSON.stringify(blocked.value).includes(candidate), 'Blocked task finish leaked the synthetic secret-shaped path.');
  check(!fs.existsSync(path.join(targetRoot, 'physical-count.txt')), 'Blocked recording executed a physical test before approval.');
  const resolved = runJson(path.join(systemRoot, 'tools', 'recording-blockers.js'), [
    'resolve', `--id=${row.id}`, '--scope=once', '--reason=Synthetic workflow fixture approval', '--confirmed=true', ...baseFlags
  ], { cwd: targetRoot });
  check(resolved.status === 0 && resolved.value.status === 'ok', 'CLI did not confirm the exact workflow blocker.');
  const finished = runJson(path.join(systemRoot, 'tools', 'agent-task.js'), finishArgs, { cwd: targetRoot, timeout: 300000 });
  check(finished.status === 0 && finished.value.status === 'completed',
    `Workflow did not complete after the one-time override: ${JSON.stringify({ exit_code: finished.status, status: finished.value.status, error: finished.value.error, issue_codes: finished.value.issue_codes, recording_status: finished.value.recording_status })}`);
  const acceptances = finished.value.primary_verification?.verification_acceptances;
  check(Array.isArray(acceptances) && acceptances.length === 1,
    'Workflow result did not preserve the real native verification acceptance.');
  const executions = finished.value.primary_verification?.executions || [];
  check(finished.value.primary_verification?.status === 'pass' && executions.length === 1 && executions[0].status === 'pass' && executions[0].exit_code === 0, 'Native KVE did not record exactly one successful physical test.');
  const ids = executions.map((item) => item.execution_id);
  const retry = runJson(path.join(systemRoot, 'tools', 'agent-task.js'), finishArgs, { cwd: targetRoot, timeout: 180000 });
  check(retry.status === 0 && retry.value.workflow_id === workflowId, 'Stable workflow retry did not return the same completed task.');
  check(JSON.stringify(retry.value.primary_verification?.verification_acceptances) === JSON.stringify(acceptances),
    'Stable workflow retry did not preserve the original native verification acceptance.');
  const retryIds = (retry.value.primary_verification?.executions || []).map((item) => item.execution_id);
  check(JSON.stringify(retryIds) === JSON.stringify(ids) && retryIds.length === 1, 'Retry duplicated the physical KVE execution.');
  check(fs.readFileSync(path.join(targetRoot, 'physical-count.txt'), 'utf8') === '1', 'Physical command ran more than once despite a stable KVE ID.');
  const policyContext = resolveKnowledgeContext({ __skipCli: true, systemRoot, projectKnowledgeRoot, targetRoot, stateRoot });
  const batchReader = require('./lib/verification-finalization');
  const nativeReader = require('./lib/repair-on-touch');
  expectRejected(() => batchReader.requireFinalizedExecutions(stateRoot, ids, acceptances), 'verification_finalization_required');
  check(nativeReader.requireFinalizedExecutions(stateRoot, ids, acceptances, policyContext).privacy_status === 'recording_policy_checked',
    'The writer-facing reader did not honor the exact current workflow exception.');
  const overrideId = resolved.value.override_id;
  check(recording.revokeOverride(policyContext, { id: overrideId, confirmed: true }).status === 'ok', 'Could not revoke the synthetic workflow exception.');
  expectRejected(() => nativeReader.requireFinalizedExecutions(stateRoot, ids, acceptances, policyContext), 'verification_finalization_required');
  check(!recording.approvedRepositoryPath(policyContext, candidate, workflowId), 'Revocation did not restore strict recording policy.');
  return { status: 'pass', workflow_id: workflowId, physical_kve_execution_count: executions.length, retry_execution_ids_stable: true };
}

async function main() {
  fs.mkdirSync(fixtureBase, { recursive: true });
  const root = fs.mkdtempSync(path.join(fixtureBase, 'run-'));
  let integration;
  let workflow = { status: 'not_requested' };
  try {
    integration = exerciseRegistryAndCli(root);
    await verifyInspectorActionIntegration(integration);
    if (process.argv.includes('--workflow-fixture')) workflow = verifyWorkflowRetry(root);
    console.log(JSON.stringify({
      schema_version: 'knowledge-recording-blockers-self-test.v1',
      status: 'pass',
      checks: [
        'real registry and CLI list/resolve/revoke',
        'Russian localized blocker notice with masked preview',
        'exact existing path classification only',
        'free-text confirmation reasons are not persisted or returned; credential-bearing reasons are rejected',
        'legacy free-text reasons are replaced by the stable public reason code',
        'one-time override bound to originating workflow',
        'project override scoped to exact path and revocable',
        'secret-key fields and display masking stay strict after path approval',
        'malformed, symlinked and hardlinked registry rejection',
        'symlinked, hardlinked and traversal paths rejected',
        'user-scope blocker exposes no actions',
        'knowledge-write-allowed=false creates no state',
        'real Inspector action list/resolve/revoke integration',
        ...(workflow.status === 'pass' ? ['blocked finish, one-time retry, one native KVE execution, and stable completed retry'] : [])
      ],
      workflow_fixture: workflow
    }, null, 2));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
