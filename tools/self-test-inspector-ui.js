#!/usr/bin/env node
'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawnSync, spawn } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');
const systemVersion = JSON.parse(fs.readFileSync(path.join(systemRoot, 'package.json'), 'utf8')).version || '3.2.5';
const keepTemp = process.argv.includes('--keep-temp');
const teamModeFixtureRequested = process.argv.includes('--team-mode-fixture');
let rootForCleanup = null;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runNode(script, args = [], options = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: options.cwd || systemRoot,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 20000
  });
}

function mustRun(cmd, args = [], options = {}) {
  const res = spawnSync(cmd, args, {
    cwd: options.cwd,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 20000
  });
  assert(res.status === 0, `${cmd} ${args.join(' ')} failed\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
  return res;
}

function parseJson(res, label) {
  assert(res.status === 0, `${label} failed\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
  try { return JSON.parse((res.stdout || '').trim()); }
  catch (error) { throw new Error(`${label} did not return JSON: ${error.message}\n${res.stdout}`); }
}

function requestJson(port, method, requestPath, body = null, token = null) {
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
  for (let i = 0; i < 50; i += 1) {
    if (child.exitCode !== null) throw new Error(`Inspector server exited early with ${child.exitCode}`);
    try {
      const res = await requestJson(port, 'GET', '/api/session');
      if (res.status === 200 && res.json?.token) return res;
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  throw lastError || new Error('Inspector server did not become ready.');
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge inspector ui '));
  rootForCleanup = root;
  const project = path.join(root, 'repo');
  const state = path.join(root, 'state');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  mustRun('git', ['init', '-b', 'main'], { cwd: project });
  mustRun('git', ['config', 'user.email', 'knowledge-inspector@example.invalid'], { cwd: project });
  mustRun('git', ['config', 'user.name', 'Knowledge Inspector Test'], { cwd: project });
  fs.writeFileSync(path.join(project, 'README.md'), '# fixture\n', 'utf8');
  mustRun('git', ['add', 'README.md'], { cwd: project });
  mustRun('git', ['commit', '-m', 'initial'], { cwd: project });
  mustRun('git', ['checkout', '-b', 'feature/diagnostics'], { cwd: project });
  fs.writeFileSync(path.join(project, 'feature.txt'), 'diagnostics\n', 'utf8');
  mustRun('git', ['add', 'feature.txt'], { cwd: project });
  mustRun('git', ['commit', '-m', 'feature branch'], { cwd: project });
  mustRun('git', ['checkout', 'main'], { cwd: project });

  const baseArgs = [
    '--json',
    '--project-knowledge-root', systemRoot,
    '--system-root', systemRoot,
    '--target-root', project,
    '--state-root', state
  ];
  parseJson(runNode(path.join(systemRoot, 'tools', 'external-memory-status.js'), baseArgs), 'external-memory-status');
  parseJson(runNode(path.join(systemRoot, 'tools', 'build-wiki-graph.js'), baseArgs), 'build wiki graph');
  const build = parseJson(runNode(path.join(systemRoot, 'tools', 'build-visual-inspector.js'), baseArgs), 'build inspector');
  assert((build.features || []).includes('canonical_navigation'), 'status missing canonical_navigation feature');
  assert((build.features || []).includes('git_branch_diagnostics'), 'status missing git_branch_diagnostics feature');
  const htmlPath = path.join(state, 'inspector', 'index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');

  const tabs = [
    'Home',
    'Review',
    'Knowledge Trust',
    'Agents Activity',
    'Reports',
    'Settings',
    'Pro Preview'
  ];
  const missingTabs = tabs.filter((tab) => !html.includes(`>${tab}</button>`) && !html.includes(`>${tab}</h2>`));
  assert(missingTabs.length === 0, `Inspector missing tab(s): ${missingTabs.join(', ')}`);
  assert(!html.includes('>Command Center</button>'), 'Command Center must not be a top-level tab');
  assert(!html.includes('>Metrics</button>'), 'Metrics must not be a top-level tab');
  assert(!html.includes('>Work</button>'), 'Work must not be a top-level tab');
  assert(!html.includes('>Chat</button>'), 'Chat must not be a top-level tab');
  assert(html.includes('https://pro2pilot.com/inspector/'), 'Pro Preview must include the Inspector Pro waitlist link');
  const hiddenCopy = [
    ['Billing', ' Boundaries'],
    ['Do Not', ' Charge For'],
    ['Usage Bi', 'lling Policy'],
    ['Pa', 'id preview'],
    ['pa', 'id-value actions']
  ].map((parts) => parts.join(''));
  for (const forbidden of hiddenCopy) {
    assert(!html.includes(forbidden), `Pro Preview must not expose "${forbidden}"`);
  }

  const commandLabels = [
    'Run Doctor',
    'Refresh Release',
    'Build Inspector',
    'Search',
    'Generate PR Summary',
    'Review PR Impact',
    'Validate Release Artifact',
    'Team Status',
    'Memory Status',
    'Preview Mem0',
    'Join Inspector Pro waitlist'
  ];
  const missingCommands = commandLabels.filter((label) => !html.includes(`<span>${label}</span>`) && !html.includes(`>${label}</a>`));
  assert(missingCommands.length === 0, `Inspector missing command button(s): ${missingCommands.join(', ')}`);

  for (const label of [
    '.knowledge Source of Truth',
    'Mem0 OSS - recommended optional universal backend',
    'Pinecone - optional vector/cloud retrieval',
    'Graphiti - future optional temporal graph',
    'Zep - future optional managed/BYOC memory'
  ]) {
    assert(html.includes(label), `Inspector missing memory card: ${label}`);
  }

  assert(!/<script\s+[^>]*src=/i.test(html), 'Inspector must not load external scripts');
  assert(!/<link\s+[^>]*href=/i.test(html), 'Inspector must not load external stylesheets');
  assert(!/<img\s+[^>]*src=/i.test(html), 'Inspector must not load external images');
  const htmlWithoutAllowedWaitlist = html.replace(/https:\/\/pro2pilot\.com\/inspector\//g, '');
  assert(!/https?:\/\//i.test(htmlWithoutAllowedWaitlist), 'Inspector should not contain unexpected remote URLs in generated UI');
  const localLeak = new RegExp(`([A-Z]:\\\\(?:Users\\\\[^\\\\]+|MyProject)|/mnt/${'data'}|/tmp/${'knowledge'}|knowledge${'-'}kit)`, 'i');
  assert(!localLeak.test(html), 'Inspector leaked local developer path');
  assert(/data-copy=/.test(html), 'Inspector copy commands missing data-copy attributes');
  assert(/empty-state/.test(html), 'Inspector empty states missing');
  assert(html.includes('data-branch-diagnostics="true"'), 'Inspector branch diagnostics panel missing');
  assert(html.includes('data-branch-select="true"'), 'Inspector branch selector missing');
  assert(html.includes('feature/diagnostics'), 'Inspector branch selector missing feature branch');
  assert(html.includes('main (active)'), 'Inspector branch selector should default to active branch');
  assert(html.includes('metric-card'), 'Inspector metric cards should use metric-card styling');
  assert(html.includes('Repair trust with an agent'), 'Inspector missing simple agent repair entrypoint');
  assert(html.includes('Trust repair prompt for agent'), 'Knowledge Trust missing repair prompt copy action');
  assert(html.includes('data-graph-shelf="free-core"'), 'Knowledge Trust graph shelf is missing.');
  assert(html.includes('data-graph-toggle="free-core"'), 'Knowledge Trust graph collapse control is missing.');
  assert(html.includes('data-graph-node="true"'), 'Knowledge Trust graph node drilldown hooks are missing.');
  assert(html.includes('data-graph-detail="true"'), 'Knowledge Trust graph detail panel is missing.');
  assert(!html.includes('class="graph-link"'), 'Graph nodes must not navigate to raw/broken pages.');

  fs.mkdirSync(path.join(project, 'modules'), { recursive: true });
  fs.mkdirSync(path.join(project, 'maintenance'), { recursive: true });
  fs.writeFileSync(path.join(project, 'modules', 'module_registry.json'), JSON.stringify({
    modules: [{
      module_id: 'fixture',
      path: 'README.md',
      confidence: 'medium',
      current_trust_level: 'routing_trusted',
      evidence: ['README.md']
    }]
  }, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(project, 'maintenance', 'trust_report.json'), JSON.stringify({
    status: 'routing_trusted',
    modules: { routing_trusted: ['fixture'] },
    module_statuses: [{ module_id: 'fixture', trust_status: 'routing_trusted', confidence: 'medium', path: 'README.md' }]
  }, null, 2) + '\n', 'utf8');

  const port = 18000 + Math.floor(Math.random() * 20000);
  const server = spawn(process.execPath, [
    path.join(systemRoot, 'tools', 'serve-inspector.js'),
    '--port', String(port),
    '--system-root', systemRoot,
    '--project-knowledge-root', project,
    '--target-root', project,
    '--state-root', state
  ], {
    cwd: systemRoot,
    env: { ...process.env, KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  try {
    const sessionRes = await waitForServer(port, server);
    const denied = await requestJson(port, 'GET', '/api/state');
    assert(denied.status === 401, 'Inspector API state must require token.');
    const stateRes = await requestJson(port, 'GET', '/api/state', null, sessionRes.json.token);
    assert(stateRes.status === 200 && stateRes.json?.state?.product?.version === systemVersion, 'Inspector API state missing product version.');
    assert(stateRes.json.state.context.branch === 'main', 'Inspector API should default to active Git branch.');
    assert(stateRes.json.state.context.git?.branches?.active === 'main', 'Inspector API branch state missing active branch.');
    assert((stateRes.json.state.context.git?.branches?.branches || []).some((branch) => branch.name === 'feature/diagnostics'), 'Inspector API branch list missing feature branch.');
    assert(stateRes.json.state.settings.onboarding.required === true, 'first-run onboarding should be required before setup is saved.');
    const pageRes = await requestJson(port, 'GET', `/?token=${sessionRes.json.token}`);
    assert(pageRes.status === 200 && pageRes.body.includes('data-onboarding-wizard="true"'), 'live Inspector missing first-run onboarding wizard.');
    assert(pageRes.body.includes('What can agents do without asking?'), 'onboarding wizard missing canonical permission wording.');
    assert(pageRes.body.includes('data-table-search="modules"'), 'live Inspector should render shared Knowledge Trust table filters.');
    assert(pageRes.body.includes('Trust repair prompt for agent'), 'live Inspector missing trust repair prompt copy action.');
    assert(pageRes.body.includes('metric-card'), 'live Inspector missing metric card styling.');
    assert(pageRes.body.includes('data-shutdown="true"'), 'live Inspector missing Turn off button.');
    assert(pageRes.body.includes('data-graph-toggle="free-core"'), 'live Inspector missing graph collapse control.');
    const deniedOnboarding = await requestJson(port, 'POST', '/api/settings/onboarding', { user_mode: 'advanced' });
    assert(deniedOnboarding.status === 401, 'onboarding save must require token.');
    const onboardingRes = await requestJson(port, 'POST', '/api/settings/onboarding', {
      user_mode: 'advanced',
      agents_can_do_without_asking: 'run checks and reports',
      concurrent_work_policy: 'Safe Queue',
      merge_policy: 'Manual Only',
      report_footer_mode: 'compact'
    }, sessionRes.json.token);
    assert(onboardingRes.status === 200 && onboardingRes.json?.settings?.operator_profile?.first_run_onboarding_completed === true, 'onboarding save did not complete operator profile.');
    const operatorProfile = JSON.parse(fs.readFileSync(path.join(project, 'settings', 'operator-profile.json'), 'utf8'));
    const autonomyPolicy = JSON.parse(fs.readFileSync(path.join(project, 'settings', 'autonomy-policy.json'), 'utf8'));
    const agentPolicy = JSON.parse(fs.readFileSync(path.join(project, 'settings', 'agent-policy.json'), 'utf8'));
    const reportFooter = JSON.parse(fs.readFileSync(path.join(project, 'settings', 'report-footer.json'), 'utf8'));
    assert(operatorProfile.user_mode === 'advanced' && operatorProfile.first_run_onboarding_completed === true, 'operator profile onboarding settings not saved.');
    assert(autonomyPolicy.agents_can_do_without_asking === 'run checks and reports', 'autonomy policy permission wording not saved.');
    assert(agentPolicy.concurrent_work_policy === 'Safe Queue' && agentPolicy.merge_policy === 'Manual Only' && agentPolicy.auto_merge === false, 'agent policy defaults not saved.');
    assert(reportFooter.mode === 'compact' && reportFooter.show_restore_action === true, 'report footer defaults not saved.');
    const savedStateRes = await requestJson(port, 'GET', '/api/state', null, sessionRes.json.token);
    assert(savedStateRes.status === 200 && savedStateRes.json.state.settings.onboarding.required === false, 'onboarding should not be required after setup is saved.');
    const savedPageRes = await requestJson(port, 'GET', `/?token=${sessionRes.json.token}`);
    assert(savedPageRes.status === 200 && savedPageRes.body.includes('data-onboarding-expanded="false"'), 'onboarding card should collapse after setup is saved.');
    const legacyProfile = { schema_version: '3.1.8', user_mode: 'advanced' };
    fs.writeFileSync(path.join(project, 'settings', 'operator-profile.json'), JSON.stringify(legacyProfile, null, 2) + '\n', 'utf8');
    const upgradeStateRes = await requestJson(port, 'GET', '/api/state', null, sessionRes.json.token);
    assert(upgradeStateRes.status === 200 && upgradeStateRes.json.state.settings.onboarding.required === true, 'upgrade without onboarding completion marker should require setup.');
    assert(upgradeStateRes.json.state.settings.onboarding.reason === 'upgrade_missing_completion_marker', 'upgrade onboarding reason should identify missing completion marker.');
    const upgradePageRes = await requestJson(port, 'GET', `/?token=${sessionRes.json.token}`);
    assert(upgradePageRes.status === 200 && upgradePageRes.body.includes('data-onboarding-wizard="true"'), 'live Inspector should render onboarding wizard after upgrade without completion marker.');
    const branchesRes = await requestJson(port, 'GET', '/api/git/branches', null, sessionRes.json.token);
    assert(branchesRes.status === 200 && branchesRes.json.git?.active === 'main', 'git branches API should default to active branch.');
    const branchDiagnostics = await requestJson(port, 'GET', '/api/git/diagnostics?branch=feature%2Fdiagnostics', null, sessionRes.json.token);
    assert(branchDiagnostics.status === 200 && branchDiagnostics.json.diagnostics?.branch === 'feature/diagnostics', 'git diagnostics API should switch diagnostic target to selected branch.');
    const actionsRes = await requestJson(port, 'GET', '/api/actions', null, sessionRes.json.token);
    assert(actionsRes.status === 200 && actionsRes.json?.actions?.some((action) => action.id === 'trust.restore.safe'), 'Inspector API actions missing Restore Trust.');
    const updateStatusRes = await requestJson(port, 'GET', '/api/update/status', null, sessionRes.json.token);
    assert(updateStatusRes.status === 200 && updateStatusRes.json?.status, 'Inspector update status API missing.');
  } finally {
    server.kill();
  }

  const teamRoot = path.join(root, 'team state');
  const teamBuild = parseJson(runNode(path.join(systemRoot, 'tools', 'build-visual-inspector.js'), [
    '--json',
    '--system-root', systemRoot,
    '--project-knowledge-root', systemRoot,
    '--target-root', project,
    '--team-root', teamRoot,
    '--workspace-id', 'ui-workspace',
    '--agent-id', 'ui-agent'
  ]), 'build team inspector');
  assert(teamBuild.mode === 'team', 'team inspector status should report team mode');
  assert((teamBuild.features || []).includes('team_mode_panel'), 'team inspector missing team_mode_panel feature');
  const teamDataPath = path.join(teamRoot, 'repos');
  const dataFiles = [];
  function walk(dir) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.name === 'data.json' && abs.includes(`${path.sep}inspector${path.sep}`)) dataFiles.push(abs);
    }
  }
  walk(teamDataPath);
  assert(dataFiles.length === 1, `expected one team inspector data.json, found ${dataFiles.length}`);
  const teamData = JSON.parse(fs.readFileSync(dataFiles[0], 'utf8'));
  assert(teamData.context.mode === 'team', 'team inspector data context mode mismatch');
  assert(teamData.context.workspaceId === 'ui-workspace', 'team inspector data workspaceId mismatch');
  assert(teamData.context.agentId === 'ui-agent', 'team inspector data agentId mismatch');
  const teamHtml = fs.readFileSync(path.join(path.dirname(dataFiles[0]), 'index.html'), 'utf8');
  assert(teamHtml.includes('Agents Activity'), 'team inspector DOM missing Agents Activity tab');
  assert(teamHtml.includes('ui-workspace'), 'team inspector DOM missing workspace id');
  assert(!localLeak.test(teamHtml), 'team inspector leaked local developer path');

  const result = {
    schema_version: systemVersion,
    status: 'pass',
    team_mode_fixture_requested: teamModeFixtureRequested,
    temp_root: keepTemp ? root : null,
    temp_root_cleaned: !keepTemp,
    checks: [
      'all canonical tabs render',
      'forbidden top-level tabs are absent',
      'memory provider cards render',
      'no external scripts/css/images',
      'no known local path leaks',
      'copy command attributes exist',
      'token-protected Inspector API works',
      'first-run onboarding wizard renders',
      'upgrade-missing onboarding marker reopens setup',
      'onboarding save writes settings',
      'git branch selector defaults to active branch',
      'git branch diagnostics API switches target branch',
      'actions endpoint includes Restore Trust',
      'live/static Inspector share tabular Knowledge Trust UI',
      'trust repair agent prompt renders',
      'onboarding card collapses after save',
      'update status API renders launch check status',
      'turn off button renders in live Inspector',
      'collapsible graph shelf renders',
      'graph node drilldown hooks render',
      'empty states render'
      ,'team-mode inspector data.json parses'
      ,'team-mode inspector DOM renders workspace status'
      ,...(teamModeFixtureRequested ? ['--team-mode-fixture flag honored'] : [])
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

main().catch((error) => { console.error(error.stack || error.message); process.exit(1); });
