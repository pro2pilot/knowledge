'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const routing = require('../tools/lib/task-routing');

const repo = path.resolve(__dirname, '..', '..');
const ownedParent = path.resolve(process.env.KNOWLEDGE_ROUTING_TEST_TMP || path.join(repo, '.qa-tmp', 'scope-test-runner'));
const key = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
if (!ownedParent.startsWith(repo + path.sep) || key(path.relative(repo, ownedParent)).startsWith('..')) {
  throw new Error('routing_test_temp_must_be_a_repository_child');
}
fs.mkdirSync(ownedParent, { recursive: true });
const runRoot = path.join(ownedParent, `typed-scope-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`);
const knowledge = path.join(runRoot, '.knowledge');
const checks = [];
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function check(name, fn) { fn(); checks.push(name); }
function fixture() {
  fs.mkdirSync(knowledge, { recursive: true });
  const modules = [
    { module_id: 'root', path: '.', card: '.knowledge/modules/root.json', key_files: ['.knowledge/modules/root.json'] },
    { module_id: 'web', path: 'web/', card: '.knowledge/modules/web.json', key_files: ['web/registry.md'], dependencies: ['api'], depends_on: [{ module_id: 'core' }] },
    { module_id: 'docs', path: 'docs/', card: '.knowledge/modules/docs.json', key_files: ['docs/registry.md', 'shared/catalog.json'] },
    { module_id: 'api', path: 'api/', card: '.knowledge/modules/api.json', key_files: ['api/registry.md', 'shared/catalog.json'] },
    { module_id: 'core', path: 'api/core/', card: '.knowledge/modules/core.json', key_files: ['api/core/index.js'] },
    { module_id: 'shared', path: 'shared/', card: '.knowledge/modules/shared.json', key_files: ['shared/index.md'] },
    { module_id: 'release-tools', path: 'tools/release/', card: '.knowledge/modules/release-tools.json', key_files: ['tools/release/index.js'] }
  ];
  write(path.join(knowledge, 'modules/module_registry.json'), { modules });
  write(path.join(knowledge, 'maintenance/trust_report.json'), {
    module_statuses: modules.map(item => ({ module_id: item.module_id, trust_status: 'trusted' }))
  });
  for (const moduleInfo of modules) {
    const card = { module_id: moduleInfo.module_id, key_files: [] };
    if (moduleInfo.module_id === 'docs') Object.assign(card, {
      key_files: ['docs/card-only.md', 'docs/card-missing.md'],
      evidence_files: ['.knowledge/evidence/docs.json'],
      ownership_paths: ['docs/specs/'],
      conditional_dependencies: [{ module_id: 'release-tools', when_paths: ['shared/release/'] }]
    });
    if (moduleInfo.module_id === 'shared') Object.assign(card, {
      conditional_dependencies: [{ module_id: 'release-tools', when_paths: ['shared/release/'] }]
    });
    if (moduleInfo.module_id === 'web') Object.assign(card, { depends_on: [{ module_id: 'docs' }] });
    write(path.join(runRoot, moduleInfo.card), card);
    for (const file of moduleInfo.key_files || []) write(path.join(runRoot, file), `fixture ${file}\n`);
  }
  write(path.join(runRoot, 'docs/card-only.md'), 'card key file\n');
  write(path.join(knowledge, 'evidence/docs.json'), { fixture: true });
  write(path.join(knowledge, 'freshness.json'), {
    tracked_files: [{ path: 'docs/specs/required.md', status: 'missing' }]
  });
  return {
    root: runRoot,
    knowledge,
    context: { targetRoot: runRoot, projectKnowledgeRoot: knowledge, stateRoot: knowledge, repoId: 'generic-fixture', agentId: 'portable-test', git: { changed_files: [] } }
  };
}

const base = fixture();
try {
  const registry = routing.__test.readRegistry(base.context);
  const docs = registry.find(item => item.module_id === 'docs');
  check('registry unions card key files, evidence, ownership boundaries and conditional dependencies', () => {
    assert(docs.key_files.includes('docs/registry.md'));
    assert(docs.key_files.includes('docs/card-only.md'));
    assert(docs.key_files.includes('docs/card-missing.md'));
    assert(docs.evidence_files.includes('.knowledge/evidence/docs.json'));
    assert(docs.ownership_paths.includes('docs/specs/'));
    assert.deepEqual(docs.conditional_dependencies, [{ module_id: 'release-tools', when_paths: ['shared/release/'] }]);
  });
  check('conflicting card and registry primary paths fail closed instead of hiding either boundary', () => {
    const registryPath = path.join(knowledge, 'modules/module_registry.json');
    const cardPath = path.join(runRoot, '.knowledge/modules/docs.json');
    const originalRegistry = fs.readFileSync(registryPath);
    const originalCard = fs.readFileSync(cardPath);
    try {
      const registryValue = JSON.parse(originalRegistry.toString('utf8'));
      registryValue.modules.find(item => item.module_id === 'docs').path = 'docs/registry-owner/';
      write(registryPath, registryValue);
      const card = JSON.parse(originalCard.toString('utf8'));
      card.path = 'docs/card-owner/';
      write(cardPath, card);
      assert.throws(() => routing.__test.readRegistry(base.context), error => error.code === 'module_ownership_invalid');
    } finally {
      fs.writeFileSync(registryPath, originalRegistry);
      fs.writeFileSync(cardPath, originalCard);
    }
  });
  const scope = (options = {}) => routing.canonicalScope({ task: 'update the selected module', scopeSource: 'explicit', ...options }, base.context);
  check('canonical scope round-trip preserves typed directory boundaries', () => {
    const original = scope({ taskClass: 'maintenance', modules: ['docs'], paths: ['docs/'], excludePaths: ['docs/private/'], excludeModules: ['api'], constraints: ['read-only'] });
    const restored = routing.canonicalScope(original, base.context);
    assert.equal(restored.task_scope_hash, original.task_scope_hash);
    assert.deepEqual(restored.path_boundaries, original.path_boundaries);
    assert.deepEqual(restored.exclude_path_boundaries, original.exclude_path_boundaries);
  });
  const select = input => routing.__test.moduleSelection(registry, input).filter(item => item.relevant).map(item => item.module_id).sort();
  check('legacy no-slash physical directory scope selects nested owners without root fallback', () => {
    const legacyScope = routing.canonicalScope({ task: null, taskClass: null, modules: [], paths: ['web'] }, base.context);
    assert.deepEqual(legacyScope.path_boundaries, [{ path: 'web', directory: true }]);
    const childRegistry = [
      { module_id: 'root', path: '.', card: '.knowledge/modules/root.json' },
      { module_id: 'site', path: 'web/site/', card: '.knowledge/modules/site.json' },
      { module_id: 'api', path: 'web/api/', card: '.knowledge/modules/api.json' }
    ];
    assert.deepEqual(routing.__test.moduleSelection(childRegistry, legacyScope).filter(item => item.relevant).map(item => item.module_id).sort(), ['api', 'site']);
  });
  check('task-routing CLI resolves --scope-path=web as a physical directory and selects both descendants', () => {
    const cliRoot = path.join(ownedParent, `cli-scope-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`);
    const cliKnowledge = path.join(cliRoot, '.knowledge');
    try {
      fs.mkdirSync(cliKnowledge, { recursive: true });
      const cliModules = [
        { module_id: 'root', path: '.', card: '.knowledge/modules/root.json', key_files: [] },
        { module_id: 'site', path: 'web/site/', card: '.knowledge/modules/site.json', key_files: ['web/site/index.js'] },
        { module_id: 'api', path: 'web/api/', card: '.knowledge/modules/api.json', key_files: ['web/api/index.js'] }
      ];
      write(path.join(cliKnowledge, 'modules/module_registry.json'), { modules: cliModules });
      for (const moduleInfo of cliModules) write(path.join(cliRoot, moduleInfo.card), { module_id: moduleInfo.module_id });
      write(path.join(cliRoot, 'web/site/index.js'), 'site\n');
      write(path.join(cliRoot, 'web/api/index.js'), 'api\n');
      const cli = spawnSync(process.execPath, [
        path.join(repo, '.knowledge/tools/task-routing.js'), 'create', '--task=Review the web directory',
        '--task-class=maintenance', '--scope-path=web', '--scope-source=explicit', '--json',
        `--system-root=${cliKnowledge}`, `--target-root=${cliRoot}`,
        `--project-knowledge-root=${cliKnowledge}`, `--state-root=${cliKnowledge}`
      ], { cwd: cliRoot, encoding: 'utf8', env: { ...process.env, KNOWLEDGE_AGENT_ID: 'portable-cli-scope-test', GIT_CEILING_DIRECTORIES: cliRoot } });
      assert.equal(cli.status, 0, cli.stderr || cli.stdout);
      const result = JSON.parse(cli.stdout);
      assert.deepEqual(result.scope.path_boundaries, [{ path: 'web', directory: true }]);
      const bundlePath = path.join(cliKnowledge, 'routing/tasks', result.task_scope_hash, 'snapshots', result.snapshot_hash, 'bundle.json');
      const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
      assert.deepEqual(bundle.selected_modules, ['api', 'site']);
    } finally {
      if (fs.existsSync(cliRoot)) fs.rmSync(cliRoot, { recursive: true, force: true });
    }
  });
  check('longest nested owner selects core without its broader api owner', () => {
    assert.deepEqual(select(scope({ paths: ['api/core/controller.js'] })), ['core']);
  });
  check('shared exact file retains every explicit claimant', () => {
    assert.deepEqual(select(scope({ paths: ['shared/catalog.json'] })), ['api', 'docs']);
  });
  check('legacy dependencies and depends_on both remain active', () => {
    assert.deepEqual(select(scope({ modules: ['web'] })), ['api', 'core', 'docs', 'web']);
    assert.deepEqual(routing.__test.dependenciesOf(registry.find(item => item.module_id === 'web')), ['api', 'core', 'docs']);
  });
  check('conditional shared-release edge activates only for its explicit path intersection', () => {
    assert.deepEqual(select(scope({ paths: ['shared/release/manifest.json'] })), ['release-tools', 'shared']);
    assert.deepEqual(select(scope({ paths: ['shared/other.json'] })), ['shared']);
  });
  check('root fallback selects unmatched files but does not wildcard unmatched directories', () => {
    assert.deepEqual(select(scope({ paths: ['unknown-package.json'] })), ['root']);
    assert.deepEqual(select(scope({ paths: ['unowned/'] })), []);
  });
  check('child exclusion preserves other docs scope and excluding the exact selected child conflicts', () => {
    assert.deepEqual(select(scope({ paths: ['docs/'], excludePaths: ['docs/private/'] })), ['docs']);
    assert.throws(() => select(scope({ paths: ['docs/private/secret.md'], excludePaths: ['docs/private/'] })),
      error => error.code === 'task_routing_scope_conflict');
  });
  check('selected scope paths retain typed directory boundaries and exact file references', () => {
    const selected = routing.__test.moduleSelection(registry, scope({ modules: ['docs'] })).filter(item => item.relevant);
    const paths = routing.__test.selectedScopePaths(selected);
    assert(paths.some(row => row.path === 'docs/specs' && row.kind === 'ownership_boundary' && row.directory));
    assert(paths.some(row => row.path === 'docs/card-missing.md' && row.kind === 'file_reference' && !row.directory));
    const changed = routing.__test.relevantPathCandidates(base.context, scope({ modules: ['docs'] }), selected, 'compact');
    assert(changed.all_relevant.some(row => row.path === 'docs/card-missing.md' && row.status === 'missing'));
    assert(changed.all_relevant.some(row => row.path === 'docs/specs/required.md' && row.status === 'missing'));
  });
  check('conflicting file/directory aliases are rejected before route selection', () => {
    assert.throws(() => scope({ paths: ['docs/private', 'docs/private/'] }), error => error.code === 'task_routing_invalid');
    if (process.platform === 'win32') assert.throws(() => scope({ paths: ['Docs/file.md', 'docs/file.md'] }), error => error.code === 'task_routing_invalid');
  });
  check('hostile scope getters and proxies are rejected without executing callbacks', () => {
    let callbacks = 0;
    const hostile = {};
    Object.defineProperty(hostile, 'paths', { enumerable: true, get() { callbacks++; return ['docs/']; } });
    assert.throws(() => routing.canonicalScope(hostile, base.context));
    assert.throws(() => routing.__test.moduleSelection(registry, new Proxy({}, { get() { callbacks++; return []; } })));
    assert.equal(callbacks, 0);
  });
  process.stdout.write(`${JSON.stringify({ status: 'pass', checks_total: checks.length, checks, fixture_directory: path.relative(repo, runRoot).replace(/\\/g, '/') }, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ status: 'fail', checks, code: error.code || error.message, stack: error.stack, fixture_directory: path.relative(repo, runRoot).replace(/\\/g, '/') }, null, 2)}\n`);
  process.exitCode = 1;
} finally {
  const physicalRepo = fs.realpathSync.native(repo);
  const physicalRun = fs.realpathSync.native(runRoot);
  const relative = path.relative(physicalRepo, physicalRun);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative) || key(path.join(physicalRepo, relative)) !== key(physicalRun)) {
    throw new Error('routing_test_cleanup_refused_outside_owned_run');
  }
  fs.rmSync(physicalRun, { recursive: true, force: false });
}
