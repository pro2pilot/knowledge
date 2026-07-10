#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir, readJson, writeJsonAtomic, normalizeRelative, getAgentId, withLock } = require('./lib/json-store');
const { autoTrackFromCriticality } = require('./lib/freshness');

const repoRoot = process.cwd();
const kitRoot = path.resolve(__dirname, '..');
const knowledgeRoot = path.join(repoRoot, '.knowledge');
const agentId = getAgentId();
const GENERATED_WORKSPACE_DIR_PATTERNS = [
  /^\.knowledge[_-]backup(?:[_-].*)?$/i,
  /^qa[_-]?runs?$/i,
  /^_baseline(?:[_-].*)?$/i,
  /^__pycache__$/i
];

function isGeneratedWorkspaceDirName(name) {
  return GENERATED_WORKSPACE_DIR_PATTERNS.some((pattern) => pattern.test(String(name || '')));
}

function parseArgs(argv) {
  const args = new Set(argv);
  // opt-out flag and configurable limit for auto-tracking.
  let autoTrackLimit = 1000;
  for (const value of argv) {
    const match = String(value).match(/^--auto-track-limit=(\d+)$/);
    if (match) autoTrackLimit = Number(match[1]);
  }
  return {
    force: args.has('--force'),
    merge: args.has('--merge') || !args.has('--replace'),
    runSync: !args.has('--no-sync'),
    autoTrack: !args.has('--no-auto-track'),
    autoTrackLimit
  };
}
function exists(p) { return fs.existsSync(p); }
function safeReadJson(p, fallback = null) { return readJson(p, fallback); }
function writeJson(p, obj) { writeJsonAtomic(p, obj); }
function sha256(p) { return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); }
function nowIso() { return new Date().toISOString(); }
function rel(p) { return path.relative(repoRoot, p).replace(/\\/g, '/'); }
function normalizeModuleId(value) { return String(value || 'root').replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase() || 'root'; }

function isFile(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

function isDirectory(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}

function isKnowledgeSourceCheckoutDir(full, name = path.basename(full)) {
  const lower = String(name || '').toLowerCase();
  const pkg = safeReadJson(path.join(full, 'package.json'), {}) || {};
  const hasKnowledgePackage = pkg.name === 'dot-knowledge' || pkg.name === 'knowledge' || /knowledge/.test(String(pkg.name || ''));
  const hasReleaseTool = isFile(path.join(full, 'tools', 'package-release.js'));
  const hasInstallManifest = isFile(path.join(full, 'install-manifest.json'));
  const hasQuickStart = isFile(path.join(full, 'Quick-Start.md'));
  const hasSourceGit = isDirectory(path.join(full, '.git'));
  return (
    lower === 'knowledge-src' ||
    lower.startsWith('knowledge-src') ||
    (hasKnowledgePackage && hasReleaseTool && hasInstallManifest) ||
    (hasSourceGit && hasReleaseTool && hasQuickStart)
  );
}

function ignoredSourceCheckouts() {
  let entries = [];
  try { entries = fs.readdirSync(repoRoot, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((entry) => entry.isDirectory())
    .filter((entry) => !['.knowledge', '.agents', '.claude', '.opencode', 'node_modules', '.git'].includes(entry.name))
    .filter((entry) => !isGeneratedWorkspaceDirName(entry.name))
    .filter((entry) => isKnowledgeSourceCheckoutDir(path.join(repoRoot, entry.name), entry.name))
    .map((entry) => `${entry.name}/`)
    .sort();
}

function listTopLevelDirectories() {
  return fs.readdirSync(repoRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((name) => name === '.github' || !name.startsWith('.'))
    .filter((name) => !['node_modules', '.knowledge', '.knowledge', '.agents', '.claude', '.opencode'].includes(name))
    .filter((name) => !isGeneratedWorkspaceDirName(name))
    .filter((name) => !isKnowledgeSourceCheckoutDir(path.join(repoRoot, name), name));
}

function detectTechnologies() {
  const technologies = new Set();
  const rootPackage = safeReadJson(path.join(repoRoot, 'package.json'));
  if (rootPackage) technologies.add('Node.js');
  if (exists(path.join(repoRoot, 'pnpm-workspace.yaml'))) technologies.add('pnpm workspace');
  if (exists(path.join(repoRoot, 'turbo.json'))) technologies.add('Turborepo');
  if (exists(path.join(repoRoot, 'pyproject.toml')) || exists(path.join(repoRoot, 'requirements.txt'))) technologies.add('Python');
  if (exists(path.join(repoRoot, 'go.mod'))) technologies.add('Go');
  if (exists(path.join(repoRoot, 'Cargo.toml'))) technologies.add('Rust');
  if (exists(path.join(repoRoot, 'Gemfile'))) technologies.add('Ruby');
  if (exists(path.join(repoRoot, 'composer.json'))) technologies.add('PHP');
  if (exists(path.join(repoRoot, 'pom.xml')) || exists(path.join(repoRoot, 'build.gradle')) || exists(path.join(repoRoot, 'build.gradle.kts'))) technologies.add('JVM');
  for (const candidate of ['web/package.json', 'desktop/package.json', 'mcp/package.json', 'app/package.json', 'frontend/package.json']) {
    const pkg = safeReadJson(path.join(repoRoot, candidate));
    if (!pkg) continue;
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    if (deps.next) technologies.add('Next.js');
    if (deps.react) technologies.add('React');
    if (deps.electron || pkg.build) technologies.add('Electron');
    if (deps.typescript) technologies.add('TypeScript');
    if (deps['@modelcontextprotocol/sdk']) technologies.add('MCP');
  }
  if (exists(path.join(repoRoot, 'worker'))) technologies.add('Python');
  if (exists(path.join(repoRoot, 'worker', 'docker-compose.yaml'))) technologies.add('Docker Compose');
  if (exists(path.join(repoRoot, 'supabase', 'config.toml'))) technologies.add('Supabase');
  if (exists(path.join(repoRoot, 'Dockerfile')) || exists(path.join(repoRoot, 'docker-compose.yml')) || exists(path.join(repoRoot, 'docker-compose.yaml')) || exists(path.join(repoRoot, 'compose.yaml'))) technologies.add('Containerized runtime');
  return Array.from(technologies).sort();
}

function detectModuleRole(dir, full) {
  const lower = dir.toLowerCase();
  if (dir === '.') return { name: 'root', purpose: 'Repository root: build manifests, workspace config, top-level documentation, and cross-module entrypoints.', trustTarget: 'routing_trusted', confidence: 'medium', status: 'partial' };
  if (['docs', 'doc', 'documentation', 'skills', 'templates', 'examples'].includes(lower)) return { name: dir, purpose: 'Documentation or guidance area; useful for context but not primary source of truth.', trustTarget: 'advisory_only', confidence: 'medium', status: 'partial' };
  if (['web', 'app', 'frontend', 'site', 'client'].includes(lower)) return { name: dir, purpose: 'Primary user-facing application surface.', trustTarget: 'routing_trusted', confidence: 'medium', status: 'partial' };
  if (['api', 'server', 'backend', 'services'].includes(lower)) return { name: dir, purpose: 'Server-side or integration surface.', trustTarget: 'routing_trusted', confidence: 'medium', status: 'partial' };
  if (['worker', 'workers', 'jobs', 'queue', 'runner'].includes(lower)) return { name: dir, purpose: 'Background execution or worker surface.', trustTarget: 'routing_trusted', confidence: 'medium', status: 'partial' };
  if (['db', 'database', 'migrations', 'supabase', 'prisma'].includes(lower)) return { name: dir, purpose: 'Data model, migrations, or persistence boundary.', trustTarget: 'routing_trusted', confidence: 'medium', status: 'partial' };
  if (exists(path.join(full, 'package.json')) || exists(path.join(full, 'pyproject.toml')) || exists(path.join(full, 'Cargo.toml')) || exists(path.join(full, 'go.mod'))) return { name: dir, purpose: 'Standalone package or runtime boundary detected from build manifests.', trustTarget: 'routing_trusted', confidence: 'medium', status: 'partial' };
  return { name: dir, purpose: 'Project area detected from repository structure. Requires targeted verification.', trustTarget: 'routing_trusted', confidence: 'low', status: 'partial' };
}

function collectKeyFiles(full, dir) {
  const rootCandidates = [
    'package.json', 'pnpm-workspace.yaml', 'turbo.json', 'tsconfig.json', 'jsconfig.json', 'vite.config.ts', 'vite.config.js',
    'next.config.js', 'next.config.mjs', 'next.config.ts', 'pyproject.toml', 'requirements.txt', 'go.mod', 'Cargo.toml',
    'composer.json', 'Gemfile', 'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yaml', 'README.md'
  ];
  const moduleCandidates = [
    'package.json', 'pyproject.toml', 'requirements.txt', 'go.mod', 'Cargo.toml', 'composer.json', 'Gemfile',
    'README.md', 'src/index.ts', 'src/index.tsx', 'src/index.js', 'src/index.jsx', 'src/main.ts', 'src/main.js',
    'main.ts', 'main.js', 'index.ts', 'index.tsx', 'index.js', 'index.jsx', 'server.ts', 'server.js',
    'prisma/schema.prisma', 'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yaml'
  ];
  const candidates = dir === '.' ? rootCandidates : moduleCandidates;
  const keyFiles = [];
  const evidenceFiles = [];
  for (const candidate of candidates) {
    const absolute = path.join(full, candidate);
    if (!exists(absolute)) continue;
    const stats = fs.statSync(absolute);
    if (stats.isDirectory()) continue;
    const relative = rel(absolute);
    keyFiles.push(relative);
    if (!/README\.md$/i.test(candidate)) evidenceFiles.push(relative);
  }
  if (keyFiles.length === 0 && exists(full)) {
    const entries = fs.readdirSync(full, { withFileTypes: true }).filter((entry) => entry.isFile()).slice(0, 3);
    for (const entry of entries) keyFiles.push(rel(path.join(full, entry.name)));
  }
  return { keyFiles: Array.from(new Set(keyFiles)), evidenceFiles: Array.from(new Set(evidenceFiles)) };
}


function hasSourceLikeFiles(full, maxDepth = 2) {
  const sourceExts = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.rs', '.java', '.kt', '.php', '.rb', '.cs', '.sql']);
  const stack = [{ dir: full, depth: 0 }];
  while (stack.length) {
    const current = stack.pop();
    let entries = [];
    try { entries = fs.readdirSync(current.dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const abs = path.join(current.dir, entry.name);
      if (entry.isDirectory() && current.depth < maxDepth && !['node_modules', '.git', 'dist', 'build', 'coverage'].includes(entry.name)) stack.push({ dir: abs, depth: current.depth + 1 });
      else if (entry.isFile() && sourceExts.has(path.extname(entry.name).toLowerCase())) return true;
    }
  }
  return false;
}

function detectDomainPurpose(moduleName, modulePath) {
  const key = `${moduleName} ${modulePath}`.toLowerCase();
  if (/auth|session|token|login|identity/.test(key)) return 'Authentication, sessions, identity, or authorization boundary. Always verify source code before behavior claims.';
  if (/billing|payment|invoice|stripe|charge|refund/.test(key)) return 'Billing, payments, invoices, charges, or refunds. High-risk business logic boundary.';
  if (/queue|job|worker|task|scheduler|claim/.test(key)) return 'Queue, jobs, workers, claims, locks, or background processing boundary.';
  if (/user|account|profile|customer/.test(key)) return 'User/account/customer management boundary.';
  if (/db|database|migration|schema|storage|repository/.test(key)) return 'Database, migration, schema, storage, or persistence boundary.';
  if (/notification|email|sms|webhook|message/.test(key)) return 'Notifications, messaging, webhook, or outbound communication boundary.';
  if (/api|route|controller|handler|endpoint/.test(key)) return 'API route, controller, handler, or endpoint boundary.';
  if (/admin|permission|rbac|role/.test(key)) return 'Admin, permissions, roles, or RBAC boundary.';
  return 'Domain module detected from nested source structure. Requires targeted verification against source code.';
}

function shouldPromoteNestedModule(name) {
  const lower = String(name || '').toLowerCase();
  if (lower.startsWith('.')) return false;
  return !['__tests__', 'tests', 'test', 'spec', 'specs', 'utils', 'util', 'shared', 'common', 'helpers', 'types', 'config', 'configs', 'constants', 'assets', 'styles'].includes(lower);
}

function detectNestedDomainModules() {
  const roots = ['src', 'app', 'server', 'api', 'backend', 'services', 'lib'];
  const modules = [];
  for (const rootDir of roots) {
    const absRoot = path.join(repoRoot, rootDir);
    if (!exists(absRoot) || !fs.statSync(absRoot).isDirectory()) continue;
    let entries = [];
    try { entries = fs.readdirSync(absRoot, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (!entry.isDirectory() || !shouldPromoteNestedModule(entry.name)) continue;
      const full = path.join(absRoot, entry.name);
      if (!hasSourceLikeFiles(full, 2)) continue;
      const moduleId = normalizeModuleId(entry.name);
      const files = collectKeyFiles(full, `${rootDir}/${entry.name}`);
      const purpose = detectDomainPurpose(entry.name, `${rootDir}/${entry.name}`);
      const highRisk = /auth|billing|payment|queue|worker|db|migration|security|secret/i.test(`${entry.name} ${rootDir}`);
      modules.push({
        module_id: moduleId,
        name: entry.name,
        path: `${rootDir}/${entry.name}/`,
        card: `.knowledge/modules/${moduleId}.json`,
        status: 'partial',
        confidence: 'medium',
        purpose,
        key_files: files.keyFiles,
        evidence_files: files.evidenceFiles,
        target_trust_level: 'routing_trusted',
        zone_importance: highRisk ? 'critical' : 'important'
      });
    }
  }
  return modules;
}

function detectModules() {
  const modules = [];
  const rootFiles = collectKeyFiles(repoRoot, '.');
  if (rootFiles.keyFiles.length > 0) {
    modules.push({ module_id: 'root', name: 'root', path: '.', card: '.knowledge/modules/root.json', status: 'partial', confidence: 'medium', purpose: 'Repository root: build manifests, workspace config, and cross-module entrypoints.', key_files: rootFiles.keyFiles, evidence_files: rootFiles.evidenceFiles, target_trust_level: 'routing_trusted' });
  }
  const nestedDomainModules = detectNestedDomainModules();
  const nestedPaths = new Set(nestedDomainModules.map((m) => m.path.split('/')[0]));
  const nestedIds = new Set();
  for (const module of nestedDomainModules) {
    let moduleId = module.module_id;
    if (nestedIds.has(moduleId) || modules.some((m) => m.module_id === moduleId)) moduleId = normalizeModuleId(module.path.replace(/\/$/, ''));
    nestedIds.add(moduleId);
    modules.push({ ...module, module_id: moduleId, card: `.knowledge/modules/${moduleId}.json` });
  }
  for (const dir of listTopLevelDirectories()) {
    if (nestedPaths.has(dir) && ['src', 'app', 'server', 'api', 'backend', 'services', 'lib'].includes(dir)) continue;
    if (['tests', 'test', '__tests__', 'spec', 'specs'].includes(dir.toLowerCase())) continue;
    const full = path.join(repoRoot, dir);
    const moduleId = normalizeModuleId(dir);
    if (modules.some((m) => m.module_id === moduleId)) continue;
    const moduleRole = detectModuleRole(dir, full);
    const files = collectKeyFiles(full, dir);
    modules.push({ module_id: moduleId, name: moduleRole.name, path: `${dir}/`, card: `.knowledge/modules/${moduleId}.json`, status: moduleRole.status, confidence: moduleRole.confidence, purpose: moduleRole.purpose, key_files: files.keyFiles, evidence_files: files.evidenceFiles, target_trust_level: moduleRole.trustTarget });
  }
  return modules;
}

function makeModuleCard(module) {
  return {
    module_id: module.module_id,
    name: module.name,
    status: module.status,
    purpose: module.purpose,
    boundaries: { owns: [module.path], does_not_own: [], external_dependencies: [] },
    entry_points: module.evidence_files || [],
    key_files: module.key_files || [],
    public_interfaces: [],
    dependencies: [],
    invariants: [],
    common_failure_zones: ['Initial ingest only. Requires follow-up verification against source code.'],
    related_decisions: [],
    evidence_files: module.evidence_files || [],
    confidence: module.confidence,
    last_verified_at: nowIso(),
    verification_status: 'heuristic_ingest',
    current_trust_level: module.target_trust_level === 'advisory_only' ? 'advisory_only' : 'routing_trusted',
    target_trust_level: module.target_trust_level,
    zone_importance: module.target_trust_level === 'advisory_only' ? 'advisory' : 'important',
    generated_by: agentId
  };
}

function runBootstrapIfNeeded() {
  if (exists(knowledgeRoot)) return;
  throw new Error('Missing .knowledge directory. Extract the .knowledge archive into the repository root before running ingest.');
}

function mergeModules(existing, detected, force) {
  const byId = new Map((existing.modules || []).map((module) => [module.module_id, module]));
  for (const module of detected) {
    const previous = byId.get(module.module_id);
    if (!previous || force) byId.set(module.module_id, module);
    else {
      byId.set(module.module_id, {
        ...previous,
        path: previous.path || module.path,
        card: previous.card || module.card,
        purpose: previous.purpose || module.purpose,
        key_files: Array.from(new Set([...(previous.key_files || []), ...(module.key_files || [])])),
        evidence_files: Array.from(new Set([...(previous.evidence_files || []), ...(module.evidence_files || [])])),
        target_trust_level: previous.target_trust_level || module.target_trust_level
      });
    }
  }
  return Array.from(byId.values()).sort((a, b) => a.module_id.localeCompare(b.module_id));
}

function getCriticality(pathStr) {
  const normalized = normalizeRelative(pathStr);
  const ext = path.extname(normalized).toLowerCase();
  const base = path.posix.basename(normalized).toLowerCase();
  if (/readme\.md$/i.test(normalized) || /(^|\/)(test|tests|__tests__|spec|specs)(\/|$)/i.test(normalized) || /\.(test|spec)\.[^.]+$/i.test(normalized)) return 'contextual';
  if (['package.json', 'pyproject.toml', 'go.mod', 'cargo.toml', 'composer.json', 'gemfile', 'tsconfig.json', 'turbo.json', 'pnpm-workspace.yaml', 'dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yaml'].includes(base)) return 'important';
  if (/(^|\/)(migrations?|schema)(\/|$)/i.test(normalized) && ['.sql', '.prisma', '.json', '.js', '.ts', '.py'].includes(ext)) return /(initial|init|baseline|foundation|0001)/i.test(normalized) ? 'critical' : 'important';
  return ['.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.rs', '.sql', '.prisma', '.yaml', '.yml', '.toml', '.json'].includes(ext) ? 'important' : 'contextual';
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  runBootstrapIfNeeded();
  return withLock(path.join(knowledgeRoot, '.lock'), () => {
    ensureDir(path.join(knowledgeRoot, 'modules'));
    ensureDir(path.join(knowledgeRoot, 'maps'));
    ensureDir(path.join(knowledgeRoot, 'invariants'));
    ensureDir(path.join(knowledgeRoot, 'evidence'));
    ensureDir(path.join(knowledgeRoot, 'maintenance', 'events'));
    ensureDir(path.join(knowledgeRoot, 'sessions', 'recent_tasks'));
    ensureDir(path.join(knowledgeRoot, 'sessions', 'active_tasks'));
    ensureDir(path.join(knowledgeRoot, 'wiki'));
    ensureDir(path.join(knowledgeRoot, 'wiki', 'architecture'));
    ensureDir(path.join(knowledgeRoot, 'wiki', 'runbooks'));
    ensureDir(path.join(knowledgeRoot, 'wiki', 'concepts'));
    ensureDir(path.join(knowledgeRoot, 'search'));

    const generatedAt = nowIso();
    const detectedModules = detectModules();
    const ignoredSourceCheckoutPaths = ignoredSourceCheckouts();
    const technologies = detectTechnologies();
    const existingIndex = safeReadJson(path.join(knowledgeRoot, 'project_index.json'), { status: 'stub' });
    if (!options.force && !['stub', 'heuristic_ingest', undefined, null].includes(existingIndex.status) && !options.merge) {
      throw new Error('project_index.json does not look like a stub/heuristic ingest. Use --merge or --force explicitly.');
    }

    const existingRegistry = safeReadJson(path.join(knowledgeRoot, 'modules', 'module_registry.json'), { generated_at: null, modules: [] });
    const mergedModules = mergeModules(existingRegistry, detectedModules, options.force);
    const registry = { generated_at: generatedAt, generated_by: agentId, merge_mode: options.force ? 'force' : 'merge', modules: mergedModules };

    const projectIndex = {
      ...existingIndex,
      project_name: existingIndex.project_name || path.basename(repoRoot),
      repo_root: '.',
      generated_at: generatedAt,
      generated_by: agentId,
      status: existingIndex.status && existingIndex.status !== 'stub' && options.merge ? existingIndex.status : 'heuristic_ingest',
      summary: existingIndex.summary || 'Initial shallow ingest generated from repository structure. Replace heuristics with code-backed summaries as modules are verified.',
      primary_source_of_truth: 'code',
      technologies,
      runtime_surfaces: mergedModules.map((m) => ({ id: m.module_id, path: m.path, role: m.purpose })),
      modules: mergedModules.map((m) => ({ module_id: m.module_id, card: m.card, confidence: m.confidence })),
      primary_entrypoints: mergedModules.flatMap((m) => (m.evidence_files || []).map((f) => ({ name: `${m.module_id} entrypoint`, file: f }))),
      task_routing: mergedModules.map((m) => ({ route_id: m.module_id, keywords: [m.module_id, String(m.name || '').toLowerCase()].filter(Boolean), target_modules: [m.module_id], start_with: [m.card, ...(m.key_files || []).slice(0, 5)] }))
    };

    const freshness = safeReadJson(path.join(knowledgeRoot, 'freshness.json'), { generated_at: null, hash_algorithm: 'sha256', tracked_files: [], artifact_dependencies: {}, artifact_statuses: {} });
    freshness.generated_at = generatedAt;
    freshness.hash_algorithm = 'sha256';
    freshness.tracked_files = freshness.tracked_files || [];
    freshness.artifact_dependencies = freshness.artifact_dependencies || {};
    const trackedByPath = new Map(freshness.tracked_files.map((entry) => [entry.path, entry]));

    const fileCriticality = safeReadJson(path.join(knowledgeRoot, 'maps', 'file_criticality.json'), { generated_at: null, files: [], coverage_by_module: {} });
    fileCriticality.generated_at = generatedAt;
    fileCriticality.files = fileCriticality.files || [];
    fileCriticality.coverage_by_module = fileCriticality.coverage_by_module || {};

    for (const module of mergedModules) {
      const cardPath = path.join(repoRoot, module.card);
      const existingCard = safeReadJson(cardPath, null);
      if (!existingCard || options.force || /heuristic_ingest|unknown|placeholder/i.test(String(existingCard.verification_status || ''))) {
        const nextCard = existingCard && options.merge ? { ...makeModuleCard(module), ...existingCard, key_files: Array.from(new Set([...(existingCard.key_files || []), ...(module.key_files || [])])), evidence_files: Array.from(new Set([...(existingCard.evidence_files || []), ...(module.evidence_files || [])])) } : makeModuleCard(module);
        writeJson(cardPath, nextCard);
      }
      freshness.artifact_dependencies[module.card] = Array.from(new Set([...(freshness.artifact_dependencies[module.card] || []), ...(module.key_files || []), ...(module.evidence_files || [])]));

      const coverage = fileCriticality.coverage_by_module[module.module_id] || { important_or_critical_files: [], tracked_in_freshness: [], referenced_by_module_card: [], covered_by_evidence: [], uncovered: [] };
      for (const file of Array.from(new Set([...(module.key_files || []), ...(module.evidence_files || [])]))) {
        const abs = path.join(repoRoot, file);
        if (!exists(abs) || !fs.statSync(abs).isFile()) continue;
        if (!trackedByPath.has(file)) {
          const entry = { path: file, sha256: sha256(abs), last_scanned_at: generatedAt, status: 'clean', first_seen_by: agentId, first_seen_at: generatedAt };
          freshness.tracked_files.push(entry);
          trackedByPath.set(file, entry);
        }
        const classification = getCriticality(file);
        if (!fileCriticality.files.some((item) => item.path === file)) fileCriticality.files.push({ path: file, classification, modules: [module.module_id], source: 'heuristic_ingest' });
        if (['critical', 'important'].includes(classification) && !coverage.important_or_critical_files.includes(file)) coverage.important_or_critical_files.push(file);
        if (!coverage.tracked_in_freshness.includes(file)) coverage.tracked_in_freshness.push(file);
        if (!coverage.referenced_by_module_card.includes(file)) coverage.referenced_by_module_card.push(file);
      }
      coverage.uncovered = coverage.important_or_critical_files.filter((file) => !(coverage.covered_by_evidence || []).includes(file));
      fileCriticality.coverage_by_module[module.module_id] = coverage;
    }

    const directoryMap = { generated_at: generatedAt, generated_by: agentId, directories: listTopLevelDirectories().map((dir) => ({ path: `${dir}/`, module_id: normalizeModuleId(dir), status: 'detected' })) };
    const entrypoints = { generated_at: generatedAt, generated_by: agentId, entrypoints: mergedModules.flatMap((m) => (m.evidence_files || []).map((file) => ({ module_id: m.module_id, file, kind: 'heuristic' }))) };
    const dependencyMap = safeReadJson(path.join(knowledgeRoot, 'maps', 'dependency_map.json'), { generated_at: generatedAt, edges: [] });
    dependencyMap.generated_at = generatedAt;
    dependencyMap.generated_by = agentId;

    const repairQueue = safeReadJson(path.join(knowledgeRoot, 'maintenance', 'repair_queue.json'), { generated_at: null, queue: [] });
    repairQueue.generated_at = generatedAt;
    repairQueue.queue = repairQueue.queue || [];
    if (!repairQueue.queue.some((item) => item.subject === 'Replace heuristic ingest with code-backed module summaries')) {
      repairQueue.queue.push({ id: `RQ-${String(repairQueue.queue.length + 1).padStart(4, '0')}`, priority: 'medium', subject: 'Replace heuristic ingest with code-backed module summaries', affected_artifacts: ['.knowledge/modules/*.json', '.knowledge/evidence/file_facts.json'], detected_by: agentId, detected_at: generatedAt });
    }

    const handoffSummary = safeReadJson(path.join(knowledgeRoot, 'maintenance', 'handoff_summary.json'), { generated_at: null });
    handoffSummary.generated_at = generatedAt;
    handoffSummary.generated_by = agentId;
    handoffSummary.project_operational_summary = handoffSummary.project_operational_summary || projectIndex.summary;
    handoffSummary.new_chat_first_files = ['.knowledge/maintenance/routing_bundle.json', '.knowledge/project_index.json', '.knowledge/maintenance/trust_report.json', '.knowledge/maintenance/handoff_summary.json', '.knowledge/wiki/index.md', '.knowledge/maps/critical_paths.json'];
    handoffSummary.maintenance_commands = ['node .knowledge/tools/sync-tracked.js', 'node .knowledge/tools/sync-tracked.js --scan', 'node .knowledge/tools/sync-tracked.js --scan --discover', 'node .knowledge/tools/build-routing-bundle.js', 'node .knowledge/tools/build-search-index.js', 'node .knowledge/tools/doctor.js', 'node .knowledge/tools/watch-maintenance.js'];
    handoffSummary.minimal_new_chat_prompt = 'Start from .knowledge/maintenance/routing_bundle.json. Then open only the relevant project_index/trust_report/handoff/module cards/wiki pages/source files. Treat code as source of truth and re-read suspect/low-confidence areas.';

    // auto-track critical/important files derived from
    // file_criticality.json so freshness.tracked_files is non-zero after a
    // fresh ingest. Capped by --auto-track-limit (default 1000) and disabled
    // by --no-auto-track. Files added by ingest's per-module loop above are
    // already in the index, so this only fills the rest.
    let autoTrackResult = { added: 0, considered: 0, capped: false, limit: options.autoTrackLimit, tracked_total: (freshness.tracked_files || []).length };
    if (options.autoTrack) {
      autoTrackResult = autoTrackFromCriticality(freshness, repoRoot, fileCriticality, {
        limit: options.autoTrackLimit,
        scopes: ['critical', 'important'],
        timestamp: generatedAt,
        agentId,
        source: 'ingest_auto_track_a1lite'
      });
    }

    writeJson(path.join(knowledgeRoot, 'project_index.json'), projectIndex);
    writeJson(path.join(knowledgeRoot, 'modules', 'module_registry.json'), registry);
    writeJson(path.join(knowledgeRoot, 'freshness.json'), freshness);
    writeJson(path.join(knowledgeRoot, 'maps', 'file_criticality.json'), fileCriticality);
    writeJson(path.join(knowledgeRoot, 'maps', 'directory_map.json'), directoryMap);
    writeJson(path.join(knowledgeRoot, 'maps', 'entrypoints.json'), entrypoints);
    writeJson(path.join(knowledgeRoot, 'maps', 'dependency_map.json'), dependencyMap);
    writeJson(path.join(knowledgeRoot, 'maintenance', 'repair_queue.json'), repairQueue);
    writeJson(path.join(knowledgeRoot, 'maintenance', 'handoff_summary.json'), handoffSummary);

    const wikiIndexPath = path.join(knowledgeRoot, 'wiki', 'index.md');
    if (!exists(wikiIndexPath) || options.force) {
      const moduleLines = mergedModules.map((m) => `- ${m.module_id}: ${m.path} — ${m.purpose}`).join('\n');
      fs.writeFileSync(wikiIndexPath, `# Knowledge Wiki Index\n\nProject: ${projectIndex.project_name}\n\nThis wiki is advisory unless backed by current code/tests and evidence JSON.\n\n## Detected modules\n\n${moduleLines || '- none detected'}\n\n## Sections\n\n- architecture/\n- runbooks/\n- concepts/\n\n`, 'utf8');
    }
    const wikiLogPath = path.join(knowledgeRoot, 'wiki', 'log.md');
    if (!exists(wikiLogPath) || options.force) {
      fs.writeFileSync(wikiLogPath, `# Knowledge Maintenance Log\n\n${generatedAt} — ${agentId} — heuristic ingest created/updated module routing.\n`, 'utf8');
    }

    let routingBundle = null;
    let searchIndex = null;
    try { routingBundle = require(path.join(knowledgeRoot, 'tools', 'build-routing-bundle.js'))({ skipLock: true, quiet: true }); } catch {}
    try { searchIndex = require(path.join(knowledgeRoot, 'tools', 'build-search-index.js'))({ skipLock: true, quiet: true }); } catch {}

    return {
      generated_at: generatedAt,
      modules_detected: detectedModules.length,
      modules_total: mergedModules.length,
      ignored_source_checkouts: ignoredSourceCheckoutPaths,
      technologies,
      root_module: mergedModules.some((m) => m.module_id === 'root'),
      mode: options.force ? 'force' : 'merge',
      routing_bundle: routingBundle ? '.knowledge/maintenance/routing_bundle.json' : null,
      search_documents: searchIndex ? searchIndex.document_count : null,
      auto_track: {
        enabled: options.autoTrack,
        limit: options.autoTrackLimit,
        added: autoTrackResult.added,
        considered: autoTrackResult.considered,
        capped: autoTrackResult.capped,
        tracked_total: autoTrackResult.tracked_total
      }
    };
  });
}

if (require.main === module) {
  try {
    const result = main();
    if (parseArgs(process.argv.slice(2)).runSync) {
      const sync = require(path.join(knowledgeRoot, 'tools', 'sync-tracked.js'));
      result.sync = sync();
      try { result.routing_bundle_refreshed = !!require(path.join(knowledgeRoot, 'tools', 'build-routing-bundle.js'))({ quiet: true }); } catch (error) { result.routing_bundle_error = error.message; }
      try { result.search_documents = require(path.join(knowledgeRoot, 'tools', 'build-search-index.js'))({ quiet: true }).document_count; } catch (error) { result.search_index_error = error.message; }
      try { const quality = require(path.join(knowledgeRoot, 'tools', 'doctor.js'))({ quiet: true }); result.quality_score = quality.quality_score; result.quality_status = quality.status; } catch (error) { result.doctor_error = error.message; }
    }
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = main;
