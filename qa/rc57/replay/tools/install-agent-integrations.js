#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const {
  assertSafeContainmentRoot,
  assertSafeContainedPath,
  ensureContainedDir,
  writeJsonAtomicContained,
  writeFileAtomicContained
} = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');
const { resolveKnowledgeContext, contextEnv, parseCliArgs } = require('./lib/path-context');

const LEGACY_MANAGED_MARKER = ['KNOWLEDGE', 'KIT'].join('-');
const MANAGED_MARKERS = ['DOT-KNOWLEDGE', LEGACY_MANAGED_MARKER];
const MANAGED_START = '<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->';
const MANAGED_END = '<!-- END DOT-KNOWLEDGE MANAGED BLOCK -->';
const INTEGRATION_TRANSACTION_LOCK_TIMEOUT_MS = 120000;

const RUNTIME_ALIASES = {
  agents: 'codex',
  codex: 'codex',
  'codex-cli': 'codex',
  claude: 'claude',
  'claude-code': 'claude',
  anthropic: 'claude',
  opencode: 'opencode',
  'open-code': 'opencode',
  openclaw: 'openclaw',
  'open-claw': 'openclaw',
  'openclaw-cli': 'openclaw',
  hermes: 'hermes',
  'hermes-cli': 'hermes',
  gemini: 'gemini',
  'gemini-cli': 'gemini',
  copilot: 'copilot',
  'github-copilot': 'copilot',
  devin: 'devin',
  windsurf: 'windsurf',
  cascade: 'windsurf',
  'windsurf-cascade': 'windsurf',
  continue: 'continue',
  'continue-dev': 'continue',
  roo: 'roo',
  'roo-code': 'roo',
  aider: 'aider'
};

function normalizeRuntime(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return RUNTIME_ALIASES[normalized] || null;
}

function supportedRuntimeIds() {
  return ['codex', 'claude', 'opencode', 'openclaw', 'hermes', 'gemini', 'copilot', 'devin', 'windsurf', 'continue', 'roo', 'aider'];
}

function runtimeCommands() {
  return supportedRuntimeIds().map((id) => `node .knowledge/tools/install-agent-integrations.js --runtime ${id}`);
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function htmlManagedBlockRegex() {
  const families = MANAGED_MARKERS.map(escapeRegex).join('|');
  return new RegExp(`<!-- BEGIN (?:${families}) MANAGED BLOCK -->[\\s\\S]*?<!-- END (?:${families}) MANAGED BLOCK -->\\n?`, 'g');
}

function hashManagedBlockRegex() {
  const families = MANAGED_MARKERS.map(escapeRegex).join('|');
  return new RegExp(`# BEGIN (?:${families}) MANAGED BLOCK[\\s\\S]*?# END (?:${families}) MANAGED BLOCK\\n?`, 'g');
}

function replaceManagedBlocks(current, block, regex) {
  let replaced = false;
  let count = 0;
  const next = current.replace(regex, () => {
    count += 1;
    if (replaced) return '';
    replaced = true;
    return block;
  });
  return { next, count };
}

function integrationSafetyError(code, message, targetPath, rootPath, cause = null) {
  const error = new Error(message);
  error.code = code;
  error.target = targetPath ? path.resolve(targetPath) : null;
  error.root = rootPath ? path.resolve(rootPath) : null;
  if (cause) error.cause = cause;
  return error;
}

function assertContainedFileTarget(rootPath, filePath, options = {}) {
  const root = assertSafeContainmentRoot(rootPath);
  const target = path.resolve(filePath);
  try {
    assertSafeContainedPath(root, target, { allowMissing: options.allowMissing === true });
  } catch (error) {
    throw integrationSafetyError(
      'UNSAFE_INTEGRATION_TARGET',
      `Unsafe integration target: ${target}: ${error.message}`,
      target,
      root,
      error
    );
  }
  if (fs.existsSync(target)) {
    const stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw integrationSafetyError(
        'UNSAFE_INTEGRATION_TARGET_TYPE',
        `Integration target must be a physical file: ${target}`,
        target,
        root
      );
    }
  }
  return target;
}

function assertContainedSourceFile(rootPath, filePath) {
  const root = assertSafeContainmentRoot(rootPath);
  const source = path.resolve(filePath);
  try {
    assertSafeContainedPath(root, source);
  } catch (error) {
    throw integrationSafetyError(
      'UNSAFE_INTEGRATION_SOURCE',
      `Unsafe integration source: ${source}: ${error.message}`,
      source,
      root,
      error
    );
  }
  const stat = fs.lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw integrationSafetyError(
      'UNSAFE_INTEGRATION_SOURCE_TYPE',
      `Integration source must be a physical file: ${source}`,
      source,
      root
    );
  }
  return source;
}

function readContainedText(rootPath, filePath) {
  const target = assertContainedFileTarget(rootPath, filePath, { allowMissing: false });
  return fs.readFileSync(target, 'utf8');
}

function readContainedJson(rootPath, filePath) {
  return JSON.parse(readContainedText(rootPath, filePath).replace(/^\uFEFF/, ''));
}

function removeContainedFile(rootPath, filePath) {
  const target = path.resolve(filePath);
  if (!fs.existsSync(target)) return false;
  assertContainedFileTarget(rootPath, target);
  fs.rmSync(target, { force: true });
  return true;
}

function pruneEmptyContainedParents(rootPath, filePath) {
  const root = assertSafeContainmentRoot(rootPath);
  let current = path.dirname(path.resolve(filePath));
  while (current !== root) {
    assertSafeContainedPath(root, current);
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || fs.readdirSync(current).length) return;
    fs.rmdirSync(current);
    current = path.dirname(current);
  }
}

function upsertManagedBlock(filePath, blockBody, options = {}) {
  const root = options.containmentRoot;
  if (!root) throw new Error('upsertManagedBlock requires containmentRoot');
  assertContainedFileTarget(root, filePath, { allowMissing: true });
  ensureContainedDir(root, path.dirname(filePath));
  const block = `${MANAGED_START}\n${blockBody.trim()}\n${MANAGED_END}\n`;
  if (!fs.existsSync(filePath)) {
    writeFileAtomicContained(filePath, options.prefix ? `${options.prefix.trim()}\n\n${block}` : block, root);
    return 'created';
  }
  const current = readContainedText(root, filePath);
  const replaced = replaceManagedBlocks(current, block, htmlManagedBlockRegex());
  if (replaced.count > 0) {
    writeFileAtomicContained(filePath, replaced.next, root);
    return replaced.count > 1 ? 'deduplicated' : 'updated';
  }
  writeFileAtomicContained(filePath, `${current.replace(/\s*$/, '')}\n\n${block}`, root);
  return 'appended';
}

function upsertHashManagedBlock(filePath, blockBody, options = {}) {
  const root = options.containmentRoot;
  if (!root) throw new Error('upsertHashManagedBlock requires containmentRoot');
  assertContainedFileTarget(root, filePath, { allowMissing: true });
  ensureContainedDir(root, path.dirname(filePath));
  const start = '# BEGIN DOT-KNOWLEDGE MANAGED BLOCK';
  const end = '# END DOT-KNOWLEDGE MANAGED BLOCK';
  const block = `${start}\n${blockBody.trim()}\n${end}\n`;
  if (!fs.existsSync(filePath)) {
    writeFileAtomicContained(filePath, options.prefix ? `${options.prefix.trim()}\n\n${block}` : block, root);
    return 'created';
  }
  const current = readContainedText(root, filePath);
  const replaced = replaceManagedBlocks(current, block, hashManagedBlockRegex());
  if (replaced.count > 0) {
    writeFileAtomicContained(filePath, replaced.next, root);
    return replaced.count > 1 ? 'deduplicated' : 'updated';
  }
  writeFileAtomicContained(filePath, `${current.replace(/\s*$/, '')}\n\n${block}`, root);
  return 'appended';
}

function normalizeReleasePath(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function publicIntegrationAllowlist(kitRoot) {
  const manifestPath = path.join(kitRoot, 'install-manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`Public integration allowlist manifest is missing: ${manifestPath}`);
  }
  const manifest = readContainedJson(kitRoot, manifestPath);
  const paths = manifest?.release_contract?.public_agent_integration_paths;
  if (!Array.isArray(paths) || paths.length === 0) {
    throw new Error('release_contract.public_agent_integration_paths must be a non-empty array');
  }
  return new Set(paths.map(normalizeReleasePath));
}

function collectCopyEntries(kitRoot, srcDir, dstDir, allowlist, result = { entries: [], rejected: [] }) {
  if (!fs.existsSync(srcDir)) return result;
  assertSafeContainedPath(kitRoot, srcDir);
  const srcStat = fs.lstatSync(srcDir);
  if (!srcStat.isDirectory() || srcStat.isSymbolicLink()) {
    throw integrationSafetyError('UNSAFE_INTEGRATION_SOURCE_TYPE', `Integration source directory is unsafe: ${srcDir}`, srcDir, kitRoot);
  }
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    const src = path.join(srcDir, entry.name);
    const dst = path.join(dstDir, entry.name);
    assertSafeContainedPath(kitRoot, src);
    const stat = fs.lstatSync(src);
    if (stat.isSymbolicLink()) {
      throw integrationSafetyError('UNSAFE_INTEGRATION_SOURCE', `Integration source contains a symlink: ${src}`, src, kitRoot);
    }
    if (entry.isDirectory()) {
      collectCopyEntries(kitRoot, src, dst, allowlist, result);
    } else if (entry.isFile()) {
      const sourceRel = normalizeReleasePath(path.relative(kitRoot, src));
      if (allowlist && !allowlist.has(sourceRel)) {
        result.rejected.push(sourceRel);
        continue;
      }
      result.entries.push({ source: src, target: dst, source_rel: sourceRel });
    } else {
      throw integrationSafetyError('UNSAFE_INTEGRATION_SOURCE_TYPE', `Unsupported integration source entry: ${src}`, src, kitRoot);
    }
  }
  return result;
}

function copyContainedFile(sourceRoot, sourcePath, targetRoot, targetPath) {
  const source = assertContainedSourceFile(sourceRoot, sourcePath);
  assertContainedFileTarget(targetRoot, targetPath, { allowMissing: true });
  const body = fs.readFileSync(source);
  writeFileAtomicContained(targetPath, body, targetRoot);
}

function copyPublicIntegrationDir(kitRoot, srcDir, repoRoot, dstDir) {
  const plan = collectCopyEntries(
    kitRoot,
    srcDir,
    dstDir,
    publicIntegrationAllowlist(kitRoot)
  );
  const written = [];
  for (const item of plan.entries) {
    copyContainedFile(kitRoot, item.source, repoRoot, item.target);
    written.push(item.target);
  }
  return { written, rejected: plan.rejected };
}

function recordPublicIntegrationCopy(installed, key, result) {
  installed[key] = result.written.length;
  installed[`${key}_source_only_rejections`] = result.rejected.slice().sort();
}

function readTemplate(kitRoot, relPath, fallback) {
  const templatePath = path.join(kitRoot, 'agent-integrations', relPath);
  try {
    fs.lstatSync(templatePath);
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
  return readContainedText(kitRoot, templatePath);
}

function sharedTemplate(kitRoot, name, fallback) {
  return readTemplate(kitRoot, path.join('_shared', name), fallback);
}

function renderTemplate(kitRoot, relPath, fallback, replacements = {}) {
  let rendered = readTemplate(kitRoot, relPath, fallback);
  const common = {
    TRUST_ROUTING: sharedTemplate(kitRoot, 'trust-routing.md', trustRoutingBlock()),
    FINAL_REPORT_CONTRACT: sharedTemplate(kitRoot, 'final-report-contract.md', finalReportContractLines().join('\n')),
    ...replacements
  };
  for (const [key, value] of Object.entries(common)) {
    rendered = rendered.replace(new RegExp(`{{${escapeRegex(key)}}}`, 'g'), String(value).trim());
  }
  return rendered;
}

function managedGitAttributePaths(repoRoot) {
  const filePath = path.join(repoRoot, '.gitattributes');
  if (!fs.existsSync(filePath)) return [];
  const current = readContainedText(repoRoot, filePath);
  const match = hashManagedBlockRegex().exec(current);
  if (!match) return [];
  const paths = [];
  for (const rawLine of match[0].split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line === '.gitattributes text eol=lf') continue;
    const parsed = line.match(/^(.*?)\s+text\s+eol=lf$/);
    if (parsed && parsed[1].trim()) paths.push(parsed[1].trim());
  }
  return paths;
}

function upsertGitAttributes(repoRoot, relPaths) {
  // Connecting another runtime must not remove attributes installed for an
  // earlier runtime. Keep the union of the existing managed entries and the
  // current installation plan while leaving user-authored lines untouched.
  const unique = Array.from(new Set([
    ...managedGitAttributePaths(repoRoot),
    ...relPaths.map((item) => String(item || '').trim()).filter(Boolean)
  ])).sort();
  const body = [
    '# .knowledge installed integration files',
    '.gitattributes text eol=lf',
    ...unique.map((item) => `${item} text eol=lf`)
  ].join('\n');
  return upsertHashManagedBlock(path.join(repoRoot, '.gitattributes'), body, { containmentRoot: repoRoot });
}

function updatePackageJson(repoRoot) {
  const packagePath = path.join(repoRoot, 'package.json');
  if (!fs.existsSync(packagePath)) return { status: 'not_found' };
  assertContainedFileTarget(repoRoot, packagePath);
  const pkg = readContainedJson(repoRoot, packagePath);
  pkg.scripts = pkg.scripts || {};
  const scripts = {
    'kb:ingest': 'node .knowledge/tools/ingest-existing-project.js --merge',
    'kb:sync': 'node .knowledge/tools/sync-tracked.js',
    'kb:scan': 'node .knowledge/tools/sync-tracked.js --scan',
    'kb:discover': 'node .knowledge/tools/sync-tracked.js --scan --discover',
    'kb:watch': 'node .knowledge/tools/watch-maintenance.js',
    'kb:hooks': 'node .knowledge/tools/install-git-hooks.js',
    'kb:integrations': 'node .knowledge/tools/install-agent-integrations.js',
    'kb:install-check': 'node .knowledge/tools/install-check.js --json',
    'kb:update-system': 'node .knowledge/tools/update-system-files.js',
    'kb:update-system:verify': 'node .knowledge/tools/update-system-files.js --verify-upgrade --json',
    'kb:git-policy': 'node .knowledge/tools/git-policy.js --json',
    'kb:routing': 'node .knowledge/tools/build-routing-bundle.js',
    'kb:index': 'node .knowledge/tools/build-search-index.js',
    'kb:search': 'node .knowledge/tools/search-knowledge.js',
    'kb:doctor': 'node .knowledge/tools/doctor.js',
    'kb:wikigraph': 'node .knowledge/tools/build-wiki-graph.js',
    'kb:lint-wiki': 'node .knowledge/tools/lint-wiki.js',
    'kb:external:status': 'node .knowledge/tools/external-memory-status.js',
    'kb:metrics': 'node .knowledge/tools/collect-metrics.js',
    'kb:evaluate': 'node .knowledge/tools/evaluation-harness.js',
    'kb:pr-summary': 'node .knowledge/tools/generate-pr-summary.js',
    'kb:inspector': 'node .knowledge/inspector.js',
    'kb:flow': 'node .knowledge/tools/flow.js release',
    'kb:smoke': 'node .knowledge/tools/watch-smoke.js',
    'kb:team:init': 'node .knowledge/tools/team-init.js --json',
    'kb:team:register': 'node .knowledge/tools/workspace-register.js --json',
    'kb:team:status': 'node .knowledge/tools/team-status.js --json',
    'kb:team:unregister': 'node .knowledge/tools/workspace-unregister.js --json',
    'kb:worktree-status': 'node .knowledge/tools/worktree-status.js --json',
    'kb:team:pr-summary': 'node .knowledge/tools/team-pr-summary.js --json'
  };
  const changed = [];
  for (const [name, value] of Object.entries(scripts)) {
    if (pkg.scripts[name] !== value) {
      pkg.scripts[name] = value;
      changed.push(name);
    }
  }
  writeJsonAtomicContained(packagePath, pkg, repoRoot);
  return { status: changed.length ? 'updated' : 'unchanged', changed };
}

function finalReportContractLines() {
  return [
    '## Final report after meaningful work',
    '',
    'After meaningful work or before handoff, run:',
    '',
    '`node .knowledge/tools/flow.js release`',
    '',
    'Then report:',
    '',
    '- doctor score/status;',
    '- wiki lint score/status;',
    '- suspect or low-confidence modules;',
    '- repair queue items;',
    '- routing bundle path;',
    '- PR summary path;',
    '- metrics path;',
    '- exactly one routing-context estimate state according to `.knowledge/agent-integrations/_shared/metrics-reporting.md`;',
    '- an explicit note when the estimate is unavailable, not comparable, stale, or was not regenerated in this run.',
    '',
    'Never describe the local estimate as provider-reported model-token savings.'
  ];
}

function trustRoutingBlock() {
  return `Use \`.knowledge/\` as the first trust/routing layer for this repository.

## First file to read

1. \`.knowledge/maintenance/routing_bundle.json\`

Then read only what the bundle says is relevant:

- \`.knowledge/project_index.json\`
- \`.knowledge/maintenance/trust_report.json\`
- \`.knowledge/maintenance/handoff_summary.json\`
- \`.knowledge/wiki/index.md\`
- relevant \`.knowledge/modules/*.json\`
- relevant source files and tests

## Source-of-truth order

1. Current code
2. Current tests
3. \`.knowledge/evidence/*.json\`
4. \`.knowledge/modules/*.json\`
5. \`.knowledge/decisions.json\`
6. \`.knowledge/wiki/*.md\`
7. \`.knowledge/sessions/*\`

Code beats summaries. Tests beat prose. Wiki is advisory unless backed by evidence and current code/tests.

## Trust rules

- \`trusted\`: usable for routing and limited planning; re-read code before critical behavior edits.
- \`near_trusted\`: usable after targeted code checks.
- \`routing_trusted\`: use only to choose files, modules, and boundaries.
- \`advisory_only\`: context only; never source of truth.
- \`suspect\`, \`needs_recheck\`, \`low_confidence\`: re-read source code before behavior claims or edits.

## Opportunistic knowledge repair

The built-in default is task-scoped repair. After routing, plan only against the
current task:

\`node .knowledge/tools/repair-on-touch.js plan --task "<current task>" --json\`

The plan is a hard scope boundary. Complete the primary task first. If that work
actually verifies every required source artifact and runs the finding's required
checks, record those checks through \`repair-on-touch.js verify\` or
\`repair-on-touch.js receipt --request=<json>\`, then apply only the receipt's
exact lifecycle ID. Never claim an unexecuted test, close a sibling finding,
edit source code for Doctor score, or auto-close a contradiction, security,
policy, incident, architecture-conflict, or manual-review finding. Leave
unrelated debt deferred.

Before the final answer, rerun Doctor and use
\`node .knowledge/tools/repair-on-touch.js summary --request=<json>\` to keep the
primary-task result, maintenance performed, global Doctor, task readiness, and
deferred work visibly separate. See \`.knowledge/docs/repair-on-touch.md\` for
the request contract.

## Maintenance

After significant changes, run:

\`node .knowledge/tools/sync-tracked.js\`

When new files, wiki pages, or module summaries changed, also run:

\`node .knowledge/tools/build-routing-bundle.js\`
\`node .knowledge/tools/build-search-index.js\`
\`node .knowledge/tools/doctor.js\``;
}

function commonAgentBlock(kitRoot, relPath, title) {
  const fallback = `# ${title}

{{TRUST_ROUTING}}

{{FINAL_REPORT_CONTRACT}}

For concurrent agent work, set a stable \`KNOWLEDGE_AGENT_ID\` and use separate git worktrees/branches.`;
  return renderTemplate(kitRoot, relPath, fallback);
}

function installMarkdownFile(repoRoot, kitRoot, targetRel, templateRel, title, installed, key) {
  const block = commonAgentBlock(kitRoot, templateRel, title);
  installed[key] = upsertManagedBlock(path.join(repoRoot, targetRel), block, { containmentRoot: repoRoot });
}

function splitFrontmatter(text) {
  const normalized = String(text || '').replace(/\r\n/g, '\n');
  if (!normalized.startsWith('---\n')) return { frontmatter: null, body: normalized };
  const end = normalized.indexOf('\n---\n', 4);
  if (end === -1) return { frontmatter: null, body: normalized };
  return {
    frontmatter: normalized.slice(4, end),
    body: normalized.slice(end + 5)
  };
}

function mergeWindsurfFrontmatter(frontmatter) {
  const lines = String(frontmatter || '').split(/\n/).filter((line) => line.trim());
  const kept = lines.filter((line) => !/^\s*trigger\s*:/.test(line));
  return ['trigger: always_on', ...kept].join('\n');
}

function upsertWindsurfRuleFile(repoRoot, filePath, blockBody) {
  assertContainedFileTarget(repoRoot, filePath, { allowMissing: true });
  ensureContainedDir(repoRoot, path.dirname(filePath));
  const managed = `${MANAGED_START}\n${blockBody.trim()}\n${MANAGED_END}\n`;
  if (!fs.existsSync(filePath)) {
    writeFileAtomicContained(filePath, `---\ntrigger: always_on\n---\n\n${managed}`, repoRoot);
    return 'created';
  }
  const current = readContainedText(repoRoot, filePath);
  const parsed = splitFrontmatter(current);
  const replaced = replaceManagedBlocks(parsed.body, managed, htmlManagedBlockRegex());
  const body = replaced.count > 0
    ? replaced.next
    : `${parsed.body.replace(/\s*$/, '')}\n\n${managed}`;
  const frontmatter = mergeWindsurfFrontmatter(parsed.frontmatter);
  writeFileAtomicContained(filePath, `---\n${frontmatter}\n---\n\n${body.replace(/^\s+/, '')}`, repoRoot);
  if (replaced.count > 1) return 'deduplicated';
  return replaced.count === 1 ? 'updated' : 'appended';
}

function pruneEmptyIntegrationParents(repoRoot, filePath, stopDir) {
  let current = path.dirname(filePath);
  const stop = path.resolve(stopDir);
  assertSafeContainedPath(repoRoot, stop, { allowMissing: true });
  while (path.resolve(current).startsWith(`${stop}${path.sep}`) || path.resolve(current) === stop) {
    if (!fs.existsSync(current)) return;
    assertSafeContainedPath(repoRoot, current);
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw integrationSafetyError('UNSAFE_INTEGRATION_PARENT', `Cannot prune unsafe integration directory: ${current}`, current, repoRoot);
    }
    const entries = fs.readdirSync(current);
    if (entries.length) return;
    fs.rmdirSync(current);
    if (path.resolve(current) === stop) return;
    current = path.dirname(current);
  }
}

function migrateLegacyDevinWindsurfFile(context, runtime) {
  const repoRoot = context.targetRoot;
  const relPath = path.join('.devin', 'rules', 'knowledge.md');
  const filePath = path.join(repoRoot, relPath);
  if (!fs.existsSync(filePath)) {
    return { status: 'absent', path: normalizeReleasePath(relPath), runtime, removed_blocks: 0 };
  }
  let current;
  try {
    current = readContainedText(repoRoot, filePath);
  } catch (error) {
    throw integrationSafetyError(
      'LEGACY_DEVIN_WINDSURF_RULE_UNSAFE',
      `Cannot safely inspect legacy Devin/Windsurf rule: ${filePath}: ${error.message}`,
      filePath,
      repoRoot,
      error
    );
  }
  let removed = 0;
  const next = current.replace(htmlManagedBlockRegex(), (block) => {
    const isWindsurf = block.includes('# Windsurf Cascade .knowledge rules') || block.includes('# Windsurf Cascade .knowledge bridge');
    const isDevin = block.includes('# Devin .knowledge rules') || block.includes('# Devin .knowledge bridge');
    if ((runtime === 'windsurf' && isWindsurf) || (runtime === 'devin' && isDevin)) {
      removed += 1;
      return '';
    }
    return block;
  });
  if (!removed) {
    return { status: 'preserved_unrecognized_or_other_runtime', path: normalizeReleasePath(relPath), runtime, removed_blocks: 0 };
  }
  const cleaned = next.replace(/\n{3,}/g, '\n\n').trim();
  if (!cleaned) {
    removeContainedFile(repoRoot, filePath);
    pruneEmptyIntegrationParents(repoRoot, filePath, path.join(repoRoot, '.devin'));
  } else {
    writeFileAtomicContained(filePath, `${cleaned}\n`, repoRoot);
  }
  return {
    status: cleaned ? 'removed_generated_block_preserved_other_content' : 'removed_legacy_generated_file',
    path: normalizeReleasePath(relPath),
    runtime,
    removed_blocks: removed
  };
}

function renderWindsurfRule(context) {
  const fallback = `# Windsurf Cascade .knowledge bridge

Use \`.knowledge/maintenance/routing_bundle.json\` as the first routing artifact for the current task. Follow the repository's shared \`AGENTS.md\` block when it exists; this Windsurf rule is the runtime-specific bridge and must not duplicate or override that shared contract.

Use \`.knowledge/Quick-Start.md\` and \`.knowledge/agent-integrations/_shared/metrics-reporting.md\` for commands and final reporting. Never describe the deterministic local context estimate as provider-reported model-token usage.

For concurrent work, set a stable \`KNOWLEDGE_AGENT_ID\` and use a separate worktree or branch.`;
  const rendered = renderTemplate(context.systemRoot, path.join('windsurf', 'rules', 'knowledge.md'), fallback);
  return splitFrontmatter(rendered).body;
}

function installCurrentWindsurfRule(context, installed) {
  const target = path.join(context.targetRoot, '.windsurf', 'rules', 'knowledge.md');
  installed.windsurf_rules = upsertWindsurfRuleFile(context.targetRoot, target, renderWindsurfRule(context));
  return target;
}

function installSharedAgentsBridge(context, installed) {
  installMarkdownFile(
    context.targetRoot,
    context.systemRoot,
    'AGENTS.md',
    path.join('_shared', 'AGENTS.md'),
    'Shared .knowledge bridge for AGENTS.md-compatible agents',
    installed,
    'agents_md'
  );
}

function removeDeprecatedManagedIntegration(repoRoot, relPath, signatures = []) {
  const filePath = path.join(repoRoot, relPath);
  if (!fs.existsSync(filePath)) return 'absent';
  let text = '';
  try {
    text = readContainedText(repoRoot, filePath);
  } catch (error) {
    if (String(error.code || '').startsWith('UNSAFE_INTEGRATION_')) throw error;
    return 'unreadable';
  }
  if (!signatures.every((signature) => text.includes(signature))) return 'preserved_unrecognized';
  removeContainedFile(repoRoot, filePath);
  return 'removed_deprecated_managed_file';
}

function installCodex(context, installed) {
  const repoRoot = context.targetRoot;
  const kitRoot = context.systemRoot;
  installSharedAgentsBridge(context, installed);
  recordPublicIntegrationCopy(installed, 'codex_skills', copyPublicIntegrationDir(
    kitRoot,
    path.join(kitRoot, 'agent-integrations', 'codex', 'skills'),
    repoRoot,
    path.join(repoRoot, '.agents', 'skills')
  ));
  installed.codex_release_preparation_cleanup = removeDeprecatedManagedIntegration(
    repoRoot,
    path.join('.agents', 'skills', 'release-preparation-workflow.md'),
    ['# Codex Skill: Release Preparation Workflow', 'tools/package-release.js']
  );
}

function installClaude(context, installed) {
  const repoRoot = context.targetRoot;
  const kitRoot = context.systemRoot;
  const fallback = `# Claude Code .knowledge notes

{{TRUST_ROUTING}}

Prefer installed skills under \`.claude/skills/\` for audit, routing bundle refresh, search index, doctor checks, sync, handoff, ingest, concurrent-agent checks, metrics collection, and PR summary generation.

Do not omit routing or metrics outcomes from the final reply. If \`.knowledge/metrics/baseline.json\` is missing or stale, say so explicitly instead of silently skipping routing-context estimate reporting.

{{FINAL_REPORT_CONTRACT}}

For concurrent agent work, set a stable \`KNOWLEDGE_AGENT_ID\` and use separate git worktrees/branches.`;
  const block = renderTemplate(kitRoot, path.join('claude', 'CLAUDE.md'), fallback);
  installed.claude_md = upsertManagedBlock(path.join(repoRoot, 'CLAUDE.md'), block, { containmentRoot: repoRoot });
  recordPublicIntegrationCopy(installed, 'claude_skills', copyPublicIntegrationDir(
    kitRoot,
    path.join(kitRoot, 'agent-integrations', 'claude', 'skills'),
    repoRoot,
    path.join(repoRoot, '.claude', 'skills')
  ));
}

function installOpenCode(context, installed) {
  recordPublicIntegrationCopy(installed, 'opencode_commands', copyPublicIntegrationDir(
    context.systemRoot,
    path.join(context.systemRoot, 'agent-integrations', 'opencode', 'commands'),
    context.targetRoot,
    path.join(context.targetRoot, '.opencode', 'commands')
  ));
}

function installOpenClaw(context, installed) {
  const repoRoot = context.targetRoot;
  const kitRoot = context.systemRoot;
  installSharedAgentsBridge(context, installed);
  recordPublicIntegrationCopy(installed, 'openclaw_skills', copyPublicIntegrationDir(
    kitRoot,
    path.join(kitRoot, 'agent-integrations', 'codex', 'skills'),
    repoRoot,
    path.join(repoRoot, '.agents', 'skills')
  ));
}

function installHermes(context, installed) {
  installSharedAgentsBridge(context, installed);
}

function installGemini(context, installed) {
  installMarkdownFile(context.targetRoot, context.systemRoot, 'GEMINI.md', path.join('gemini', 'GEMINI.md'), 'Gemini CLI .knowledge notes', installed, 'gemini_md');
}

function installCopilot(context, installed) {
  installMarkdownFile(
    context.targetRoot,
    context.systemRoot,
    path.join('.github', 'copilot-instructions.md'),
    path.join('copilot', 'copilot-instructions.md'),
    'GitHub Copilot .knowledge instructions',
    installed,
    'copilot_instructions'
  );
}

function installRuleFile(context, installed, runtime, targetRel, templateRel, title, key) {
  installMarkdownFile(context.targetRoot, context.systemRoot, targetRel, templateRel, title, installed, key || `${runtime}_rules`);
}

function renderDevinRule(context) {
  const fallback = `# Devin .knowledge bridge

Use the repository-root AGENTS.md as the primary .knowledge instruction contract. This separate Devin rule is only a concise vendor-specific discovery bridge; it must not duplicate or override the shared managed block.

Start with .knowledge/maintenance/routing_bundle.json, then follow .knowledge/Quick-Start.md and .knowledge/agent-integrations/_shared/metrics-reporting.md. Never describe the deterministic local context estimate as provider-reported model-token usage.

For concurrent work, set a stable KNOWLEDGE_AGENT_ID and use a separate worktree or branch.`;
  return renderTemplate(context.systemRoot, path.join('devin', 'rules', 'knowledge.rules'), fallback);
}

function installCurrentDevinRule(context, installed) {
  const target = path.join(context.targetRoot, '.devin', 'rules', 'knowledge.rules');
  installed.devin_rules = upsertManagedBlock(target, renderDevinRule(context), { containmentRoot: context.targetRoot });
  installed.devin_vendor_contract = 'specialized_rules_bridge';
  installed.devin_primary_contract = 'AGENTS.md';
  return target;
}

function installDevin(context, installed) {
  installed.legacy_devin_rule = migrateLegacyDevinWindsurfFile(context, 'devin');
  installSharedAgentsBridge(context, installed);
  installCurrentDevinRule(context, installed);
}

function installWindsurf(context, installed) {
  installed.legacy_windsurf_rule = migrateLegacyDevinWindsurfFile(context, 'windsurf');
  installCurrentWindsurfRule(context, installed);
}

function installAider(context, installed) {
  installMarkdownFile(
    context.targetRoot,
    context.systemRoot,
    'CONVENTIONS.md',
    path.join('aider', 'CONVENTIONS.md'),
    'Aider .knowledge conventions',
    installed,
    'conventions_md'
  );
  const configPath = path.join(context.targetRoot, '.aider.conf.yml');
  assertContainedFileTarget(context.targetRoot, configPath, { allowMissing: true });
  if (fs.existsSync(configPath) && readContainedText(context.targetRoot, configPath).includes('CONVENTIONS.md')) {
    installed.aider_config = 'unchanged';
  } else {
    installed.aider_config = upsertHashManagedBlock(
      configPath,
      `read:
  - CONVENTIONS.md`,
      { containmentRoot: context.targetRoot }
    );
  }
}

const INTEGRATIONS = {
  codex: {
    label: 'Codex',
    paths: ['AGENTS.md', '.agents/skills/**'],
    install: installCodex
  },
  claude: {
    label: 'Claude Code',
    paths: ['CLAUDE.md', '.claude/skills/**'],
    install: installClaude
  },
  opencode: {
    label: 'OpenCode',
    paths: ['.opencode/commands/**'],
    install: installOpenCode
  },
  openclaw: {
    label: 'OpenClaw',
    paths: ['AGENTS.md', '.agents/skills/**'],
    install: installOpenClaw
  },
  hermes: {
    label: 'Hermes',
    paths: ['AGENTS.md'],
    install: installHermes
  },
  gemini: {
    label: 'Gemini CLI',
    paths: ['GEMINI.md'],
    install: installGemini
  },
  copilot: {
    label: 'GitHub Copilot',
    paths: ['.github/copilot-instructions.md'],
    install: installCopilot
  },
  devin: {
    label: 'Devin',
    paths: ['AGENTS.md', '.devin/rules/knowledge.rules'],
    install: installDevin
  },
  windsurf: {
    label: 'Windsurf Cascade',
    paths: ['.windsurf/rules/knowledge.md'],
    install: installWindsurf
  },
  continue: {
    label: 'Continue',
    paths: ['.continue/rules/knowledge.md'],
    install: (context, installed) => installRuleFile(context, installed, 'continue', path.join('.continue', 'rules', 'knowledge.md'), path.join('continue', 'rules', 'knowledge.md'), 'Continue .knowledge rules')
  },
  roo: {
    label: 'Roo Code',
    paths: ['.roo/rules/knowledge.md'],
    install: (context, installed) => installRuleFile(context, installed, 'roo', path.join('.roo', 'rules', 'knowledge.md'), path.join('roo', 'rules', 'knowledge.md'), 'Roo Code .knowledge rules')
  },
  aider: {
    label: 'Aider',
    paths: ['CONVENTIONS.md', '.aider.conf.yml'],
    install: installAider
  }
};

function allPotentialIntegrationTargetRelPaths() {
  return [
    'AGENTS.md',
    'CLAUDE.md',
    'GEMINI.md',
    'CONVENTIONS.md',
    '.aider.conf.yml',
    '.gitattributes',
    'package.json',
    '.agents',
    '.agents/skills',
    '.claude',
    '.claude/skills',
    '.opencode',
    '.opencode/commands',
    '.github',
    '.devin',
    '.devin/rules',
    '.windsurf',
    '.windsurf/rules',
    '.continue',
    '.continue/rules',
    '.roo',
    '.roo/rules',
    '.agents/skills/release-preparation-workflow.md',
    '.github/copilot-instructions.md',
    '.devin/rules/knowledge.md',
    '.devin/rules/knowledge.rules',
    '.windsurf/rules/knowledge.md',
    '.continue/rules/knowledge.md',
    '.roo/rules/knowledge.md'
  ];
}

function addPlanTarget(plan, repoRoot, relPath, operation = 'write', runtime = null) {
  const normalized = normalizeReleasePath(relPath);
  const key = `${operation}:${normalized}`;
  if (!plan._targetKeys.has(key)) {
    plan._targetKeys.add(key);
    plan.targets.push({
      path: path.join(repoRoot, ...normalized.split('/')),
      rel_path: normalized,
      operation,
      runtime
    });
  }
}

function addPlanSource(plan, systemRoot, relPath, runtime = null) {
  const normalized = normalizeReleasePath(relPath);
  if (plan._sourceKeys.has(normalized)) return;
  plan._sourceKeys.add(normalized);
  plan.sources.push({
    path: path.join(systemRoot, ...normalized.split('/')),
    rel_path: normalized,
    runtime
  });
}

function addTemplatePlan(plan, context, targetRel, templateRel, runtime) {
  addPlanTarget(plan, context.targetRoot, targetRel, 'write', runtime);
  addPlanSource(plan, context.systemRoot, path.join('agent-integrations', templateRel), runtime);
  addPlanSource(plan, context.systemRoot, path.join('agent-integrations', '_shared', 'trust-routing.md'), runtime);
  addPlanSource(plan, context.systemRoot, path.join('agent-integrations', '_shared', 'final-report-contract.md'), runtime);
}

function addCopyTreePlan(plan, context, srcRelDir, targetRelDir, runtime) {
  const srcDir = path.join(context.systemRoot, ...normalizeReleasePath(srcRelDir).split('/'));
  const dstDir = path.join(context.targetRoot, ...normalizeReleasePath(targetRelDir).split('/'));
  const copies = collectCopyEntries(
    context.systemRoot,
    srcDir,
    dstDir,
    publicIntegrationAllowlist(context.systemRoot)
  );
  for (const item of copies.entries) {
    addPlanSource(plan, context.systemRoot, item.source_rel, runtime);
    addPlanTarget(plan, context.targetRoot, normalizeReleasePath(path.relative(context.targetRoot, item.target)), 'write', runtime);
  }
}

function buildIntegrationWritePlan(context, runtimes, options = {}) {
  const plan = {
    schema_version: 'knowledge-integration-write-plan.v1',
    repo_root: context.targetRoot,
    system_root: context.systemRoot,
    runtimes: [...runtimes],
    targets: [],
    sources: [],
    _targetKeys: new Set(),
    _sourceKeys: new Set()
  };
  addPlanSource(plan, context.systemRoot, 'install-manifest.json', 'system');
  for (const runtime of runtimes) {
    switch (runtime) {
      case 'codex':
        addTemplatePlan(plan, context, 'AGENTS.md', path.join('_shared', 'AGENTS.md'), runtime);
        addCopyTreePlan(plan, context, 'agent-integrations/codex/skills', '.agents/skills', runtime);
        addPlanTarget(plan, context.targetRoot, '.agents/skills/release-preparation-workflow.md', 'inspect_or_remove', runtime);
        break;
      case 'claude':
        addTemplatePlan(plan, context, 'CLAUDE.md', path.join('claude', 'CLAUDE.md'), runtime);
        addCopyTreePlan(plan, context, 'agent-integrations/claude/skills', '.claude/skills', runtime);
        break;
      case 'opencode':
        addCopyTreePlan(plan, context, 'agent-integrations/opencode/commands', '.opencode/commands', runtime);
        break;
      case 'openclaw':
        addTemplatePlan(plan, context, 'AGENTS.md', path.join('_shared', 'AGENTS.md'), runtime);
        addCopyTreePlan(plan, context, 'agent-integrations/codex/skills', '.agents/skills', runtime);
        break;
      case 'hermes':
        addTemplatePlan(plan, context, 'AGENTS.md', path.join('_shared', 'AGENTS.md'), runtime);
        break;
      case 'gemini':
        addTemplatePlan(plan, context, 'GEMINI.md', path.join('gemini', 'GEMINI.md'), runtime);
        break;
      case 'copilot':
        addTemplatePlan(plan, context, '.github/copilot-instructions.md', path.join('copilot', 'copilot-instructions.md'), runtime);
        break;
      case 'devin':
        addTemplatePlan(plan, context, 'AGENTS.md', path.join('_shared', 'AGENTS.md'), runtime);
        addTemplatePlan(plan, context, '.devin/rules/knowledge.rules', path.join('devin', 'rules', 'knowledge.rules'), runtime);
        addPlanTarget(plan, context.targetRoot, '.devin/rules/knowledge.md', 'inspect_or_remove', runtime);
        break;
      case 'windsurf':
        addTemplatePlan(plan, context, '.windsurf/rules/knowledge.md', path.join('windsurf', 'rules', 'knowledge.md'), runtime);
        addPlanTarget(plan, context.targetRoot, '.devin/rules/knowledge.md', 'inspect_or_remove', runtime);
        break;
      case 'continue':
        addTemplatePlan(plan, context, '.continue/rules/knowledge.md', path.join('continue', 'rules', 'knowledge.md'), runtime);
        break;
      case 'roo':
        addTemplatePlan(plan, context, '.roo/rules/knowledge.md', path.join('roo', 'rules', 'knowledge.md'), runtime);
        break;
      case 'aider':
        addTemplatePlan(plan, context, 'CONVENTIONS.md', path.join('aider', 'CONVENTIONS.md'), runtime);
        addPlanTarget(plan, context.targetRoot, '.aider.conf.yml', 'write', runtime);
        break;
      default:
        break;
    }
  }
  if (options.updatePackageScripts !== false) {
    addPlanTarget(plan, context.targetRoot, 'package.json', 'write_if_present', 'system');
  }
  addPlanTarget(plan, context.targetRoot, '.gitattributes', 'write', 'system');
  delete plan._targetKeys;
  delete plan._sourceKeys;
  return plan;
}

function classifyPreflightViolation(error, item) {
  const message = String(error?.message || error);
  let code = [
    'integration_target_hardlinked',
    'integration_package_invalid',
    'integration_managed_block_invalid'
  ].includes(error?.code) ? error.code : 'unsafe_integration_target';
  if (/escapes containment root|outside/i.test(message)) code = 'integration_target_outside_repo';
  else if (/symlink|junction|reparse/i.test(message)) {
    code = item.operation === 'source' ? 'unsafe_integration_source' : 'integration_target_symlink';
  } else if (/parent is not a directory|directory.*file/i.test(message)) {
    code = 'unsafe_integration_parent';
  }
  return {
    code,
    path: item.rel_path,
    operation: item.operation,
    runtime: item.runtime || null,
    message,
    os_code: error?.code || null
  };
}

function preflightIntegrationWritePlan(plan) {
  const violations = [];
  assertSafeContainmentRoot(plan.repo_root);
  assertSafeContainmentRoot(plan.system_root);
  for (const source of plan.sources) {
    try {
      assertContainedSourceFile(plan.system_root, source.path);
    } catch (error) {
      violations.push(classifyPreflightViolation(error, { ...source, operation: 'source' }));
    }
  }
  for (const target of plan.targets) {
    try {
      assertContainedFileTarget(plan.repo_root, target.path, { allowMissing: true });
      if (fs.existsSync(target.path)) {
        const stat = fs.lstatSync(target.path);
        if (!stat.isFile() || stat.isSymbolicLink()) {
          const error = new Error('Integration target must be a physical regular file.');
          error.code = 'unsafe_integration_target';
          throw error;
        }
        if (Number(stat.nlink) !== 1) {
          const error = new Error('Integration target has more than one physical link.');
          error.code = 'integration_target_hardlinked';
          throw error;
        }
        const body = fs.readFileSync(target.path, 'utf8');
        if (target.rel_path === 'package.json') {
          let pkg;
          try { pkg = JSON.parse(body.replace(/^\uFEFF/, '')); }
          catch {
            const error = new Error('Existing package.json is malformed.');
            error.code = 'integration_package_invalid';
            throw error;
          }
          if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg) ||
              (pkg.scripts !== undefined && (!pkg.scripts || typeof pkg.scripts !== 'object' || Array.isArray(pkg.scripts)))) {
            const error = new Error('Existing package.json has an unsupported schema.');
            error.code = 'integration_package_invalid';
            throw error;
          }
        }
        const htmlStarts = (body.match(new RegExp(`<!-- BEGIN (?:DOT-KNOWLEDGE|${LEGACY_MANAGED_MARKER}) MANAGED BLOCK -->`, 'g')) || []).length;
        const htmlEnds = (body.match(new RegExp(`<!-- END (?:DOT-KNOWLEDGE|${LEGACY_MANAGED_MARKER}) MANAGED BLOCK -->`, 'g')) || []).length;
        const hashStarts = (body.match(/^# BEGIN DOT-KNOWLEDGE MANAGED BLOCK$/gm) || []).length;
        const hashEnds = (body.match(/^# END DOT-KNOWLEDGE MANAGED BLOCK$/gm) || []).length;
        if (htmlStarts !== htmlEnds || hashStarts !== hashEnds) {
          const error = new Error('Existing integration target has an unbalanced managed block.');
          error.code = 'integration_managed_block_invalid';
          throw error;
        }
      }
    } catch (error) {
      violations.push(classifyPreflightViolation(error, target));
    }
  }
  if (violations.length) {
    const error = new Error(`Integration preflight rejected ${violations.length} unsafe path(s).`);
    error.code = 'INTEGRATION_PREFLIGHT_FAILED';
    error.violations = violations;
    error.plan = {
      schema_version: plan.schema_version,
      runtimes: plan.runtimes,
      targets_total: plan.targets.length,
      sources_total: plan.sources.length
    };
    throw error;
  }
  return {
    status: 'pass',
    schema_version: plan.schema_version,
    runtimes: plan.runtimes,
    targets_total: plan.targets.length,
    sources_total: plan.sources.length,
    targets: plan.targets.map((item) => ({ rel_path: item.rel_path, operation: item.operation, runtime: item.runtime })),
    sources: plan.sources.map((item) => ({ rel_path: item.rel_path, runtime: item.runtime }))
  };
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function snapshotIntegrationTarget(repoRoot, target) {
  const absolute = path.join(repoRoot, ...target.rel_path.split('/'));
  if (!fs.existsSync(absolute)) return { exists: false, body: null, sha256: null, identity: null };
  assertContainedFileTarget(repoRoot, absolute);
  const stat = fs.lstatSync(absolute, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) {
    const error = new Error(`Integration target is not a physical file: ${target.rel_path}`);
    error.code = 'unsafe_integration_target';
    throw error;
  }
  if (stat.nlink !== 1n) {
    const error = new Error(`Integration target is hardlinked: ${target.rel_path}`);
    error.code = 'integration_target_hardlinked';
    throw error;
  }
  const body = fs.readFileSync(absolute);
  const after = fs.lstatSync(absolute, { bigint: true });
  if (String(stat.dev) !== String(after.dev) || String(stat.ino) !== String(after.ino) ||
      String(stat.size) !== String(after.size) || after.nlink !== 1n) {
    const error = new Error(`Integration target changed while being staged: ${target.rel_path}`);
    error.code = 'integration_target_changed';
    throw error;
  }
  return {
    exists: true,
    body,
    sha256: sha256Buffer(body),
    identity: {
      dev: String(after.dev),
      ino: String(after.ino),
      size: String(after.size),
      mtime_ns: String(after.mtimeNs),
      nlink: String(after.nlink)
    }
  };
}

function assertTargetSnapshotUnchanged(repoRoot, target, snapshot) {
  const absolute = path.join(repoRoot, ...target.rel_path.split('/'));
  if (!snapshot.exists) {
    if (fs.existsSync(absolute)) {
      const error = new Error(`Integration target appeared after preflight: ${target.rel_path}`);
      error.code = 'integration_target_changed';
      throw error;
    }
    return;
  }
  const current = snapshotIntegrationTarget(repoRoot, target);
  if (!current.exists || current.sha256 !== snapshot.sha256 ||
      current.identity.dev !== snapshot.identity.dev || current.identity.ino !== snapshot.identity.ino ||
      current.identity.nlink !== '1') {
    const error = new Error(`Integration target changed after preflight: ${target.rel_path}`);
    error.code = 'integration_target_changed';
    throw error;
  }
}

function persistIntegrationTransaction(stateRoot, transaction) {
  const root = ensureContainedDir(stateRoot, path.join(stateRoot, 'maintenance', 'integration-transactions'));
  const filePath = path.join(root, `${transaction.transaction_id}.json`);
  writeJsonAtomicContained(filePath, transaction, stateRoot);
  return filePath;
}

function cleanTransactionStage(stageRoot) {
  if (!fs.existsSync(stageRoot)) return;
  removeTempDirStrict(stageRoot, {
    label: 'integration transaction staging directory',
    retryCodes: ['EBUSY', 'EPERM', 'ENOTEMPTY', 'EACCES']
  });
}

function stageIntegrationInstall(context, requested, options, plan, preflight) {
  const transactionId = crypto.randomUUID();
  const transactionBase = ensureContainedDir(
    context.stateRoot,
    path.join(context.stateRoot, 'maintenance', 'integration-transactions', '.staging')
  );
  const stageRoot = path.join(transactionBase, transactionId);
  ensureContainedDir(context.stateRoot, stageRoot);
  const snapshots = new Map();
  const uniqueTargets = [];
  const seen = new Set();
  for (const target of plan.targets) {
    if (seen.has(target.rel_path)) continue;
    seen.add(target.rel_path);
    uniqueTargets.push(target);
  }
  const transaction = {
    schema_version: 'knowledge-integration-transaction.v1',
    transaction_id: transactionId,
    created_at: new Date().toISOString(),
    status: 'staging',
    runtimes: requested.runtimes,
    targets_total: uniqueTargets.length,
    files_created: [],
    files_modified: [],
    files_deleted: [],
    rollback: null,
    preflight: {
      status: preflight.status,
      targets_total: preflight.targets_total,
      sources_total: preflight.sources_total
    }
  };

  try {
    if (options.transactionFault === 'staging') {
      const error = new Error('Injected integration staging failure.');
      error.code = 'integration_staging_failed';
      throw error;
    }
    for (const target of uniqueTargets) {
      const snapshot = snapshotIntegrationTarget(context.targetRoot, target);
      snapshots.set(target.rel_path, snapshot);
      if (!snapshot.exists) continue;
      const stagedPath = path.join(stageRoot, ...target.rel_path.split('/'));
      writeFileAtomicContained(stagedPath, snapshot.body, stageRoot);
    }

    const stageContext = { ...context, targetRoot: stageRoot };
    const installed = {
      status: 'ok',
      mode: requested.all ? 'all' : 'runtime',
      runtimes: requested.runtimes,
      source: requested.source,
      installed: {},
      preflight
    };
    const attributePaths = [];
    for (const runtime of requested.runtimes) {
      const integration = INTEGRATIONS[runtime];
      if (!integration) continue;
      const runtimeInstalled = {};
      integration.install(stageContext, runtimeInstalled);
      installed.installed[runtime] = runtimeInstalled;
      attributePaths.push(...integration.paths);
    }
    if (options.updatePackageScripts !== false) {
      installed.package_json = updatePackageJson(stageRoot);
      if (installed.package_json.status !== 'not_found') attributePaths.push('package.json');
    }
    installed.gitattributes = upsertGitAttributes(stageRoot, attributePaths);

    const changes = [];
    for (const target of uniqueTargets) {
      const prior = snapshots.get(target.rel_path);
      const stagedPath = path.join(stageRoot, ...target.rel_path.split('/'));
      const stagedExists = fs.existsSync(stagedPath);
      const stagedBody = stagedExists ? fs.readFileSync(stagedPath) : null;
      if (!prior.exists && !stagedExists) continue;
      if (prior.exists && stagedExists && prior.body.equals(stagedBody)) continue;
      changes.push({ target, prior, stagedExists, stagedBody });
      if (!prior.exists && stagedExists) transaction.files_created.push(target.rel_path);
      else if (prior.exists && stagedExists) transaction.files_modified.push(target.rel_path);
      else transaction.files_deleted.push(target.rel_path);
    }

    for (const target of uniqueTargets) {
      assertTargetSnapshotUnchanged(context.targetRoot, target, snapshots.get(target.rel_path));
    }
    transaction.status = 'committing';
    transaction.changes_total = changes.length;
    persistIntegrationTransaction(context.stateRoot, transaction);

    const committed = [];
    try {
      for (let index = 0; index < changes.length; index += 1) {
        const change = changes[index];
        const failAt = options.transactionFault === 'commit:first' ? 0
          : (options.transactionFault === 'commit:middle' || options.transactionFault === 'commit:middle+rollback'
            ? Math.max(1, Math.floor(changes.length / 2)) : -1);
        if (index === failAt) {
          const error = new Error(`Injected integration commit failure at index ${index}.`);
          error.code = 'integration_commit_failed';
          throw error;
        }
        assertTargetSnapshotUnchanged(context.targetRoot, change.target, change.prior);
        const livePath = path.join(context.targetRoot, ...change.target.rel_path.split('/'));
        if (change.stagedExists) writeFileAtomicContained(livePath, change.stagedBody, context.targetRoot);
        else removeContainedFile(context.targetRoot, livePath);
        committed.push(change);
      }
    } catch (commitError) {
      const rollback = { status: 'running', restored: [], failed: [] };
      let rollbackFaultInjected = false;
      for (const change of committed.slice().reverse()) {
        try {
          if (options.transactionFault === 'commit:middle+rollback' && !rollbackFaultInjected) {
            rollbackFaultInjected = true;
            const error = new Error('Injected integration rollback failure.');
            error.code = 'integration_rollback_failed';
            throw error;
          }
          const livePath = path.join(context.targetRoot, ...change.target.rel_path.split('/'));
          if (change.prior.exists) writeFileAtomicContained(livePath, change.prior.body, context.targetRoot);
          else {
            removeContainedFile(context.targetRoot, livePath);
            pruneEmptyContainedParents(context.targetRoot, livePath);
          }
          rollback.restored.push(change.target.rel_path);
        } catch (rollbackError) {
          rollback.failed.push({ rel_path: change.target.rel_path, code: rollbackError.code || 'integration_rollback_failed' });
        }
      }
      rollback.status = rollback.failed.length ? 'rollback_failed' : 'rolled_back';
      transaction.status = rollback.status;
      transaction.rollback = rollback;
      transaction.error = { code: commitError.code || 'integration_commit_failed', message: commitError.message };
      transaction.completed_at = new Date().toISOString();
      persistIntegrationTransaction(context.stateRoot, transaction);
      const error = new Error(rollback.failed.length
        ? 'Integration commit failed and rollback was incomplete.'
        : 'Integration commit failed; all committed targets were rolled back.');
      error.code = rollback.failed.length ? 'INTEGRATION_ROLLBACK_FAILED' : 'INTEGRATION_COMMIT_ROLLED_BACK';
      error.transaction = transaction;
      throw error;
    }

    transaction.status = 'committed';
    transaction.completed_at = new Date().toISOString();
    transaction.rollback = { status: 'not_required', restored: [], failed: [] };
    persistIntegrationTransaction(context.stateRoot, transaction);
    installed.transaction = transaction;
    return installed;
  } catch (error) {
    if (!error.transaction) {
      transaction.status = transaction.status === 'staging' ? 'staging_failed' : transaction.status;
      transaction.error = { code: error.code || 'integration_transaction_failed', message: error.message };
      transaction.completed_at = new Date().toISOString();
      try { persistIntegrationTransaction(context.stateRoot, transaction); } catch {}
      error.transaction = transaction;
    }
    throw error;
  } finally {
    cleanTransactionStage(stageRoot);
  }
}

function detectRuntimeFromEnv(env = process.env) {
  const explicit = normalizeRuntime(env.KNOWLEDGE_AGENT_RUNTIME || env.KNOWLEDGE_RUNTIME);
  if (explicit) return { runtime: explicit, source: 'env:KNOWLEDGE_AGENT_RUNTIME' };
  const hints = [
    ['codex', ['CODEX_HOME', 'CODEX_SANDBOX', 'CODEX_CLI_SANDBOX', 'CODEX_ENV_PWD']],
    ['claude', ['CLAUDECODE', 'CLAUDE_CODE', 'ANTHROPIC_CLAUDE_CODE']],
    ['opencode', ['OPENCODE', 'OPENCODE_APP']],
    ['openclaw', ['OPENCLAW_HOME', 'OPENCLAW_WORKSPACE']],
    ['hermes', ['HERMES_HOME', 'HERMES_AGENT']],
    ['gemini', ['GEMINI_CLI', 'GEMINI_API_KEY']],
    ['copilot', ['GITHUB_COPILOT_AGENT', 'COPILOT_AGENT']],
    ['continue', ['CONTINUE_GLOBAL_DIR']],
    ['aider', ['AIDER_MODEL', 'AIDER_ANALYTICS']]
  ];
  for (const [runtime, names] of hints) {
    if (names.some((name) => env[name])) return { runtime, source: `env:${names.find((name) => env[name])}` };
  }
  return null;
}

function resolveRequestedRuntime(options = {}) {
  if (options.all && !options.confirmAll) {
    return {
      all: false,
      runtimes: [],
      source: 'flag:--all',
      allRequiresConfirmation: true
    };
  }
  if (options.all) return { all: true, runtimes: supportedRuntimeIds(), source: 'flag:--all --confirm-all' };
  const requested = normalizeRuntime(options.runtime);
  if (requested) return { all: false, runtimes: [requested], source: 'flag:--runtime' };
  if (options.runtime) return { all: false, runtimes: [], unknown: String(options.runtime), source: 'flag:--runtime' };
  const detected = detectRuntimeFromEnv();
  if (detected?.runtime) return { all: false, runtimes: [detected.runtime], source: detected.source };
  return { all: false, runtimes: [], source: 'none' };
}

function runtimeRequired(reason = 'No supported agent runtime was detected.') {
  return {
    status: 'runtime_required',
    reason,
    supported_runtimes: supportedRuntimeIds(),
    commands: runtimeCommands(),
    note: 'Install only the active agent runtime during first setup. Other agents can add their own runtime later.'
  };
}

function allRequiresConfirmation() {
  return {
    status: 'all_requires_confirmation',
    reason: '`--all` installs every supported agent bridge and is not a first-run default.',
    recommendation: 'Use one --runtime command for the active agent. Only use --all with --confirm-all when a human explicitly wants every integration folder.',
    supported_runtimes: supportedRuntimeIds(),
    commands: runtimeCommands(),
    all_command: 'node .knowledge/tools/install-agent-integrations.js --all --confirm-all'
  };
}

function installAgentIntegrations(options = {}) {
  const context = resolveKnowledgeContext(options);
  const repoRoot = context.targetRoot;
  const requested = resolveRequestedRuntime(options);

  if (requested.allRequiresConfirmation) {
    return {
      ...allRequiresConfirmation(),
      repo_root: repoRoot,
      knowledge_root: context.systemRoot
    };
  }

  if (!requested.runtimes.length) {
    const reason = requested.unknown
      ? `Unknown agent runtime: ${requested.unknown}.`
      : 'No supported agent runtime was detected.';
    return {
      ...runtimeRequired(reason),
      repo_root: repoRoot,
      knowledge_root: context.systemRoot
    };
  }

  const writePlan = buildIntegrationWritePlan(context, requested.runtimes, options);
  const preflight = preflightIntegrationWritePlan(writePlan);
  const installed = withContainedLock({
    context,
    rootKind: 'state',
    rootPath: context.stateRoot,
    lockName: 'agent-integrations',
    purpose: LOCKS['agent-integrations'].purpose,
    // Multiple agent CLIs may initialize a repository concurrently. The
    // transaction must serialize rather than inherit an ambient short lock
    // timeout that can expire while an earlier integration is still copying.
    timeoutMs: INTEGRATION_TRANSACTION_LOCK_TIMEOUT_MS
  }, () => {
    const lockedPreflight = preflightIntegrationWritePlan(writePlan);
    return stageIntegrationInstall(context, requested, options, writePlan, lockedPreflight);
  });

  const installCheckScript = path.join(context.systemRoot, 'tools', 'install-check.js');
  if (fs.existsSync(installCheckScript) && options.runInstallCheck !== false) {
    const res = spawnSync(process.execPath, [installCheckScript, '--json'], { cwd: repoRoot, encoding: 'utf8', env: contextEnv(context), windowsHide: true });
    installed.install_check = {
      command: 'node .knowledge/tools/install-check.js --json',
      exit: res.status,
      status: null
    };
    try {
      installed.install_check.result = JSON.parse((res.stdout || '').trim() || '{}');
      installed.install_check.status = installed.install_check.result.status || null;
    } catch {
      installed.install_check.stdout = (res.stdout || '').trim().slice(0, 4000);
    }
    if (res.stderr) installed.install_check.stderr = res.stderr.trim().slice(0, 2000);
  } else {
    installed.install_check = { recommendation: 'Run node .knowledge/tools/install-check.js --json' };
  }
  return installed;
}

module.exports = installAgentIntegrations;
module.exports.INTEGRATIONS = INTEGRATIONS;
module.exports.supportedRuntimeIds = supportedRuntimeIds;
module.exports.allPotentialIntegrationTargetRelPaths = allPotentialIntegrationTargetRelPaths;
module.exports.buildIntegrationWritePlan = buildIntegrationWritePlan;
module.exports.preflightIntegrationWritePlan = preflightIntegrationWritePlan;
module.exports.stageIntegrationInstall = stageIntegrationInstall;

if (require.main === module) {
  try {
    const parsed = parseCliArgs(process.argv.slice(2)).flags;
    const options = {
      runtime: parsed.runtime,
      all: parsed.all === true,
      confirmAll: parsed.confirmAll === true,
      updatePackageScripts: !process.argv.includes('--no-package-scripts'),
      runInstallCheck: !process.argv.includes('--no-install-check')
    };
    if (parsed.listRuntimes) {
      console.log(JSON.stringify({ status: 'ok', supported_runtimes: supportedRuntimeIds(), commands: runtimeCommands() }, null, 2));
    } else {
      console.log(JSON.stringify(installAgentIntegrations(options), null, 2));
    }
  } catch (error) {
    const failure = {
      status: 'failed',
      code: error.code || 'INTEGRATION_INSTALL_FAILED',
      message: error.message,
      violations: Array.isArray(error.violations) ? error.violations : undefined,
      plan: error.plan || undefined,
      transaction: error.transaction || undefined
    };
    console.error(JSON.stringify(failure, null, 2));
    process.exit(1);
  }
}
