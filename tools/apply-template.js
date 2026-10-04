#!/usr/bin/env node
'use strict';

// template pages, registers them in wiki/index.md via a managed block,
// stamps verified_against: ["template:<id>:<version>"] on every page,
// and supports --remove / --dry-run / --diff for clean rollback.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { readJson, writeJsonAtomicContained, writeFileAtomicContained, assertSafeContainedPath, getAgentId } = require('./lib/json-store');
const { assertSafePathSegment } = require('./lib/path-segment');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { systemVersion } = require('./lib/system-version');

const knowledgeRoot = path.resolve(__dirname, '..');
const templatesRoot = path.join(knowledgeRoot, 'templates', 'official');
const wikiRoot = path.join(knowledgeRoot, 'wiki');
const TEMPLATE_LOCK = Object.freeze({
  context: { projectKnowledgeRoot: knowledgeRoot },
  rootKind: 'project',
  rootPath: knowledgeRoot,
  lockName: 'apply-template',
  purpose: LOCKS['apply-template'].purpose
});

function nowIso() { return new Date().toISOString(); }
function contentHash(text) { return crypto.createHash('sha256').update(text).digest('hex'); }
function readMetadata(file, fallback) { return fs.existsSync(file) ? readJson(file) : fallback; }

function safeKnowledgeFile(relative) {
  const file = path.join(knowledgeRoot, relative);
  assertSafeContainedPath(knowledgeRoot, file, { allowMissing: true });
  return file;
}

function safeWikiFile(relative) {
  if (typeof relative !== 'string' || !relative.startsWith('wiki/') ||
      !relative.endsWith('.md') || relative.includes('\\') ||
      relative.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new Error('Template pages must be canonical wiki/*.md paths inside .knowledge/wiki');
  }
  for (const segment of relative.split('/')) assertSafePathSegment(segment, 'template page segment');
  if (relative === 'wiki/index.md') throw new Error('Templates cannot own the managed wiki/index.md');
  return safeKnowledgeFile(relative);
}

function metadataPaths() {
  return {
    index: safeKnowledgeFile('wiki/index.md'),
    repair: safeKnowledgeFile('maintenance/repair_queue.json'),
    applied: safeKnowledgeFile('maintenance/applied_templates.json'),
    project: safeKnowledgeFile('project_index.json')
  };
}

function listTemplates() {
  if (!fs.existsSync(templatesRoot)) return [];
  assertSafeContainedPath(knowledgeRoot, templatesRoot);
  return fs.readdirSync(templatesRoot, { withFileTypes: true }).filter(e => e.isDirectory()).map(e => {
    const data = readTemplate(e.name);
    return { id: data.id || e.name, name: data.name || e.name, description: data.description || '', version: data.schema_version || '1' };
  });
}

function readTemplate(id) {
  assertSafePathSegment(id, 'template id');
  const file = path.join(templatesRoot, id, 'template.json');
  assertSafeContainedPath(knowledgeRoot, file, { allowMissing: true });
  if (!fs.existsSync(file)) throw new Error(`Unknown official template: ${id}. Run --list.`);
  const tpl = readJson(file);
  if (!tpl || typeof tpl !== 'object' || Array.isArray(tpl) || tpl.id !== id ||
      !tpl.wiki_pages || typeof tpl.wiki_pages !== 'object' || Array.isArray(tpl.wiki_pages) ||
      (tpl.critical_paths !== undefined && !Array.isArray(tpl.critical_paths))) {
    throw new Error(`Invalid official template manifest: ${id}`);
  }
  for (const [relative, body] of Object.entries(tpl.wiki_pages)) {
    safeWikiFile(relative);
    if (typeof body !== 'string') throw new Error('Template page body must be a string');
  }
  return tpl;
}

function rel(absUnderKnowledge) {
  return path.relative(knowledgeRoot, absUnderKnowledge).replace(/\\/g, '/');
}

// Architecture pages support runbooks; runbooks depend_on architecture;
// concepts pages are related to both. This eliminates orphan warnings.
function inferTypedLinks(allPagePaths) {
  // allPagePaths are wiki-relative ("architecture/x.md", "runbooks/y.md", ...)
  const groups = { architecture: [], runbooks: [], concepts: [] };
  for (const p of allPagePaths) {
    if (p.startsWith('architecture/')) groups.architecture.push(p);
    else if (p.startsWith('runbooks/')) groups.runbooks.push(p);
    else if (p.startsWith('concepts/')) groups.concepts.push(p);
  }
  const links = {};
  for (const p of allPagePaths) links[p] = { supports: [], depends_on: [], related: [] };
  // architecture -> supports runbooks
  for (const arch of groups.architecture) {
    for (const rb of groups.runbooks) links[arch].supports.push(`./${path.posix.relative(path.posix.dirname(arch), rb)}`);
    for (const cp of groups.concepts) links[arch].related.push(`./${path.posix.relative(path.posix.dirname(arch), cp)}`);
  }
  // runbooks -> depends_on architecture
  for (const rb of groups.runbooks) {
    for (const arch of groups.architecture) links[rb].depends_on.push(`./${path.posix.relative(path.posix.dirname(rb), arch)}`);
  }
  // concepts -> related to architecture
  for (const cp of groups.concepts) {
    for (const arch of groups.architecture) links[cp].related.push(`./${path.posix.relative(path.posix.dirname(cp), arch)}`);
  }
  return links;
}

function renderFrontmatter(tpl, pagePath, typedLinks) {
  const links = typedLinks[pagePath] || { supports: [], depends_on: [], related: [] };
  const yamlList = (arr) => arr.length === 0 ? '[]' : '\n' + arr.map((x) => `    - ${x}`).join('\n');
  return [
    '---',
    'type: official_template_note',
    'status: advisory_template_seed',
    'trust: advisory_only',
    `template: ${tpl.id}`,
    `template_version: ${tpl.schema_version || '1'}`,
    `generated_by_template: ${tpl.id}`,
    `verified_against:`,
    `  - "template:${tpl.id}:${tpl.schema_version || '1'}"`,
    `links:`,
    `  supports:${yamlList(links.supports)}`,
    `  depends_on:${yamlList(links.depends_on)}`,
    `  related:${yamlList(links.related)}`,
    `  contradicts: []`,
    '---',
    ''
  ].join('\n');
}

function renderManagedIndexBlock(tpl, pagePaths) {
  const items = pagePaths.map((p) => `- [${p.replace(/\.md$/, '').split('/').pop().replace(/-/g, ' ')}](${p}) — generated by template:${tpl.id}`).join('\n');
  return [
    `<!-- BEGIN template:${tpl.id} -->`,
    `<!-- Managed by apply-template.js; do not edit by hand. Remove with --remove ${tpl.id}. -->`,
    `### Template ${tpl.name}`,
    '',
    items,
    '',
    `<!-- END template:${tpl.id} -->`
  ].join('\n');
}

function upsertManagedBlock(indexPath, tpl, pagePaths) {
  const begin = `<!-- BEGIN template:${tpl.id} -->`;
  const end = `<!-- END template:${tpl.id} -->`;
  let current = fs.existsSync(indexPath) ? fs.readFileSync(indexPath, 'utf8') : '# Knowledge Wiki Index\n\nThis wiki is advisory unless backed by current code/tests and evidence JSON.\n';
  const block = renderManagedIndexBlock(tpl, pagePaths);
  const beginIdx = current.indexOf(begin);
  const endIdx = current.indexOf(end);
  if (beginIdx !== -1 && endIdx !== -1) {
    return current.slice(0, beginIdx) + block + current.slice(endIdx + end.length);
  }
  return current.trimEnd() + '\n\n' + block + '\n';
}

function removeManagedBlock(indexPath, tplId) {
  if (!fs.existsSync(indexPath)) return null;
  const begin = `<!-- BEGIN template:${tplId} -->`;
  const end = `<!-- END template:${tplId} -->`;
  const current = fs.readFileSync(indexPath, 'utf8');
  const beginIdx = current.indexOf(begin);
  const endIdx = current.indexOf(end);
  if (beginIdx === -1 || endIdx === -1) return current;
  const before = current.slice(0, beginIdx).trimEnd();
  const after = current.slice(endIdx + end.length).replace(/^\s*\n/, '');
  return before + '\n\n' + after;
}

function diffSummary(beforeText, afterText, label) {
  if (beforeText === null && afterText !== null) return `+ create ${label}`;
  if (afterText === null && beforeText !== null) return `- delete ${label}`;
  if (beforeText === afterText) return `= unchanged ${label}`;
  const beforeLines = (beforeText || '').split(/\r?\n/).length;
  const afterLines = (afterText || '').split(/\r?\n/).length;
  return `~ modify  ${label} (${beforeLines} → ${afterLines} lines)`;
}

function addRepair(repairQueue, item, templateId) {
  repairQueue.queue = repairQueue.queue || [];
  if (repairQueue.queue.some(x => x.subject === item.subject)) return null;
  const usedIds = new Set(repairQueue.queue.map((entry) => entry.id));
  let ordinal = repairQueue.queue.length + 1;
  while (usedIds.has(`TPL-${String(ordinal).padStart(4, '0')}`)) ordinal += 1;
  const id = `TPL-${String(ordinal).padStart(4, '0')}`;
  const entry = { id, ...item, source_template: templateId };
  repairQueue.queue.push(entry);
  return id;
}

function applyOne(id, options = {}) {
  const tpl = readTemplate(id);
  const files = metadataPaths();
  const now = nowIso();
  const wikiPaths = Object.keys(tpl.wiki_pages || {}).map((p) => p.replace(/^wiki\//, ''));
  const typedLinks = inferTypedLinks(wikiPaths);

  const planned = [];
  const wikiWrites = [];
  for (const [relWiki, body] of Object.entries(tpl.wiki_pages || {})) {
    const pagePath = relWiki.replace(/^wiki\//, '');
    const target = safeWikiFile(relWiki);
    const exists = fs.existsSync(target);
    if (exists && !options.force) {
      planned.push(`= preserve ${relWiki} (skip: already exists, use --force to overwrite)`);
      continue;
    }
    const content = renderFrontmatter(tpl, pagePath, typedLinks) + body;
    planned.push(diffSummary(exists ? fs.readFileSync(target, 'utf8') : null, content, relWiki));
    wikiWrites.push({ relative: relWiki, target, content });
  }

  const indexPath = files.index;
  const indexBefore = fs.existsSync(indexPath) ? fs.readFileSync(indexPath, 'utf8') : null;
  const indexAfter = upsertManagedBlock(indexPath, tpl, wikiPaths);
  planned.push(diffSummary(indexBefore, indexAfter, 'wiki/index.md'));

  const repairPath = files.repair;
  const repair = readMetadata(repairPath, { generated_at: null, queue: [] });
  const repairSnapshot = JSON.stringify(repair);
  const repairAdded = [];
  for (const cp of tpl.critical_paths || []) {
    const newId = addRepair(repair, {
      priority: 'medium',
      subject: `[${tpl.name}] verify critical path: ${cp}`,
      affected_artifacts: ['.knowledge/maps/critical_paths.json', '.knowledge/modules/*.json', '.knowledge/evidence/*.json'],
      detected_by: getAgentId(),
      detected_at: now,
      source: 'official_template'
    }, tpl.id);
    if (newId) repairAdded.push(newId);
  }
  repair.generated_at = now;
  planned.push(repairAdded.length === 0 ? '= unchanged maintenance/repair_queue.json' : `~ modify  maintenance/repair_queue.json (+${repairAdded.length} items)`);

  const appliedPath = files.applied;
  const applied = readMetadata(appliedPath, { schema_version: systemVersion(), generated_at: null, templates: [] });
  const before = applied.templates.find((t) => t.id === tpl.id);
  // A skipped pre-existing page never becomes template-owned. Hashes bind
  // removal to the exact bytes written by this tool; legacy records without
  // hashes deliberately preserve their pages until explicitly overwritten.
  const pageHashes = { ...(before?.wiki_page_hashes || {}) };
  for (const write of wikiWrites) pageHashes[write.relative] = contentHash(write.content);
  if (!before) {
    applied.templates.push({
      id: tpl.id,
      name: tpl.name,
      version: tpl.schema_version || '1',
      applied_at: now,
      applied_by: getAgentId(),
      status: 'advisory_template_seed_requires_code_verification',
      wiki_pages: wikiWrites.map((write) => write.relative),
      wiki_page_hashes: pageHashes,
      repair_items: repairAdded,
      managed_index_marker: `template:${tpl.id}`
    });
  } else {
    before.applied_at = now;
    before.repair_items = Array.from(new Set([...(before.repair_items || []), ...repairAdded]));
    before.wiki_pages = Array.from(new Set([...(before.wiki_pages || []), ...wikiWrites.map((write) => write.relative)]));
    before.wiki_page_hashes = pageHashes;
  }
  applied.generated_at = now;

  const project = readMetadata(files.project, {});
  project.official_templates = project.official_templates || [];
  if (!project.official_templates.some(t => t.id === tpl.id)) project.official_templates.push({ id: tpl.id, name: tpl.name, version: tpl.schema_version || '1', applied_at: now });

  const summary = {
    applied: tpl.id,
    name: tpl.name,
    wiki_pages: Object.keys(tpl.wiki_pages || {}).length,
    wiki_pages_written: wikiWrites.length,
    wiki_pages_skipped: Object.keys(tpl.wiki_pages || {}).length - wikiWrites.length,
    typed_links_generated: true,
    repair_items_seeded: repairAdded.length,
    note: 'Template suggestions are advisory until verified against current code/tests.',
    diff: planned,
    dry_run: !!options.dryRun
  };
  if (options.dryRun) return summary;

  for (const { target, content } of wikiWrites) {
    writeFileAtomicContained(target, content, knowledgeRoot);
  }
  writeFileAtomicContained(indexPath, indexAfter, knowledgeRoot);
  writeJsonAtomicContained(repairPath, repair, knowledgeRoot);
  writeJsonAtomicContained(appliedPath, applied, knowledgeRoot);
  writeJsonAtomicContained(files.project, project, knowledgeRoot);

  if (JSON.stringify(repair) === repairSnapshot) summary.repair_items_seeded = 0;
  return summary;
}

function removeOne(id, options = {}) {
  assertSafePathSegment(id, 'template id');
  const files = metadataPaths();
  const appliedPath = files.applied;
  const applied = readMetadata(appliedPath, { templates: [] });
  const record = (applied.templates || []).find((t) => t.id === id);
  if (!record) throw new Error(`Template ${id} is not applied. Nothing to remove.`);
  const now = nowIso();
  const planned = [];
  const deletions = [];
  const preserved = [];

  // Delete generated wiki pages
  for (const relWiki of record.wiki_pages || []) {
    const abs = safeWikiFile(relWiki);
    if (!fs.existsSync(abs)) continue;
    const current = fs.readFileSync(abs);
    const expected = record.wiki_page_hashes?.[relWiki];
    if (typeof expected === 'string' && expected === contentHash(current)) {
      deletions.push({ abs, relative: relWiki, expected });
      planned.push(diffSummary(current.toString('utf8'), null, relWiki));
    } else {
      const reason = expected ? 'modified_since_apply' : 'ownership_hash_missing';
      preserved.push({ path: relWiki, reason });
      planned.push(`= preserve ${relWiki} (${reason})`);
    }
  }
  // Update wiki/index.md (remove managed block)
  const indexPath = files.index;
  const indexBefore = fs.existsSync(indexPath) ? fs.readFileSync(indexPath, 'utf8') : null;
  const indexAfter = removeManagedBlock(indexPath, id);
  planned.push(diffSummary(indexBefore, indexAfter, 'wiki/index.md'));

  // Remove repair items
  const repairPath = files.repair;
  const repair = readMetadata(repairPath, { queue: [] });
  const beforeRepair = (repair.queue || []).length;
  repair.queue = (repair.queue || []).filter((item) => item.source_template !== id);
  const repairRemoved = beforeRepair - repair.queue.length;
  if (repairRemoved > 0) planned.push(`~ modify  maintenance/repair_queue.json (-${repairRemoved} items)`);

  // Remove from applied_templates + project_index
  const newApplied = { ...applied, generated_at: now, templates: (applied.templates || []).filter((t) => t.id !== id) };
  const project = readMetadata(files.project, {});
  project.official_templates = (project.official_templates || []).filter((t) => t.id !== id);

  const summary = {
    removed: id,
    name: record.name,
    wiki_pages_deleted: deletions.length,
    wiki_pages_preserved: preserved,
    repair_items_removed: repairRemoved,
    diff: planned,
    dry_run: !!options.dryRun
  };
  if (options.dryRun) return summary;

  for (const item of deletions) {
    safeWikiFile(item.relative);
    if (fs.existsSync(item.abs) && contentHash(fs.readFileSync(item.abs)) === item.expected) fs.unlinkSync(item.abs);
    else {
      summary.wiki_pages_deleted -= 1;
      summary.wiki_pages_preserved.push({ path: item.relative, reason: 'changed_during_remove' });
    }
  }
  if (indexAfter !== null) writeFileAtomicContained(indexPath, indexAfter, knowledgeRoot);
  repair.generated_at = now;
  writeJsonAtomicContained(repairPath, repair, knowledgeRoot);
  writeJsonAtomicContained(appliedPath, newApplied, knowledgeRoot);
  writeJsonAtomicContained(files.project, project, knowledgeRoot);
  return summary;
}

function main(argv = process.argv.slice(2)) {
  const allowedFlags = new Set(['--list', '--force', '--dry-run', '--diff', '--remove', '--help', '--json']);
  for (const arg of argv) {
    if (arg.startsWith('--') && !allowedFlags.has(arg)) throw new Error(`Unknown apply-template flag: ${arg}`);
  }
  if (argv.includes('--help')) {
    console.log(JSON.stringify({ usage: 'apply-template.js <template-id> [--force] [--dry-run|--diff] | --remove <template-id> | --list', removal: 'Only unchanged pages with a recorded ownership hash are deleted.' }, null, 2));
    return;
  }
  if (argv.includes('--list') || argv.length === 0) {
    console.log(JSON.stringify({ templates: listTemplates() }, null, 2));
    return;
  }
  const flags = new Set(argv.filter((a) => a.startsWith('--')));
  const ids = argv.filter((a) => !a.startsWith('--'));
  const options = {
    force: flags.has('--force'),
    dryRun: flags.has('--dry-run') || flags.has('--diff'),
    diff: flags.has('--diff'),
    remove: flags.has('--remove')
  };
  if (ids.length === 0) throw new Error('A template id is required. Run --list.');
  const results = ids.map((id) => options.remove ? removeOne(id, options) : applyOne(id, options));
  console.log(JSON.stringify({ results }, null, 2));
}

if (require.main === module) {
  // Read-only operations (--list, --dry-run, --diff) skip the lock.
  const argv = process.argv.slice(2);
  try {
    if (argv.length === 0 || argv.some((flag) => ['--list', '--help', '--dry-run', '--diff'].includes(flag))) main(argv);
    else withContainedLock(TEMPLATE_LOCK, () => main(argv));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, error: error.message, code: error.code || 'template_operation_failed' }, null, 2));
    process.exitCode = 1;
  }
}

module.exports = { listTemplates, applyOne, removeOne };
