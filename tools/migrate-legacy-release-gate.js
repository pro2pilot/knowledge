#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { assertSafeContainedPath, writeFileAtomicContained } = require('./lib/json-store');
const { resolveKnowledgeContext, parseCliArgs } = require('./lib/path-context');

const LEGACY_SHA256 = '608bc9d28543fec72bdc02b03298acaf76c484aca0ed87b33388c97f2b4d06bd';
const digest = (body) => crypto.createHash('sha256').update(body.replace(/\r\n/g, '\n')).digest('hex');
const replacement = () => fs.readFileSync(path.join(__dirname, 'templates/release-gate-redirect.js'), 'utf8');
function inspectLegacyGate(repoRoot) {
  const file = path.join(repoRoot, 'tools/release-gate.js');
  if (!fs.existsSync(file)) return { status: 'absent' };
  try {
    assertSafeContainedPath(repoRoot, file);
    if (!fs.lstatSync(file).isFile()) return { status: 'unsafe_path' };
    const body = fs.readFileSync(file, 'utf8');
    const sha256 = digest(body);
    return { status: sha256 === LEGACY_SHA256 ? 'obsolete' :
      sha256 === digest(replacement()) ? 'redirected' : 'custom_preserved', sha256 };
  } catch { return { status: 'unsafe_path' }; }
}
function migrateLegacyGate(repoRoot, apply = false) {
  const before = inspectLegacyGate(repoRoot);
  if (before.status !== 'obsolete' || !apply) return { ...before, applied: false };
  const file = path.join(repoRoot, 'tools/release-gate.js');
  const backup = path.join(repoRoot, 'tools/release-gate.js.pre-3.4.3.bak');
  const original = fs.readFileSync(file, 'utf8');
  if (digest(original) !== LEGACY_SHA256) throw new Error('Legacy release gate changed during migration');
  if (fs.existsSync(backup)) {
    assertSafeContainedPath(repoRoot, backup);
    if (fs.readFileSync(backup, 'utf8') !== original) throw new Error('Existing migration backup differs');
  } else writeFileAtomicContained(backup, original, repoRoot);
  if (inspectLegacyGate(repoRoot).sha256 !== LEGACY_SHA256) throw new Error('Legacy release gate changed before replacement');
  writeFileAtomicContained(file, replacement(), repoRoot);
  return { status: 'redirected', applied: true, backup: path.relative(repoRoot, backup).replace(/\\/g, '/') };
}
if (require.main === module) {
  const { flags } = parseCliArgs();
  const repoRoot = flags.root ? path.resolve(flags.root) : resolveKnowledgeContext().targetRoot;
  console.log(JSON.stringify(migrateLegacyGate(repoRoot, Boolean(flags.apply)), null, 2));
}
module.exports = { inspectLegacyGate, migrateLegacyGate };
