'use strict';

const fs = require('fs');
const path = require('path');

function normalizeReleasePath(value, options = {}) {
  const raw = String(value ?? '');
  const errors = [];
  if (!raw || /[\u0000-\u001f]/.test(raw)) errors.push('empty_or_control_character_path');
  if (/^[A-Za-z]:[\\/]/.test(raw) || raw.startsWith('/') || raw.startsWith('\\\\')) errors.push('absolute_path');
  if (raw.includes('\\') && options.rejectBackslash) errors.push('backslash_separator');
  let normalized = raw.replace(/\\/g, '/').normalize('NFC');
  while (normalized.startsWith('./')) normalized = normalized.slice(2);
  const segments = normalized.split('/');
  if (segments.some((segment) => segment === '')) errors.push('empty_segment');
  if (segments.includes('..')) errors.push('path_traversal');
  if (segments.includes('.')) errors.push('dot_segment');
  return { raw, path: normalized, errors: Array.from(new Set(errors)) };
}

function loadReleaseContract(root) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'install-manifest.json'), 'utf8'));
  if (!manifest.release_contract || typeof manifest.release_contract !== 'object') {
    throw new Error('install-manifest.json is missing release_contract.');
  }
  return { manifest, ...manifest.release_contract };
}

function pathMatches(pathValue, ruleValue) {
  const target = normalizeReleasePath(pathValue).path;
  const rule = normalizeReleasePath(ruleValue).path.replace(/\/+$/, '');
  return String(ruleValue).replace(/\\/g, '/').endsWith('/')
    ? target === rule || target.startsWith(`${rule}/`)
    : target === rule;
}

function pathIsIncluded(pathValue, contract) {
  const target = normalizeReleasePath(pathValue).path;
  if (target === 'agent-integrations' || target.startsWith('agent-integrations/')) {
    const allowed = (contract.public_agent_integration_paths || [])
      .map((item) => normalizeReleasePath(item).path);
    return target === 'agent-integrations' || allowed.some((item) =>
      target === item || item.startsWith(`${target}/`)
    );
  }
  return (contract.system_include_paths || []).some((rule) => {
    const normalizedRule = normalizeReleasePath(rule).path.replace(/\/+$/, '');
    // A directory ancestor of an explicitly included file must be traversed
    // during staging; descendants still undergo their own contract check.
    return target === normalizedRule ||
      target.startsWith(`${normalizedRule}/`) ||
      normalizedRule.startsWith(`${target}/`);
  });
}

function exclusionForPath(relativePath, contract) {
  const normalized = normalizeReleasePath(relativePath).path;
  if (normalized.startsWith('agent-integrations/')) {
    const allowed = new Set((contract.public_agent_integration_paths || [])
      .map((item) => normalizeReleasePath(item).path));
    const isAncestor = Array.from(allowed).some((item) => item.startsWith(`${normalized}/`));
    if (!allowed.has(normalized) && !isAncestor) {
      return { excluded: true, reason: 'public_agent_integration_allowlist', rule: normalized };
    }
  }
  const paths = [
    ...(contract.manifest.system_exclude_paths || []),
    ...(contract.source_only_test_paths || []),
    ...(contract.source_only_document_paths || []),
    ...(contract.maintainer_tool_paths || []),
    ...(contract.runtime_state_prefixes || [])
  ];
  const match = paths.find((rule) => pathMatches(normalized, rule));
  if (match) return { excluded: true, reason: 'manifest_exclude_path', rule: match };
  const isPublicReleaseNote = (contract.public_release_note_paths || [])
    .some((item) => pathMatches(normalized, item));
  if (normalized.startsWith('.release-notes/') && !isPublicReleaseNote) {
    return { excluded: true, reason: 'manifest_public_release_note_allowlist', rule: normalized };
  }
  const candidatePattern = contract.candidate_note_pattern ? new RegExp(contract.candidate_note_pattern, 'i') : null;
  if (candidatePattern && candidatePattern.test(normalized) && !isPublicReleaseNote) {
    return { excluded: true, reason: 'candidate_release_note', rule: normalized };
  }
  const base = path.posix.basename(normalized);
  for (const pattern of contract.transient_name_patterns || []) {
    if (new RegExp(pattern, 'i').test(normalized) || new RegExp(pattern, 'i').test(base)) {
      return { excluded: true, reason: 'manifest_transient_path', rule: pattern };
    }
  }
  return { excluded: false };
}

function validateReleaseInventory(entries, contract, options = {}) {
  const prefix = options.prefix || '.knowledge/';
  const violations = [];
  const names = new Set();
  const exactNames = new Set();
  const publicTests = new Set((contract.public_self_test_paths || []).map((item) => normalizeReleasePath(item).path));
  const publicIntegrations = new Set((contract.public_agent_integration_paths || []).map((item) => normalizeReleasePath(item).path));
  const actualTests = new Set();
  const actualIntegrations = new Set();
  for (const entry of entries) {
    const raw = typeof entry === 'string' ? entry : entry.name;
    const normalized = normalizeReleasePath(raw, { rejectBackslash: options.rejectBackslash });
    for (const reason of normalized.errors) violations.push({ type: 'zip_path_invalid', entry: raw, reason });
    if (!normalized.path.startsWith(prefix)) {
      violations.push({ type: 'entry_root', entry: normalized.path, reason: `entry must be below ${prefix}` });
      continue;
    }
    const relative = normalized.path.slice(prefix.length);
    const collisionKey = relative.toLocaleLowerCase('en-US');
    if (names.has(collisionKey)) violations.push({ type: 'zip_duplicate_entry', entry: normalized.path, reason: 'duplicate or Windows case-collision path' });
    names.add(collisionKey);
    exactNames.add(relative);
    const excluded = exclusionForPath(relative, contract);
    if (excluded.excluded) violations.push({ type: 'manifest_excluded_path', entry: normalized.path, reason: excluded.reason, rule: excluded.rule });
    if (/^tools\/self-test-.*\.js$/i.test(relative)) {
      actualTests.add(relative);
      if (!publicTests.has(relative)) violations.push({ type: 'public_self_test_unallowlisted', entry: normalized.path, reason: 'shipped self-test is absent from public_self_test_paths' });
    }
    if (relative.startsWith('agent-integrations/') && !relative.endsWith('/')) {
      actualIntegrations.add(relative);
      if (!publicIntegrations.has(relative)) violations.push({ type: 'public_agent_integration_unallowlisted', entry: normalized.path, reason: 'shipped integration file is absent from public_agent_integration_paths' });
    }
  }
  // Every accepted inventory entry is a file. Compare every proper parent
  // after collecting all names so either archive order and Windows case aliases
  // cannot hide a file that must also be a directory during extraction.
  for (const relative of exactNames) {
    const segments = relative.split('/');
    for (let count = 1; count < segments.length; count++) {
      const ancestor = segments.slice(0, count).join('/');
      if (names.has(ancestor.toLocaleLowerCase('en-US'))) {
        violations.push({ type: 'zip_file_directory_conflict', entry: `${prefix}${relative}`,
          conflict_entry: `${prefix}${ancestor}`, reason: 'a file entry is also an extraction parent directory' });
      }
    }
  }
  for (const expected of publicTests) {
    if (!exactNames.has(expected)) violations.push({ type: 'public_self_test_missing', entry: `${prefix}${expected}`, reason: 'allowlisted self-test is missing from ZIP inventory' });
  }
  for (const expected of publicIntegrations) {
    if (!exactNames.has(expected)) violations.push({ type: 'public_agent_integration_missing', entry: `${prefix}${expected}`, reason: 'allowlisted agent integration is missing from ZIP inventory' });
  }
  for (const required of contract.required_public_paths || []) {
    const expected = normalizeReleasePath(required).path;
    if (!exactNames.has(expected)) violations.push({ type: 'required_entry_missing', entry: `${prefix}${expected}`, reason: 'required public path is missing' });
  }
  // Staging and physical ZIP validation share the installer's required runtime
  // inventory. Case-folded collision detection cannot prove that a required
  // spelling exists on a case-sensitive installation.
  for (const required of contract.manifest.required_system_files || []) {
    const expected = normalizeReleasePath(required).path;
    if (!exactNames.has(expected)) violations.push({ type: 'required_system_entry_missing', entry: `${prefix}${expected}`, reason: 'install-manifest required system file is missing' });
  }
  return { entries: names.size, public_self_tests: Array.from(actualTests).sort(), public_agent_integrations: Array.from(actualIntegrations).sort(), violations };
}

module.exports = { normalizeReleasePath, loadReleaseContract, pathMatches, pathIsIncluded, exclusionForPath, validateReleaseInventory };
