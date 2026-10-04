'use strict';

const fs = require('fs');
const path = require('path');

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '').normalize('NFC');
}

function loadReleasePolicy(root) {
  const policyPath = path.join(root, 'release-policy.json');
  return JSON.parse(fs.readFileSync(policyPath, 'utf8'));
}

function compileRule(rule) {
  return new RegExp(rule.pattern, rule.flags || '');
}

function firstMatchingRule(rules, relPath) {
  const rel = normalizeRel(relPath);
  for (const rule of rules || []) {
    if (compileRule(rule).test(rel)) return rule;
  }
  return null;
}

function matchAllRules(rules, relPath) {
  const rel = normalizeRel(relPath);
  return (rules || []).filter((rule) => compileRule(rule).test(rel));
}

function contentAllowed(rule, entryName) {
  const name = normalizeRel(entryName);
  return (rule.allow_entries || []).some((item) => {
    if (typeof item === 'string') return normalizeRel(item) === name;
    if (item && typeof item === 'object') return normalizeRel(item.entry || item.path || '') === name;
    return false;
  });
}

function requiredEntriesForProfile(policy, profile = 'public_runtime') {
  if (policy.required_entry_profiles && Array.isArray(policy.required_entry_profiles[profile])) {
    return policy.required_entry_profiles[profile].map(normalizeRel);
  }
  if (Array.isArray(policy.required_entries)) return policy.required_entries.map(normalizeRel);
  if (policy.required_entries && Array.isArray(policy.required_entries[profile])) {
    return policy.required_entries[profile].map(normalizeRel);
  }
  return [];
}

module.exports = {
  normalizeRel,
  loadReleasePolicy,
  firstMatchingRule,
  matchAllRules,
  compileRule,
  contentAllowed,
  requiredEntriesForProfile
};
