#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');

function parseArgs(argv = process.argv.slice(2)) {
  return { json: argv.includes('--json') };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const noticesPath = path.join(root, 'THIRD_PARTY_NOTICES.md');
  const sbomPath = path.join(root, 'SBOM.memory.json');
  const issues = [];
  const notices = fs.existsSync(noticesPath) ? fs.readFileSync(noticesPath, 'utf8') : '';
  const sbom = fs.existsSync(sbomPath) ? JSON.parse(fs.readFileSync(sbomPath, 'utf8')) : { providers: [] };

  if (!notices.trim()) issues.push({ id: 'missing_notices', message: 'THIRD_PARTY_NOTICES.md is missing or empty' });
  for (const provider of sbom.providers || []) {
    if (!provider.id) issues.push({ id: 'sbom_provider_missing_id', provider });
    if (!provider.license_spdx) issues.push({ id: 'sbom_provider_missing_license', provider: provider.id || '<unknown>' });
    if (provider.bundled === true) issues.push({ id: 'unexpected_bundled_provider', provider: provider.id, message: 'Free core should not bundle external memory provider code' });
    if (provider.name && !notices.includes(provider.name)) issues.push({ id: 'notice_missing_provider_name', provider: provider.id, name: provider.name });
    if (provider.version_pin && !notices.includes(provider.version_pin)) issues.push({ id: 'notice_missing_version_pin', provider: provider.id, version_pin: provider.version_pin });
  }

  const result = {
    schema_version: 'third-party-notices-validation.v1',
    status: issues.length ? 'fail' : 'pass',
    notices: 'THIRD_PARTY_NOTICES.md',
    sbom: 'SBOM.memory.json',
    providers_checked: (sbom.providers || []).length,
    issues
  };
  if (args.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`third-party notices ${result.status}`);
  if (result.status !== 'pass') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const args = parseArgs(process.argv.slice(2));
    const result = { schema_version: 'third-party-notices-validation.v1', status: 'fail', error: error.message };
    if (args.json) console.log(JSON.stringify(result, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}
