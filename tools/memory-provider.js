#!/usr/bin/env node
'use strict';

const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const {
  listProviders,
  previewProvider,
  recordInstall,
  recordUpdate,
  uninstallProvider,
  migrateLegacy,
  statusProvider,
  buildExternalMemoryReport
} = require('./lib/memory-providers');

function print(result, json) {
  if (json) console.log(JSON.stringify(result, null, 2));
  else if (result && typeof result === 'object') {
    if (Array.isArray(result.providers)) {
      for (const provider of result.providers) {
        console.log(`${provider.id}\t${provider.layer}\t${provider.type}\t${provider.license_spdx}\t${provider.version_pin || '-'}`);
      }
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
  } else {
    console.log(String(result));
  }
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const flags = parsed.flags;
  const command = parsed.positional[0] || 'list';
  const providerId = parsed.positional[1];
  const context = resolveKnowledgeContext(flags);
  const options = { paidRoot: flags.paidRoot, write: true };
  let result;

  if (command === 'list') result = listProviders(context, options);
  else if (command === 'preview') result = previewProvider(context, providerId, options);
  else if (command === 'install') result = recordInstall(context, providerId, flags, options);
  else if (command === 'update') result = recordUpdate(context, providerId, flags, options);
  else if (command === 'uninstall') result = uninstallProvider(context, providerId, flags, options);
  else if (command === 'status') result = statusProvider(context, providerId, options);
  else if (command === 'status-all') result = buildExternalMemoryReport(context, options);
  else if (command === 'migrate-legacy') result = migrateLegacy(context, options);
  else throw new Error(`Unknown memory-provider command: ${command}`);

  print(result, Boolean(flags.json));
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const parsed = parseCliArgs(process.argv.slice(2));
    if (parsed.flags.json) console.log(JSON.stringify({ ok: false, error: error.message }, null, 2));
    else console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = main;
