#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { writeFileAtomic } = require('./lib/json-store');
const {
  generateGithubForm,
  readSchema
} = require('./lib/field-report/contract');

function run(argv = process.argv.slice(2)) {
  const systemRoot = path.resolve(__dirname, '..');
  const schema = readSchema(systemRoot);
  const expected = generateGithubForm(schema);
  const output = path.join(
    systemRoot,
    '.github',
    'DISCUSSION_TEMPLATE',
    'field-reports.yml'
  );
  const current = fs.existsSync(output)
    ? fs.readFileSync(output, 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n')
    : null;
  if (argv.includes('--write')) {
    writeFileAtomic(output, expected);
    return {
      schema_version: schema.schema_version,
      status: 'written',
      output,
      changed: current !== expected
    };
  }
  return {
    schema_version: schema.schema_version,
    status: current === expected ? 'pass' : 'drift',
    output,
    changed: current !== expected
  };
}

if (require.main === module) {
  try {
    const result = run();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (result.status === 'drift') process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { run };
