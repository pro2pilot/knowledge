'use strict';

const fs = require('fs');
const path = require('path');

function systemVersion(root = path.resolve(__dirname, '..', '..')) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    return pkg.version || '3.2.9';
  } catch {
    return '3.2.9';
  }
}

module.exports = { systemVersion };
