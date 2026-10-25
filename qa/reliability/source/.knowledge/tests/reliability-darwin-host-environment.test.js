'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const client = require(process.env.DARWIN_ENV_TARGET || '../tools/lib/verification-darwin-client');
test('genuine captured host environment reaches native helper without widening caller admission', () => {
  const result = client.nativeEnv();
  assert.equal(Object.getPrototypeOf(result), null);
  for (const [key, value] of Object.entries(result)) {
    assert.equal(typeof value, 'string');assert.equal(/^(?:DYLD_|LD_)/i.test(key), false);
    assert.equal(/^(?:NODE_OPTIONS|NODE_PATH|BASH_ENV|ENV)$/i.test(key), false);
  }
  assert.equal(result.PATH, process.env.PATH);
});
test('arbitrary caller proxies and getters are refused without invocation', () => {
  let effects = 0;
  assert.throws(() => client.nativeEnv(new Proxy({}, { getPrototypeOf() { effects++;return null; }, ownKeys() { effects++;return []; } })),
    { code: 'verification_darwin_environment_invalid' });
  assert.throws(() => client.nativeEnv({ get PATH() { effects++;return '/bin'; } }),
    { code: 'verification_darwin_environment_invalid' });
  assert.equal(effects, 0);
});
test('plain caller environment retains sanitization and exact values', () => {
  const value = client.nativeEnv({ PATH: '/usr/bin', HOME: '/home/fixture', NODE_OPTIONS: '--inspect',
    DYLD_INSERT_LIBRARIES: '/x', LD_PRELOAD: '/y', NODE_PATH: '/z', BASH_ENV: '/a' });
  assert.equal(JSON.stringify(value), JSON.stringify({ PATH: '/usr/bin', HOME: '/home/fixture' }));
});
