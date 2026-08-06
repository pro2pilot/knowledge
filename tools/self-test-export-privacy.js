#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { sanitizeExportValue } = require('./lib/export-sanitizer');
const { systemVersion } = require('./lib/system-version');

const sourceRoot = path.resolve(__dirname, '..');
const TOKEN_CANARY = ['ghp', 'CANARYCANARYCANARYCANARYCANARY123456'].join('_');
const EMAIL_CANARY = ['privacy-canary-3212', 'example.invalid'].join('@');
const PATH_CANARY = ['C:', 'Users', 'fake-researcher', ['knowledge', 'kit', '3212'].join('-'), 'private.txt'].join('\\');
const UNC_PATH_CANARY = ['', '', 'fake-server', 'fake-share', 'fake-researcher', 'private.txt'].join('\\');
const ROOT_PATH_CANARY = ['', 'root', '.ssh', 'privacy_id'].join('/');
const HOME_PATH_CANARY = ['', 'home', 'fake-researcher', '.ssh', 'privacy_id'].join('/');
const MAC_USER_PATH_CANARY = ['', 'Users', 'fake-researcher', 'Library', 'privacy.db'].join('/');
const MAC_PRIVATE_PATH_CANARY = ['', 'private', 'var', 'folders', 'privacy', 'cache.db'].join('/');
const WORKSPACE_PATH_CANARY = ['', 'workspace', 'private-project', 'privacy.db'].join('/');
const TILDE_SSH_PATH_CANARY = ['~', '.ssh', 'privacy_id'].join('/');
const OPAQUE_BEARER_VALUE = ['opaque', 'authorization', 'canary', '3212'].join('-');
const BEARER_CANARY = `${['Bear', 'er'].join('')} ${OPAQUE_BEARER_VALUE}`;
const CLIENT_SECRET_CANARY = ['ordinary', 'client', 'secret', 'canary', '3212'].join('-');
const PRIVATE_KEY_CANARY = ['ordinary', 'private', 'key', 'canary', '3212'].join('-');
const CREDENTIALS_CANARY = ['ordinary', 'credentials', 'canary', '3212'].join('-');
const CONTENT_CANARY = ['private', 'memory', 'content', 'canary', '3212'].join('-');
const TEXT_CANARY = ['private', 'text', 'canary', '3212'].join('-');
const MEMORY_NOTE_CANARY = ['private', 'memory', 'note', 'canary', '3212'].join('-');
const MEMORY_NARRATIVE_CANARY = ['ordinary', 'private', 'memory', 'narrative', '3212'].join('-');
const MULTIWORD_PASSWORD_CANARY = ['two', 'word', 'password', 'canary', '3212'].join(' ');
const CLIENT_SECRET_KEY = ['client', 'Secret'].join('');
const PRIVATE_KEY_KEY = ['private', 'key'].join('_');
const PRIVATE_KEY_MATERIAL_KEY = ['private', 'key', 'material'].join('_');
const API_KEY_VALUE_KEY = ['api', 'Key', 'Value'].join('');
const CREDENTIALS_KEY = ['credential', 's'].join('');
const AUTHORIZATION_KEY = ['author', 'ization'].join('');
const NUMERIC_TOKEN_KEY = ['access', 'Token'].join('');
const MEMORY_CAMEL_KEY = ['memory', 'Note'].join('');
const NUMERIC_TOKEN_CANARY = Number(['987', '654', '321'].join(''));
const CONTENT_NUMBER_CANARY = Number(['4242', '4242'].join(''));
const TEXT_NUMBER_CANARY = Number(['313', '37'].join(''));
const MEMORY_PIN_CANARY = Number(['867', '5309'].join(''));
const NESTED_MEMORY_PIN_CANARY = Number(['246', '80'].join(''));
const SENSITIVE_NUMBER_CANARIES = [
  NUMERIC_TOKEN_CANARY,
  CONTENT_NUMBER_CANARY,
  TEXT_NUMBER_CANARY,
  MEMORY_PIN_CANARY,
  NESTED_MEMORY_PIN_CANARY
];
const NORMAL_TEXT = 'The lighthouse verifies ordinal blue paperclips.';
const LOCAL_PATH_CANARIES = [
  PATH_CANARY,
  UNC_PATH_CANARY,
  ROOT_PATH_CANARY,
  HOME_PATH_CANARY,
  MAC_USER_PATH_CANARY,
  MAC_PRIVATE_PATH_CANARY,
  WORKSPACE_PATH_CANARY,
  TILDE_SSH_PATH_CANARY
];
const SECRET_STRING_CANARIES = [
  TOKEN_CANARY,
  EMAIL_CANARY,
  OPAQUE_BEARER_VALUE,
  CLIENT_SECRET_CANARY,
  PRIVATE_KEY_CANARY,
  CREDENTIALS_CANARY,
  CONTENT_CANARY,
  TEXT_CANARY,
  MEMORY_NOTE_CANARY,
  MEMORY_NARRATIVE_CANARY,
  MULTIWORD_PASSWORD_CANARY
];

function assert(condition, message, details = null) {
  if (condition) return;
  const suffix = details ? `\n${JSON.stringify(details, null, 2)}` : '';
  throw new Error(`${message}${suffix}`);
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function runExporter(tool, fixture, stateRoot, options = {}) {
  const args = [
    path.join('tools', tool),
    '--target-root', fixture,
    '--project-knowledge-root', sourceRoot,
    '--state-root', stateRoot,
    '--json'
  ];
  if (options.team) {
    args.push(
      '--mode', 'team',
      '--team-root', path.join(fixture, 'team-root'),
      '--workspace-id', 'privacy-export-team',
      '--agent-id', 'privacy-export-self-test'
    );
  }
  const result = spawnSync(process.execPath, args, {
    cwd: sourceRoot,
    env: {
      ...process.env,
      KNOWLEDGE_AGENT_ID: 'privacy-export-self-test',
      CI: '1',
      NO_PROXY: '*',
      no_proxy: '*'
    },
    encoding: 'utf8',
    windowsHide: true,
    timeout: 120000
  });
  assert(result.status === 0, `${tool} failed`, {
    exit_code: result.status,
    stdout: result.stdout,
    stderr: result.stderr
  });
  let parsed;
  try {
    parsed = JSON.parse(String(result.stdout || '').trim());
  } catch (error) {
    throw new Error(`${tool} stdout was not one JSON document: ${error.message}`);
  }
  return { parsed, stdout: String(result.stdout || ''), stderr: String(result.stderr || '') };
}

function stringsIn(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((item) => stringsIn(item, out));
  else if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      out.push(key);
      stringsIn(item, out);
    }
  }
  return out;
}

function assertNoCanary(value, serialized, label) {
  const strings = stringsIn(value);
  for (const text of strings) {
    for (const canary of SECRET_STRING_CANARIES) {
      assert(!text.includes(canary), `${label} leaked secret/content canary`);
    }
    for (const canary of LOCAL_PATH_CANARIES) {
      assert(!text.includes(canary), `${label} leaked local path canary`);
    }
  }
  for (const canary of [...SECRET_STRING_CANARIES, ...LOCAL_PATH_CANARIES]) {
    const encoded = JSON.stringify(canary).slice(1, -1);
    const doubleEncoded = JSON.stringify(encoded).slice(1, -1);
    assert(!serialized.includes(canary), `${label} serialized bytes leaked raw canary`);
    assert(!serialized.includes(encoded), `${label} serialized bytes leaked encoded canary`);
    assert(!serialized.includes(doubleEncoded), `${label} serialized bytes leaked double-encoded canary`);
  }
  for (const canary of SENSITIVE_NUMBER_CANARIES) {
    assert(!serialized.includes(String(canary)), `${label} serialized bytes leaked sensitive numeric scalar`);
  }
  assert(!/[A-Za-z]:<local-path>/.test(serialized), `${label} left a drive prefix on a redacted path`);
}

function assertNoFixturePath(result, fixture, label) {
  const serialized = JSON.stringify(result);
  const encoded = JSON.stringify(fixture).slice(1, -1);
  const doubleEncoded = JSON.stringify(encoded).slice(1, -1);
  assert(!stringsIn(result).some((text) => text.includes(fixture)), `${label} leaked fixture path in data`);
  assert(
    !serialized.includes(fixture) && !serialized.includes(encoded) && !serialized.includes(doubleEncoded),
    `${label} leaked fixture path in serialized data`
  );
}

function assertNormalTextSurvives(value, label) {
  assert(stringsIn(value).some((text) => text.includes(NORMAL_TEXT)), `${label} removed harmless control text`);
}

function seedFixture(stateRoot) {
  const nestedProbe = {
    token: TOKEN_CANARY,
    email: EMAIL_CANARY,
    local_path: PATH_CANARY,
    unc_path: UNC_PATH_CANARY,
    posix_paths: [
      ROOT_PATH_CANARY,
      HOME_PATH_CANARY,
      MAC_USER_PATH_CANARY,
      MAC_PRIVATE_PATH_CANARY,
      WORKSPACE_PATH_CANARY,
      TILDE_SSH_PATH_CANARY
    ],
    encoded_path: JSON.stringify(PATH_CANARY),
    content: CONTENT_CANARY,
    text: TEXT_CANARY,
    memory_note: MEMORY_NOTE_CANARY,
    [MEMORY_CAMEL_KEY]: MEMORY_NOTE_CANARY,
    memory_records: {
      note: MEMORY_NARRATIVE_CANARY,
      pin: NESTED_MEMORY_PIN_CANARY,
      active: true,
      rows: [{ summary: MEMORY_NARRATIVE_CANARY, active: false }]
    },
    memory_records_array: [
      { note: MEMORY_NARRATIVE_CANARY, pin: NESTED_MEMORY_PIN_CANARY, active: true },
      [MEMORY_NARRATIVE_CANARY]
    ],
    numeric_content_fields: {
      content: CONTENT_NUMBER_CANARY,
      text: TEXT_NUMBER_CANARY,
      memory_pin: MEMORY_PIN_CANARY
    },
    [CLIENT_SECRET_KEY]: CLIENT_SECRET_CANARY,
    [PRIVATE_KEY_KEY]: PRIVATE_KEY_CANARY,
    [PRIVATE_KEY_MATERIAL_KEY]: PRIVATE_KEY_CANARY,
    [API_KEY_VALUE_KEY]: CLIENT_SECRET_CANARY,
    [CREDENTIALS_KEY]: {
      username: CREDENTIALS_CANARY,
      pin: NUMERIC_TOKEN_CANARY
    },
    [AUTHORIZATION_KEY]: BEARER_CANARY,
    [NUMERIC_TOKEN_KEY]: NUMERIC_TOKEN_CANARY,
    diagnostic_log: `${['pass', 'word'].join('')}="${MULTIWORD_PASSWORD_CANARY}"`,
    sensitive_property_names: {
      [TOKEN_CANARY]: 'token-key-value',
      [EMAIL_CANARY]: 'email-key-value',
      [PATH_CANARY]: 'path-key-value'
    },
    normal_text: NORMAL_TEXT,
    nested: [
      {
        token_alias: TOKEN_CANARY,
        identity: `Owner ${EMAIL_CANARY}`,
        path_text: `Read ${PATH_CANARY}`,
        unc_path_text: `Read ${UNC_PATH_CANARY}`,
        normal_text: NORMAL_TEXT
      },
      [TOKEN_CANARY, EMAIL_CANARY, PATH_CANARY, UNC_PATH_CANARY, NORMAL_TEXT]
    ],
    flags: {
      memory_content: false,
      api_keys: false
    }
  };

  writeJson(path.join(stateRoot, 'maintenance', 'routing_bundle.json'), {
    source_of_truth_order: ['current_code', 'current_tests'],
    project: { summary: NORMAL_TEXT },
    privacy_export_probe: nestedProbe,
    modules: [{
      module_id: 'privacy_canary_module',
      path: PATH_CANARY,
      trust_status: 'advisory_only',
      freshness_status: 'fresh'
    }],
    high_risk_modules: [EMAIL_CANARY]
  });
  writeJson(path.join(stateRoot, 'maintenance', 'trust_report.json'), {
    modules: {
      trusted: [NORMAL_TEXT],
      suspect: [TOKEN_CANARY, EMAIL_CANARY, PATH_CANARY]
    }
  });
  writeJson(path.join(stateRoot, 'maintenance', 'quality_report.json'), {
    status: 'healthy',
    quality_score: 100,
    issues: []
  });
  writeJson(path.join(stateRoot, 'maintenance', 'repair_queue.json'), {
    queue: [{
      id: 'PRIVACY-CANARY-REPAIR',
      status: 'open',
      ...nestedProbe
    }]
  });
  writeJson(path.join(stateRoot, 'maintenance', 'stale_items.json'), {
    items: [{
      id: 'PRIVACY-CANARY-STALE',
      status: 'stale',
      ...nestedProbe
    }]
  });
  writeJson(path.join(stateRoot, 'maps', 'file_criticality.json'), {
    files: [{
      path: PATH_CANARY,
      classification: 'critical',
      metadata: nestedProbe
    }]
  });
}

function main() {
  const tempCandidates = [
    ...(process.platform === 'win32' ? ['C:\\tmp'] : []),
    os.tmpdir()
  ].filter((candidate, index, all) => candidate && all.indexOf(candidate) === index);
  let preferredTemp = null;
  let fixture = null;
  let lastTempError = null;
  for (const candidate of tempCandidates) {
    try {
      fs.mkdirSync(candidate, { recursive: true });
      fixture = fs.mkdtempSync(path.join(candidate, 'knowledge-export-privacy-'));
      preferredTemp = candidate;
      break;
    } catch (error) {
      lastTempError = error;
    }
  }
  if (!fixture) {
    throw new Error(`Unable to create privacy self-test fixture: ${lastTempError?.message || 'no writable temporary root'}`);
  }
  const stateRoot = path.join(fixture, '.knowledge');
  let cleaned = false;
  let report;
  try {
    seedFixture(stateRoot);

    const directInput = {
      token: TOKEN_CANARY,
      email: EMAIL_CANARY,
      local_path: PATH_CANARY,
      unc_path: UNC_PATH_CANARY,
      posix_paths: [
        ROOT_PATH_CANARY,
        HOME_PATH_CANARY,
        MAC_USER_PATH_CANARY,
        MAC_PRIVATE_PATH_CANARY,
        WORKSPACE_PATH_CANARY,
        TILDE_SSH_PATH_CANARY
      ],
      encoded_path: JSON.stringify(PATH_CANARY),
      content: CONTENT_CANARY,
      text: TEXT_CANARY,
      memory_note: MEMORY_NOTE_CANARY,
      [MEMORY_CAMEL_KEY]: MEMORY_NOTE_CANARY,
      memory_records: {
        note: MEMORY_NARRATIVE_CANARY,
        pin: NESTED_MEMORY_PIN_CANARY,
        active: true,
        rows: [{ summary: MEMORY_NARRATIVE_CANARY, active: false }]
      },
      memory_records_array: [
        { note: MEMORY_NARRATIVE_CANARY, pin: NESTED_MEMORY_PIN_CANARY, active: true },
        [MEMORY_NARRATIVE_CANARY]
      ],
      numeric_content_fields: {
        content: CONTENT_NUMBER_CANARY,
        text: TEXT_NUMBER_CANARY,
        memory_pin: MEMORY_PIN_CANARY
      },
      memory_governance: {
        policy_summary: NORMAL_TEXT
      },
      [CLIENT_SECRET_KEY]: CLIENT_SECRET_CANARY,
      [PRIVATE_KEY_KEY]: PRIVATE_KEY_CANARY,
      [PRIVATE_KEY_MATERIAL_KEY]: PRIVATE_KEY_CANARY,
      [API_KEY_VALUE_KEY]: CLIENT_SECRET_CANARY,
      [CREDENTIALS_KEY]: {
        username: CREDENTIALS_CANARY,
        pin: NUMERIC_TOKEN_CANARY
      },
      [AUTHORIZATION_KEY]: BEARER_CANARY,
      [NUMERIC_TOKEN_KEY]: NUMERIC_TOKEN_CANARY,
      diagnostic_log: `${['pass', 'word'].join('')}="${MULTIWORD_PASSWORD_CANARY}"`,
      bearer_log: `request ${BEARER_CANARY}`,
      sensitive_property_names: {
        [TOKEN_CANARY]: 'token-key-value',
        [EMAIL_CANARY]: 'email-key-value',
        [PATH_CANARY]: 'path-key-value'
      },
      normal_text: NORMAL_TEXT,
      nested: [{
        values: [
          TOKEN_CANARY,
          EMAIL_CANARY,
          ...LOCAL_PATH_CANARIES,
          BEARER_CANARY,
          NORMAL_TEXT
        ]
      }],
      memory_content: false,
      api_keys: false,
      secrets_included: false,
      memory_content_included: false
    };
    const direct = sanitizeExportValue(directInput, {
      redactContentFields: true,
      redactWorkspaceName: true
    });
    const directSerialized = JSON.stringify(direct);
    assertNoCanary(direct, directSerialized, 'shared sanitizer');
    assertNormalTextSurvives(direct, 'shared sanitizer');
    assert(direct.memory_content === false && typeof direct.memory_content === 'boolean', 'memory_content boolean changed type');
    assert(direct.api_keys === false && typeof direct.api_keys === 'boolean', 'api_keys boolean changed type');
    assert(direct.secrets_included === false && typeof direct.secrets_included === 'boolean', 'secrets_included boolean changed type');
    assert(direct.memory_content_included === false && typeof direct.memory_content_included === 'boolean', 'memory_content_included boolean changed type');
    assert(Array.isArray(direct.nested) && Array.isArray(direct.nested[0].values), 'shared sanitizer changed nested structure');
    assert(direct.content === '<redacted>', 'content field was not redacted');
    assert(direct.text === '<redacted>', 'text field was not redacted');
    assert(direct.memory_note === '<redacted>', 'memory_* string field was not redacted');
    assert(direct[MEMORY_CAMEL_KEY] === '<redacted>', 'camelCase memory string field was not redacted');
    assert(direct.memory_records.note === '<redacted>', 'nested memory_* object string was not redacted');
    assert(direct.memory_records.pin === '<redacted>', 'nested memory_* numeric scalar was not redacted');
    assert(direct.memory_records.active === true && typeof direct.memory_records.active === 'boolean', 'nested memory_* boolean changed type');
    assert(direct.memory_records.rows[0].summary === '<redacted>', 'deep memory_* object string was not redacted');
    assert(direct.memory_records.rows[0].active === false && typeof direct.memory_records.rows[0].active === 'boolean', 'deep memory_* boolean changed type');
    assert(direct.memory_records_array[0].note === '<redacted>', 'memory_* array object string was not redacted');
    assert(direct.memory_records_array[0].pin === '<redacted>', 'memory_* array numeric scalar was not redacted');
    assert(direct.memory_records_array[0].active === true && typeof direct.memory_records_array[0].active === 'boolean', 'memory_* array boolean changed type');
    assert(direct.memory_records_array[1][0] === '<redacted>', 'nested memory_* array string was not redacted');
    assert(direct.numeric_content_fields.content === '<redacted>', 'numeric content field was not redacted');
    assert(direct.numeric_content_fields.text === '<redacted>', 'numeric text field was not redacted');
    assert(direct.numeric_content_fields.memory_pin === '<redacted>', 'numeric memory_* field was not redacted');
    assert(direct.memory_governance.policy_summary === NORMAL_TEXT, 'safe memory governance metadata was over-redacted');
    assert(!Object.prototype.hasOwnProperty.call(direct, CLIENT_SECRET_KEY), 'clientSecret property name was not redacted');
    assert(!Object.prototype.hasOwnProperty.call(direct, PRIVATE_KEY_KEY), 'private_key property name was not redacted');
    assert(!Object.prototype.hasOwnProperty.call(direct, PRIVATE_KEY_MATERIAL_KEY), 'private_key_* property name was not redacted');
    assert(!Object.prototype.hasOwnProperty.call(direct, API_KEY_VALUE_KEY), 'apiKey* property name was not redacted');
    assert(!Object.prototype.hasOwnProperty.call(direct, CREDENTIALS_KEY), 'credentials property name was not redacted');
    assert(!Object.prototype.hasOwnProperty.call(direct, AUTHORIZATION_KEY), 'authorization property name was not redacted');
    assert(!Object.prototype.hasOwnProperty.call(direct, NUMERIC_TOKEN_KEY), 'numeric token property name was not redacted');
    assert(Object.keys(direct).filter((key) => key.startsWith('<redacted-key>')).length >= 7, 'sensitive property-key collisions were not preserved safely');
    assert(Object.keys(direct.sensitive_property_names).every((key) => key.startsWith('<redacted-key>')), 'secret/PII property names were not redacted');

    const debug = runExporter('export-debug-bundle.js', fixture, stateRoot);
    const debugArtifactPath = path.join(stateRoot, 'maintenance', 'debug-bundle.json');
    const debugArtifact = readJson(debugArtifactPath);
    const debugSerialized = fs.readFileSync(debugArtifactPath, 'utf8');
    assert(debug.parsed.ok === true, 'debug exporter did not report ok');
    assert(JSON.stringify(debug.parsed.bundle) === JSON.stringify(debugArtifact), 'debug stdout data differs from artifact');
    assertNoCanary(debug.parsed, debug.stdout, 'debug stdout/data');
    assertNoCanary(debugArtifact, debugSerialized, 'debug artifact');
    assertNormalTextSurvives(debug.parsed, 'debug stdout/data');
    assert(debugArtifact.includes.memory_content === false && typeof debugArtifact.includes.memory_content === 'boolean', 'debug memory_content flag changed type');
    assert(debugArtifact.includes.api_keys === false && typeof debugArtifact.includes.api_keys === 'boolean', 'debug api_keys flag changed type');
    assert(Array.isArray(debugArtifact.routing_bundle.privacy_export_probe.nested), 'debug nested array structure changed');

    const pro = runExporter('export-pro-snapshot.js', fixture, stateRoot);
    const proArtifactPath = path.join(stateRoot, 'maintenance', 'pro-inspector-snapshot.json');
    const proArtifact = readJson(proArtifactPath);
    const proSerialized = fs.readFileSync(proArtifactPath, 'utf8');
    assert(pro.parsed.ok === true, 'Pro exporter did not report ok');
    assert(JSON.stringify(pro.parsed.snapshot) === JSON.stringify(proArtifact), 'Pro stdout data differs from artifact');
    assertNoCanary(pro.parsed, pro.stdout, 'Pro stdout/data');
    assertNoCanary(proArtifact, proSerialized, 'Pro artifact');
    assertNormalTextSurvives(pro.parsed, 'Pro stdout/data');
    assert(proArtifact.provenance.secrets_included === false && typeof proArtifact.provenance.secrets_included === 'boolean', 'Pro secrets_included flag changed type');
    assert(proArtifact.provenance.memory_content_included === false && typeof proArtifact.provenance.memory_content_included === 'boolean', 'Pro memory_content_included flag changed type');
    assert(Array.isArray(proArtifact.repair_board.items[0].nested), 'Pro nested array structure changed');
    assert(Array.isArray(proArtifact.stale_items[0].nested), 'Pro stale nested array structure changed');

    const teamStateRoot = path.join(fixture, 'team-state');
    seedFixture(teamStateRoot);
    const teamDebug = runExporter('export-debug-bundle.js', fixture, teamStateRoot, { team: true });
    const teamDebugArtifact = readJson(path.join(teamStateRoot, 'maintenance', 'debug-bundle.json'));
    assert(teamDebug.parsed.output === '<stateRoot>/maintenance/debug-bundle.json', 'team debug output is not a safe logical path');
    assertNoFixturePath(teamDebug.parsed, fixture, 'team debug stdout/data');
    assertNoFixturePath({ stdout: teamDebug.stdout, stderr: teamDebug.stderr }, fixture, 'team debug process output');
    assertNoCanary(teamDebug.parsed, teamDebug.stdout, 'team debug stdout/data');
    assertNoCanary(teamDebugArtifact, JSON.stringify(teamDebugArtifact), 'team debug artifact');

    const teamPro = runExporter('export-pro-snapshot.js', fixture, teamStateRoot, { team: true });
    const teamProArtifact = readJson(path.join(teamStateRoot, 'maintenance', 'pro-inspector-snapshot.json'));
    assert(teamPro.parsed.output === '<stateRoot>/maintenance/pro-inspector-snapshot.json', 'team Pro output is not a safe logical path');
    assertNoFixturePath(teamPro.parsed, fixture, 'team Pro stdout/data');
    assertNoFixturePath({ stdout: teamPro.stdout, stderr: teamPro.stderr }, fixture, 'team Pro process output');
    assertNoCanary(teamPro.parsed, teamPro.stdout, 'team Pro stdout/data');
    assertNoCanary(teamProArtifact, JSON.stringify(teamProArtifact), 'team Pro artifact');

    report = {
      schema_version: systemVersion(),
      status: 'pass',
      checks: [
        'shared sanitizer nested objects and arrays',
        'token, opaque bearer, assignment, and key-aware secret redaction',
        'email identity and sensitive property-name redaction',
        'Windows, UNC, Linux, macOS, workspace, and tilde path redaction',
        'content, text, and memory_* field redaction',
        'harmless normal text preservation',
        'boolean schema type preservation, including nested memory containers',
        'debug artifact and stdout parity',
        'Pro artifact and stdout parity',
        'team-mode stdout path containment',
        'debug schema structure preservation',
        'Pro schema structure preservation'
      ],
      canary_classes: [
        'token-shaped',
        'opaque-authorization',
        'key-aware-secret',
        'email-identity',
        'sensitive-property-name',
        'absolute-local-user-path',
        'content-field',
        'numeric-sensitive-scalar',
        'harmless-control'
      ],
      fixture_cleaned: false
    };
  } finally {
    const resolved = path.resolve(fixture);
    const expectedPrefix = path.resolve(preferredTemp, 'knowledge-export-privacy-');
    if (!resolved.startsWith(expectedPrefix)) throw new Error(`Refusing unsafe self-test cleanup: ${resolved}`);
    fs.rmSync(resolved, { recursive: true, force: true });
    cleaned = !fs.existsSync(resolved);
    if (!cleaned) throw new Error(`Self-test fixture cleanup failed: ${resolved}`);
  }
  report.fixture_cleaned = cleaned;
  console.log(JSON.stringify(report, null, 2));
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exit(1);
}
