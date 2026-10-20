'use strict';

// Export-boundary policy only. This module does not mutate canonical project
// state; it creates a deeply sanitized JSON-compatible copy before an exporter
// writes an artifact or returns data to stdout.

const PLACEHOLDERS = Object.freeze({
  sensitiveField: '<redacted>',
  sensitiveKey: '<redacted-key>',
  token: '<redacted-secret>',
  email: '<redacted-email>',
  localPath: '<local-path>',
  localUser: '<local-user>'
});

const DEFAULT_CONTENT_KEYS = new Set(['content', 'text', 'memory_body', 'memory_content']);
const PRESERVED_BOOLEAN_KEYS = new Set([
  'api_keys',
  'install_receipts',
  'memory_content',
  'memory_content_included',
  'runtime_databases',
  'secrets_included'
]);
const PRESERVED_SCHEMA_KEYS = new Set(PRESERVED_BOOLEAN_KEYS);
const SAFE_MEMORY_METADATA_CONTAINERS = new Set(['memory_governance']);
const SENSITIVE_KEY_WORDS = new Set([
  'authorization',
  'credential',
  'credentials',
  'password',
  'passwd',
  'pwd',
  'secret',
  'token'
]);
const SENSITIVE_COMPOUND_KEYS = new Set([
  'apikey',
  'apikeys',
  'authheader',
  'authtoken',
  'clientsecret',
  'privatekey',
  'accesskey',
  'accesstoken',
  'refreshtoken'
]);

const TOKEN_PATTERNS = Object.freeze([
  /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g,
  /\b(?:pcsk|m0sk|pk)[A-Za-z0-9_./+=-]{12,}\b/g,
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  /\bxox[abrsp]-[A-Za-z0-9-]{10,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\bBasic\s+[A-Za-z0-9+/=]{8,}/gi,
  /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g
]);

const EMAIL_IDENTITY = /\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\b/gi;
const WINDOWS_ABSOLUTE_PATH = /\b[A-Za-z]:(?:\\\\|[\\/])[^\r\n"',}\]]+/g;
const WINDOWS_UNC_PATH = /\\\\[^\\\r\n"',}\]]+(?:\\[^\r\n"',}\]]+)+/g;
const POSIX_LOCAL_PATH = /(^|[\s"'=:(])\/(?:Users|home|root|workspace|private\/var|var\/folders|mnt\/[A-Za-z]\/Users|mnt\/data|tmp)(?:\/[^\s"',}\]]*)?/gi;
const HOME_RELATIVE_PATH = /(^|[\s"'=:(])~\/[^\s"',}\]]+/g;
const RELATIVE_USER_IDENTITY = /Users(?:\\\\|[\\/])[^\\/\s"',}\]]+/gi;
const SENSITIVE_ASSIGNMENT_NAME = '(?:api[_-]?key|client[_-]?secret|private[_-]?key|credentials?|authorization|secret|token|password|passwd|pwd)';
const DOUBLE_QUOTED_SECRET_ASSIGNMENT = new RegExp(`(${SENSITIVE_ASSIGNMENT_NAME}\\s*["']?\\s*[:=]\\s*")(?!<redacted)(?:\\\\.|[^"\\\\])*"`, 'gi');
const SINGLE_QUOTED_SECRET_ASSIGNMENT = new RegExp(`(${SENSITIVE_ASSIGNMENT_NAME}\\s*["']?\\s*[:=]\\s*')(?!<redacted)(?:\\\\.|[^'\\\\])*'`, 'gi');
const UNQUOTED_SECRET_ASSIGNMENT = new RegExp(`(${SENSITIVE_ASSIGNMENT_NAME}\\s*["']?\\s*[:=]\\s*)(?!["'<])[^,;\\r\\n}\\]]+`, 'gi');
const AWS_SECRET_ASSIGNMENT = /(aws_secret_access_key\s*[:=]\s*["']?)[A-Za-z0-9/+]{40}(["']?)/gi;

function keyWords(value) {
  return String(value)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function isSensitiveKey(value) {
  const words = keyWords(value);
  if (words.some((word) => SENSITIVE_KEY_WORDS.has(word))) return true;
  const compact = words.join('');
  return SENSITIVE_COMPOUND_KEYS.has(compact)
    || words.some((word) => SENSITIVE_COMPOUND_KEYS.has(word))
    || words.some((word, index) => SENSITIVE_COMPOUND_KEYS.has(`${word}${words[index + 1] || ''}`));
}

function sanitizeExportString(value, options = {}) {
  let out = String(value);

  for (const pattern of TOKEN_PATTERNS) out = out.replace(pattern, PLACEHOLDERS.token);
  out = out
    .replace(AWS_SECRET_ASSIGNMENT, `$1${PLACEHOLDERS.token}$2`)
    .replace(DOUBLE_QUOTED_SECRET_ASSIGNMENT, `$1${PLACEHOLDERS.sensitiveField}"`)
    .replace(SINGLE_QUOTED_SECRET_ASSIGNMENT, `$1${PLACEHOLDERS.sensitiveField}'`)
    .replace(UNQUOTED_SECRET_ASSIGNMENT, `$1${PLACEHOLDERS.sensitiveField}`)
    .replace(EMAIL_IDENTITY, PLACEHOLDERS.email)
    .replace(WINDOWS_ABSOLUTE_PATH, PLACEHOLDERS.localPath)
    .replace(WINDOWS_UNC_PATH, PLACEHOLDERS.localPath)
    .replace(POSIX_LOCAL_PATH, `$1${PLACEHOLDERS.localPath}`)
    .replace(HOME_RELATIVE_PATH, `$1${PLACEHOLDERS.localPath}`)
    .replace(RELATIVE_USER_IDENTITY, `Users\\${PLACEHOLDERS.localUser}`);

  if (options.redactWorkspaceName) {
    out = out.replace(new RegExp(`knowledge${'-'}kit`, 'gi'), 'workspace');
  }
  return out;
}

function normalizeContentKeys(value) {
  if (value === true) return DEFAULT_CONTENT_KEYS;
  if (!value) return new Set();
  return new Set(Array.from(value, (item) => String(item).toLowerCase()));
}

function sanitizeExportValue(value, options = {}) {
  const contentKeys = normalizeContentKeys(options.redactContentFields);

  function visit(item, key = '', forceRedactStrings = false) {
    const lowerKey = String(key).toLowerCase();
    const sensitiveKey = isSensitiveKey(key);
    const exactContentKey = contentKeys.has(lowerKey);
    const memoryStringKey = Boolean(options.redactContentFields)
      && (lowerKey.startsWith('memory_') || keyWords(key)[0] === 'memory');
    const redactByKey = forceRedactStrings || sensitiveKey || exactContentKey || memoryStringKey;
    const propagateRedaction = forceRedactStrings
      || sensitiveKey
      || exactContentKey
      || (memoryStringKey && !SAFE_MEMORY_METADATA_CONTAINERS.has(lowerKey));

    if (typeof item === 'string') {
      if (redactByKey && item) return PLACEHOLDERS.sensitiveField;
      return sanitizeExportString(item, options);
    }
    if (typeof item === 'number' || typeof item === 'bigint') {
      return redactByKey ? PLACEHOLDERS.sensitiveField : item;
    }
    if (typeof item === 'boolean') {
      // Booleans carry state, not credential material. Preserve their type
      // even inside a redacted content/credential container.
      return item;
    }
    if (Array.isArray(item)) {
      return item.map((entry) => visit(entry, '', propagateRedaction));
    }
    if (item && typeof item === 'object') {
      const out = {};
      for (const [childKey, childValue] of Object.entries(item)) {
        const keyText = sanitizeExportString(childKey, options);
        const preserveSchemaKey = PRESERVED_SCHEMA_KEYS.has(String(childKey).toLowerCase());
        const baseKey = keyText !== childKey || (isSensitiveKey(childKey) && !preserveSchemaKey)
          ? PLACEHOLDERS.sensitiveKey
          : keyText;
        let safeKey = baseKey;
        let collision = 2;
        while (Object.prototype.hasOwnProperty.call(out, safeKey)) {
          safeKey = `${baseKey}#${collision}`;
          collision += 1;
        }
        Object.defineProperty(out, safeKey, {
          value: visit(childValue, childKey, propagateRedaction),
          enumerable: true,
          configurable: true,
          writable: true
        });
      }
      return out;
    }
    // Null/undefined do not carry a secret payload and retain their JSON shape.
    return item;
  }

  return visit(value);
}

module.exports = {
  PLACEHOLDERS,
  isSensitiveKey,
  sanitizeExportString,
  sanitizeExportValue
};
