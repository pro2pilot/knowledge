'use strict';

const crypto = require('crypto');

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function signingPayload(manifest) {
  const { signature, ...body } = manifest;
  return Buffer.from(canonicalJson(body), 'utf8');
}

function validateExtension(manifest, bytes, entitlementState, coreVersion, trustedKeys = {}) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return ['missing_manifest'];
  const errors = [];
  const safeId = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/;
  if (typeof manifest.extension_id !== 'string' || !safeId.test(manifest.extension_id) || manifest.extension_id.includes('..')) errors.push('invalid_extension_id');
  if (typeof manifest.version !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)?$/.test(manifest.version)) errors.push('invalid_extension_version');
  if (!['stable', 'beta', 'internal'].includes(manifest.channel)) errors.push('invalid_channel');
  if (!Array.isArray(manifest.core_versions) || !manifest.core_versions.includes(coreVersion)) errors.push('incompatible_core_version');
  if (manifest.sha256 !== crypto.createHash('sha256').update(bytes).digest('hex')) errors.push('sha256_mismatch');
  const entitlements = Array.isArray(entitlementState?.entitlements) ? entitlementState.entitlements : [];
  if (!Array.isArray(manifest.entitlements_required) || !manifest.entitlements_required.every((item) => typeof item === 'string')) {
    errors.push('invalid_entitlements_required');
  } else for (const required of manifest.entitlements_required) {
    if (!entitlements.includes(required)) errors.push(`missing_entitlement:${required}`);
  }
  if (['beta', 'internal'].includes(manifest.channel) && !entitlements.includes(`${manifest.channel}_channel`)) {
    errors.push(`channel_not_allowed:${manifest.channel}`);
  }
  const signature = typeof manifest.signature === 'string' ? /^ed25519:([A-Za-z0-9+/]{86}==)$/.exec(manifest.signature) : null;
  if (!signature) errors.push('missing_or_invalid_signature');
  else if (!trustedKeys || typeof trustedKeys !== 'object' || Array.isArray(trustedKeys) || typeof manifest.key_id !== 'string' || !Object.prototype.hasOwnProperty.call(trustedKeys, manifest.key_id)) {
    errors.push('untrusted_signing_key');
  } else {
    try {
      const key = crypto.createPublicKey(trustedKeys[manifest.key_id]);
      const decoded = Buffer.from(signature[1], 'base64');
      if (decoded.toString('base64') !== signature[1] || key.asymmetricKeyType !== 'ed25519' ||
          !crypto.verify(null, signingPayload(manifest), key, decoded)) errors.push('signature_verification_failed');
    } catch { errors.push('signature_verification_failed'); }
  }
  return errors;
}

module.exports = { signingPayload, validateExtension };
