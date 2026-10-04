'use strict';

// IDs become directory or file names in several public CLIs. Validate the
// original value instead of sanitizing it: two different IDs must never map
// silently to the same workspace/session, on either Windows or POSIX.
function assertSafePathSegment(value, label = 'identifier') {
  const invalid = typeof value !== 'string' || !value || value.length > 128 ||
    value === '.' || value === '..' ||
    /[\\/\u0000-\u001f\u007f<>:"|?*]/u.test(value) || /[. ]$/u.test(value) ||
    /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(value);
  if (invalid) {
    const error = new Error(`${label} must be a non-empty, safe path segment (maximum 128 characters).`);
    error.code = 'path_segment_invalid';
    throw error;
  }
  return value;
}

module.exports = { assertSafePathSegment };
