'use strict';

// Canonical package permissions are selected by the fixed runtime inventory,
// never copied from a source checkout's incidental or privileged mode bits.
function runtimeFileMode(relative) {
  const normalized = String(relative).replace(/\\/g, '/').replace(/^\.knowledge\//, '');
  return /^tools\/lib\/native\/linux-(?:x64|arm64)\/verification-linux-namespace$/.test(normalized)
    ? 0o755 : 0o644;
}

module.exports = { runtimeFileMode };
