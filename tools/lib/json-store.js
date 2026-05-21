'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

function stripBom(value) {
  return typeof value === 'string' && value.charCodeAt(0) === 0xfeff ? value.slice(1) : value;
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function sleepSync(ms) {
  const buffer = new SharedArrayBuffer(4);
  const view = new Int32Array(buffer);
  Atomics.wait(view, 0, 0, ms);
}

function readJson(filePath, fallback) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(stripBom(raw));
  } catch (error) {
    if (arguments.length >= 2 && (error.code === 'ENOENT' || error instanceof SyntaxError)) return fallback;
    throw error;
  }
}

function writeJsonAtomic(filePath, value, options = {}) {
  ensureDir(path.dirname(filePath));
  const tmpPath = `${filePath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const body = JSON.stringify(value, null, 2) + '\n';
  if (options.backup && fs.existsSync(filePath)) {
    const backupPath = `${filePath}.bak-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    fs.copyFileSync(filePath, backupPath);
  }
  fs.writeFileSync(tmpPath, body, 'utf8');
  fs.renameSync(tmpPath, filePath);
}

function writeFileAtomic(filePath, body, options = {}) {
  ensureDir(path.dirname(filePath));
  const tmpPath = `${filePath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  if (options.backup && fs.existsSync(filePath)) {
    const backupPath = `${filePath}.bak-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    fs.copyFileSync(filePath, backupPath);
  }
  fs.writeFileSync(tmpPath, body, 'utf8');
  fs.renameSync(tmpPath, filePath);
}

function updateJsonAtomic(filePath, updater, fallback = {}) {
  const current = readJson(filePath, fallback);
  const next = updater(current) || current;
  writeJsonAtomic(filePath, next);
  return next;
}

function removeDirRecursive(dirPath) {
  fs.rmSync(dirPath, { recursive: true, force: true });
}

function acquireLock(lockDir, options = {}) {
  const timeoutMs = Number(options.timeoutMs || process.env.KNOWLEDGE_LOCK_TIMEOUT_MS || 30000);
  const staleMs = Number(options.staleMs || process.env.KNOWLEDGE_LOCK_STALE_MS || 120000);
  const retryMs = Number(options.retryMs || 100);
  const started = Date.now();
  const owner = {
    pid: process.pid,
    hostname: os.hostname(),
    agent_id: process.env.KNOWLEDGE_AGENT_ID || null,
    started_at: new Date().toISOString(),
    cwd: process.cwd()
  };

  ensureDir(path.dirname(lockDir));
  while (true) {
    try {
      fs.mkdirSync(lockDir);
      writeJsonAtomic(path.join(lockDir, 'owner.json'), owner);
      return () => removeDirRecursive(lockDir);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      try {
        const stat = fs.statSync(lockDir);
        if (Date.now() - stat.mtimeMs > staleMs) {
          removeDirRecursive(lockDir);
          continue;
        }
      } catch {
        continue;
      }
      if (Date.now() - started > timeoutMs) {
        let ownerText = '';
        try { ownerText = fs.readFileSync(path.join(lockDir, 'owner.json'), 'utf8'); } catch {}
        const details = ownerText ? ` Existing owner: ${ownerText}` : '';
        throw new Error(`Timed out waiting for knowledge lock at ${lockDir}.${details}`);
      }
      sleepSync(retryMs);
    }
  }
}

function withLock(lockDir, fn, options = {}) {
  const release = acquireLock(lockDir, options);
  try {
    return fn();
  } finally {
    release();
  }
}

function getAgentId() {
  return process.env.KNOWLEDGE_AGENT_ID || `${os.hostname()}-${process.pid}`;
}

function appendNdjson(filePath, event) {
  ensureDir(path.dirname(filePath));
  fs.appendFileSync(filePath, JSON.stringify(event) + '\n', 'utf8');
}

function normalizeRelative(filePath) {
  return String(filePath || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

module.exports = {
  stripBom,
  ensureDir,
  readJson,
  writeJsonAtomic,
  writeFileAtomic,
  updateJsonAtomic,
  acquireLock,
  withLock,
  appendNdjson,
  normalizeRelative,
  getAgentId,
  sleepSync
};
