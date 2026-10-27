'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { readJson, writeJsonAtomicContained, ensureContainedDir, assertSafeContainedPath, containedPath } = require('./json-store');
const { withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');
const { copyInertData } = require('./json-transaction');

const SCHEMA = 'knowledge-recording-blockers.v1';
const secret = /\b(?:(?:sk|pk)(?=[_-])|ghp|github_pat|m0sk|pcsk|eyJ)[A-Za-z0-9_./+=-]{18,}\b/;
const OVERRIDE_REASON_CODE = 'user_confirmed_non_secret_repository_path';
const secretAssignment = /\b(?:api[_-]?key|secret|token|password|authorization|private[_-]?key)\s*[:=]\s*["']?[^\s,;"']+/i;
const sha = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
function storePath(context) { return path.join(context.stateRoot, 'maintenance', 'recording_blockers.json'); }
function read(context) {
  const file = storePath(context);
  assertSafeContainedPath(context.stateRoot, file, { allowMissing: true });
  if (fs.existsSync(file) && Number(fs.lstatSync(file).nlink || 1) > 1) throw Object.assign(new Error('Hardlinked recording registry.'), { code: 'recording_registry_unsafe' });
  const value = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '')) : { schema_version: SCHEMA, blockers: [], overrides: [] };
  if (value.schema_version !== SCHEMA || !Array.isArray(value.blockers) || !Array.isArray(value.overrides)) {
    throw Object.assign(new Error('Invalid recording blocker registry.'), { code: 'recording_registry_invalid' });
  }
  return value;
}
function mutate(context, fn) {
  return withContainedLock({ context, rootKind: 'state', rootPath: context.stateRoot,
    lockName: 'recording-blockers', purpose: LOCKS['recording-blockers'].purpose }, () => {
    const data = read(context);
    const result = fn(data);
    if (result.status !== 'rejected') {
      ensureContainedDir(context.stateRoot, path.dirname(storePath(context)));
      writeJsonAtomicContained(storePath(context), data, context.stateRoot);
    }
    return result;
  });
}
function fingerprint(context, value) { return sha(`${path.resolve(context.targetRoot)}\0${String(value)}`); }
function repositoryPath(context, value) {
  if (typeof value !== 'string' || !value || path.isAbsolute(value) || /^[a-z]:/i.test(value) ||
      value.includes('\0') || value.split(/[\\/]/).includes('..') || !/[./\\]/.test(value)) return false;
  try {
    const file = path.resolve(context.targetRoot, value);
    assertSafeContainedPath(context.targetRoot, file);
    const stat = fs.lstatSync(file);
    return !stat.isSymbolicLink() && Number(stat.nlink || 1) === 1 &&
      stat.isFile() && containedPath(context.targetRoot, fs.realpathSync(file));
  } catch { return false; }
}
function language(context, supplied, fallback = 'en') {
  const clean = (value) => { const code = String(value || '').toLowerCase().split(/[-_]/)[0]; return /^[a-z]{2,3}$/.test(code) ? code : 'en'; };
  if (supplied) return clean(supplied);
  const profile = readJson(path.join(context.projectKnowledgeRoot || context.stateRoot, 'settings', 'operator-profile.json'), {});
  return clean(profile.preferred_language || profile.language || process.env.KNOWLEDGE_USER_LANGUAGE || fallback);
}
function safeField(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9_$.[\]-]{1,160}$/.test(value) && !secret.test(value) ? value : 'task_record';
}
function publicId(value, prefix) {
  return typeof value === 'string' && value.startsWith(prefix + '-') && /^(?:RB|EX|ATW)-[a-f0-9]{64}$/.test(value) ? value : null;
}
function publicTime(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value)) ? value : null;
}
function notice(row, lang) {
  const reason = row.kind === 'user_scope' ? 'blocked_by_user_scope' : 'suspected_secret';
  const field = safeField(row.field), preview = row.kind === 'user_scope' ? '.knowledge' : '********';
  if (lang === 'ru') return `Запись ${field} (${preview}) заблокирована: ${reason === 'blocked_by_user_scope' ? 'границы записи, заданные пользователем, исключают .knowledge' : 'значение распознано как возможный секрет'}. ${row.kind === 'user_scope' ? 'Нужна явная корректировка границ записи пользователем.' : 'Если это не секрет, сообщите об этом в чате или выберите нужное действие в Inspector.'}`;
  return `Recording ${field} (${preview}) is blocked because ${reason === 'blocked_by_user_scope' ? 'the user write boundary excludes .knowledge' : 'the value was identified as a possible secret'}. ${row.kind === 'user_scope' ? 'The user must explicitly change the write boundary.' : 'If this is not a secret, say so in chat or choose an action in Inspector.'}`;
}
function publicRow(row, lang) {
  // Persisted state is not a safe display contract. Project known typed fields;
  // raw previews and extensions may contain old private values and stay local.
  const kind = row.kind === 'user_scope' ? 'user_scope' : 'suspected_secret';
  const out = { id: publicId(row.id, 'RB'), kind, field: safeField(row.field),
    status: row.status === 'resolved' ? 'resolved' : 'blocked',
    preview: kind === 'user_scope' ? '.knowledge' : '********',
    reason: kind === 'user_scope' ? 'blocked_by_user_scope' : 'suspected_secret',
    session_id: publicId(row.session_id, 'ATW'), created_at: publicTime(row.created_at),
    allowed_actions: kind === 'suspected_secret' && Array.isArray(row.allowed_actions)
      ? [...new Set(row.allowed_actions.filter(action => ['once', 'project'].includes(action)))] : [],
    ...(publicId(row.override_id, 'EX') ? { override_id: row.override_id } : {}) };
  return { ...out, chat_notice: notice(out, lang), notice_language: lang === 'ru' ? 'ru' : 'en',
    translate_to_user_language: !['ru', 'en'].includes(lang) };
}
function registerBlocker(context, input) {
  const kind = input.kind === 'user_scope' ? 'user_scope' : 'suspected_secret';
  const field = safeField(input.field);
  const classifiableField = field === input.field && !/(api[_-]?key|secret|token|password|authorization|private[_-]?key)/i.test(field);
  const sessionId = /^ATW-[a-f0-9]{64}$/.test(String(input.session_id)) ? String(input.session_id) : null;
  const valueHash = fingerprint(context, input.value || kind);
  const id = `RB-${sha(`${kind}:${field}:${sessionId || ''}:${valueHash}`)}`;
  return mutate(context, (data) => {
    let row = data.blockers.find((item) => item.id === id);
    if (!row) {
      row = { id, kind, field, status: 'blocked', preview: kind === 'user_scope' ? '.knowledge' : '********',
        reason: kind === 'user_scope' ? 'blocked_by_user_scope' : 'suspected_secret',
        value_sha256: valueHash, session_id: sessionId, created_at: new Date().toISOString(),
        allowed_actions: kind === 'suspected_secret' && classifiableField && repositoryPath(context, input.value) ? (sessionId ? ['once', 'project'] : ['project']) : [] };
      data.blockers.push(row);
    } else row.status = 'blocked';
    const lang = language(context, input.language, data.language || 'en');
    if (input.language) data.language = lang;
    return { status: 'ok', blocker: publicRow(row, lang), chat_notice: notice(row, lang) };
  });
}
function listBlockers(context) {
  const data = read(context), lang = language(context, null, data.language || 'en');
  const blockers = data.blockers.map(row => publicRow(row, lang));
  return { status: 'ok', language: lang, blockers,
    overrides: data.overrides.map(row => {
      const blocker = blockers.find(item => item.id === row.blocker_id);
      return { id: publicId(row.id, 'EX'), blocker_id: publicId(row.blocker_id, 'RB'),
        status: row.status === 'active' ? 'active' : 'revoked', kind: 'repository_path',
        scope: ['once', 'project'].includes(row.scope) ? row.scope : null,
        session_id: publicId(row.session_id, 'ATW'), reason: OVERRIDE_REASON_CODE,
        confirmed_at: publicTime(row.confirmed_at),
        ...(row.revoked_at !== undefined ? { revoked_at: publicTime(row.revoked_at) } : {}),
        field: blocker?.field || 'task_record', preview: blocker?.preview || '********', created_at: publicTime(row.confirmed_at) };
    }) };
}
function resolveBlocker(context, input) {
  if (input.confirmed !== true) return { status: 'rejected', reason: 'explicit_confirmation_required' };
  if (!['once', 'project'].includes(input.scope)) return { status: 'rejected', reason: 'invalid_scope' };
  if (typeof input.reason !== 'string' || !input.reason.trim() || input.reason.length > 500 ||
      secret.test(input.reason) || secretAssignment.test(input.reason) || require('./repair-on-touch').secretPaths(input.reason).length) {
    return { status: 'rejected', reason: 'safe_reason_required' };
  }
  return mutate(context, (data) => {
    const row = data.blockers.find((item) => item.id === input.id);
    if (!row || row.status !== 'blocked') return { status: 'rejected', reason: 'blocker_not_open' };
    if (!row.allowed_actions.includes(input.scope) || row.kind !== 'suspected_secret') return { status: 'rejected', reason: 'blocker_not_overridable' };
    const override = { id: `EX-${sha(crypto.randomBytes(32))}`, blocker_id: row.id, status: 'active',
      kind: 'repository_path', scope: input.scope, value_sha256: row.value_sha256,
      session_id: input.scope === 'once' ? row.session_id : null,
      reason: OVERRIDE_REASON_CODE, confirmed_at: new Date().toISOString() };
    data.overrides.push(override); row.status = 'resolved'; row.override_id = override.id;
    return { status: 'ok', override_id: override.id, scope: input.scope, retry_required: true };
  });
}
function revokeOverride(context, input) {
  if (input.confirmed !== true) return { status: 'rejected', reason: 'explicit_confirmation_required' };
  return mutate(context, (data) => {
    const item = data.overrides.find((row) => row.id === input.id && row.status === 'active');
    if (!item) return { status: 'rejected', reason: 'override_not_active' };
    item.status = 'revoked'; item.revoked_at = new Date().toISOString();
    const row = data.blockers.find((row) => row.id === item.blocker_id);
    if (row) row.status = 'blocked';
    return { status: 'ok', override_id: item.id };
  });
}
function approvedRepositoryPath(context, value, sessionId) {
  if (!repositoryPath(context, value)) return false;
  const valueHash = fingerprint(context, value);
  return read(context).overrides.some((row) => row.status === 'active' && row.kind === 'repository_path' &&
    row.value_sha256 === valueHash && (row.scope === 'project' ||
      (row.scope === 'once' && sessionId && row.session_id === sessionId)));
}
const admit = fn => (...args) => {
  const clean = [];
  // Admit both data and context before field inspection, filesystem reads,
  // locks or writes. This also rejects revoked proxies without running traps.
  for (let index = 0; index < args.length; index++) clean[index] = copyInertData(args[index]);
  return fn(...clean);
};
module.exports = { SCHEMA, OVERRIDE_REASON_CODE,
  registerBlocker: admit(registerBlocker), listBlockers: admit(listBlockers), resolveBlocker: admit(resolveBlocker),
  revokeOverride: admit(revokeOverride), approvedRepositoryPath: admit(approvedRepositoryPath),
  repositoryPath: admit(repositoryPath), notice: admit(notice), language: admit(language) };
