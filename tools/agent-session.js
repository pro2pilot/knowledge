#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const { ensureDir, readJson, writeJsonAtomic, appendNdjson } = require('./lib/json-store');

function nowIso() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function sessionsDir(context) {
  return path.join(context.stateRoot, 'sessions', 'agents');
}

function registryPath(context) {
  return path.join(context.stateRoot, 'sessions', 'agent-registry.json');
}

function eventsPath(context) {
  return path.join(context.stateRoot, 'events', `${nowIso().slice(0, 10)}.ndjson`);
}

function sessionFromFlags(context, flags, existing = {}) {
  const runtimeId = flags.runtime || flags.agentRuntimeId || process.env.KNOWLEDGE_AGENT_RUNTIME_ID || existing.agent_runtime_id || 'unknown-agent';
  const instanceId = flags.instance || flags.agentInstanceId || process.env.KNOWLEDGE_AGENT_INSTANCE_ID || existing.agent_instance_id || `${runtimeId}-${process.pid}`;
  return {
    schema_version: 'knowledge-agent-session.v1',
    operator_id: flags.operator || flags.operatorId || process.env.KNOWLEDGE_OPERATOR_ID || existing.operator_id || 'local-operator',
    operator_email: flags.operatorEmail || process.env.KNOWLEDGE_OPERATOR_EMAIL || existing.operator_email || null,
    agent_runtime_id: runtimeId,
    agent_runtime_label: flags.runtimeLabel || existing.agent_runtime_label || runtimeId,
    agent_instance_id: instanceId,
    agent_display_name: flags.displayName || existing.agent_display_name || instanceId,
    session_id: flags.sessionId || process.env.KNOWLEDGE_SESSION_ID || existing.session_id || id('sess'),
    run_id: flags.runId || process.env.KNOWLEDGE_RUN_ID || existing.run_id || id('run'),
    task_id: flags.taskId || process.env.KNOWLEDGE_TASK_ID || existing.task_id || null,
    workspace_id: flags.workspaceId || process.env.KNOWLEDGE_WORKSPACE_ID || context.workspaceId || existing.workspace_id || 'repo',
    branch: flags.branch || context.branch || existing.branch || 'unknown',
    status: flags.status || existing.status || 'running',
    started_at: existing.started_at || nowIso(),
    last_heartbeat_at: nowIso(),
    finished_at: existing.finished_at || null
  };
}

function writeSession(context, session) {
  ensureDir(sessionsDir(context));
  const file = path.join(sessionsDir(context), `${session.session_id}.json`);
  writeJsonAtomic(file, session);
  const registry = readJson(registryPath(context), { schema_version: 'knowledge-agent-registry.v1', sessions: [] });
  const sessions = (registry.sessions || []).filter((item) => item.session_id !== session.session_id);
  sessions.push(session);
  writeJsonAtomic(registryPath(context), { ...registry, updated_at: nowIso(), sessions });
  appendNdjson(eventsPath(context), { type: 'agent_session', at: nowIso(), session_id: session.session_id, status: session.status, agent_instance_id: session.agent_instance_id });
  return file;
}

function findSession(context, flags) {
  const registry = readJson(registryPath(context), { sessions: [] });
  const sessionId = flags.sessionId || process.env.KNOWLEDGE_SESSION_ID;
  if (sessionId) return registry.sessions.find((item) => item.session_id === sessionId) || null;
  const instance = flags.instance || flags.agentInstanceId || process.env.KNOWLEDGE_AGENT_INSTANCE_ID;
  if (instance) return [...registry.sessions].reverse().find((item) => item.agent_instance_id === instance && item.status !== 'done') || null;
  return [...registry.sessions].reverse().find((item) => item.status === 'running') || null;
}

function report(context) {
  const registry = readJson(registryPath(context), { schema_version: 'knowledge-agent-registry.v1', sessions: [] });
  const sessions = registry.sessions || [];
  return {
    ok: true,
    schema_version: 'knowledge-agent-activity-report.v1',
    generated_at: nowIso(),
    active_sessions: sessions.filter((item) => ['running', 'waiting'].includes(item.status)),
    recent_sessions: sessions.slice(-25),
    registry_path: 'sessions/agent-registry.json'
  };
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const command = parsed.positional[0] || 'report';
  const context = resolveKnowledgeContext({ ...parsed.flags, workspaceId: null, __skipCli: true });
  let result;
  if (command === 'start') {
    const session = sessionFromFlags(context, parsed.flags, { status: 'running' });
    writeSession(context, session);
    result = { ok: true, command, session };
  } else if (command === 'heartbeat') {
    const existing = findSession(context, parsed.flags) || {};
    const session = sessionFromFlags(context, parsed.flags, { ...existing, status: existing.status || 'running' });
    writeSession(context, session);
    result = { ok: true, command, session };
  } else if (command === 'finish') {
    const existing = findSession(context, parsed.flags) || {};
    const session = sessionFromFlags(context, parsed.flags, { ...existing, status: parsed.flags.status || 'done' });
    session.status = parsed.flags.status || 'done';
    session.finished_at = nowIso();
    writeSession(context, session);
    result = { ok: true, command, session };
  } else if (command === 'report') {
    result = report(context);
  } else {
    throw new Error(`Unknown agent-session command: ${command}`);
  }
  if (parsed.flags.json || true) console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = { main, report };
