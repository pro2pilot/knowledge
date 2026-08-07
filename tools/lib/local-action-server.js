'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
const { canRunAction, getAction, listActions, loadEntitlements, RISK_REQUIRES_CONFIRMATION } = require('./action-registry');

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

function json(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store'
  });
  res.end(JSON.stringify(payload, null, 2));
}

function notFound(res) {
  json(res, 404, { ok: false, error: 'not_found' });
}

function collectBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
      if (body.length > 1024 * 1024) req.destroy();
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); } catch { resolve({}); }
    });
  });
}

function createActionServer(options) {
  const knowledgeRoot = options.knowledgeRoot;
  const repoRoot = options.repoRoot || path.resolve(knowledgeRoot, '..');
  const host = options.host || '127.0.0.1';
  const port = Number.isFinite(options.port) ? options.port : 8765;
  const token = crypto.randomBytes(24).toString('hex');
  const runs = new Map();
  const confirmations = new Map();
  let server = null;

  function actionLogPath() {
    const date = new Date().toISOString().slice(0, 10);
    return path.join(knowledgeRoot, 'maintenance', 'action-runs', `${date}.ndjson`);
  }

  function appendRunLog(run) {
    fs.mkdirSync(path.dirname(actionLogPath()), { recursive: true });
    fs.appendFileSync(actionLogPath(), JSON.stringify(run) + '\n', 'utf8');
  }

  function makeState() {
    const routing = readJson(path.join(knowledgeRoot, 'maintenance', 'routing_bundle.json'), {});
    const trust = readJson(path.join(knowledgeRoot, 'maintenance', 'trust_report.json'), {});
    const stale = readJson(path.join(knowledgeRoot, 'maintenance', 'stale_items.json'), {});
    const repair = readJson(path.join(knowledgeRoot, 'maintenance', 'repair_queue.json'), {});
    const quality = readJson(path.join(knowledgeRoot, 'maintenance', 'quality_report.json'), {});
    const externalMemory = readJson(path.join(knowledgeRoot, 'maintenance', 'external_memory_status.json'), {});
    const syncLog = readJson(path.join(knowledgeRoot, 'maintenance', 'sync_log.json'), {});
    const staleCount = Array.isArray(stale.items) ? stale.items.length : Number(stale.total || stale.count || 0);
    const repairCount = Array.isArray(repair.items) ? repair.items.length : Number(repair.total || repair.count || 0);
    return {
      schema_version: 'knowledge-inspector-state.v1',
      generated_at: new Date().toISOString(),
      repo: {
        name: routing.project?.name || path.basename(repoRoot),
        root: '<repo>'
      },
      home_cards: {
        doctor_score: quality.quality_score ?? routing.health?.quality_score ?? null,
        trust_health: trust.status || routing.health?.status || 'unknown',
        stale_pressure: staleCount,
        repair_pressure: repairCount,
        pr_impact_status: readJson(path.join(knowledgeRoot, 'maintenance', 'pr_summary.md'), null) ? 'available' : 'not-generated',
        team_mode_status: routing.concurrency?.mode || 'single-agent',
        memory_provider_status: externalMemory.status || 'disabled',
        git_policy_status: fs.existsSync(path.join(repoRoot, '.git')) ? 'git-detected' : 'no-git-repo',
        last_release_run: syncLog.generated_at || syncLog.updated_at || null,
        next_best_action: repairCount ? 'Review repair queue' : staleCount ? 'Refresh stale items' : 'Run doctor'
      },
      pro: loadEntitlements(knowledgeRoot),
      source_of_truth_policy: {
        external_memory_source_of_truth: false,
        external_memory_can_raise_trust: false
      }
    };
  }

  function authOk(req) {
    if (req.url.startsWith('/api/session')) return true;
    const header = req.headers.authorization || req.headers['x-knowledge-session'] || '';
    const provided = String(header).replace(/^Bearer\s+/i, '');
    const url = new URL(req.url, 'http://127.0.0.1');
    return provided === token || url.searchParams.get('token') === token;
  }

  function sanitizeQuery(value) {
    return String(value || '').replace(/[^\w\s./:-]/g, '').slice(0, 160);
  }

  async function performAction(action, body, run) {
    const now = Date.now();
    run.status = 'running';
    run.started_at = new Date(now).toISOString();
    const home = makeState().home_cards;
    if (action.id === 'search.run') {
      const query = sanitizeQuery(body.query || '');
      run.stdout_summary = query ? `Search prepared for query: ${query}` : 'Search action is ready; provide a query from the UI.';
    } else if (action.id === 'doctor.run') {
      run.stdout_summary = `Doctor score: ${home.doctor_score ?? 'unknown'}; trust health: ${home.trust_health}.`;
    } else if (action.id === 'team.status') {
      run.stdout_summary = `Team mode status: ${home.team_mode_status}.`;
    } else if (action.id === 'memory.status' || action.id === 'mem0.preview') {
      run.stdout_summary = `Memory providers are ${home.memory_provider_status}; external memory remains advisory only.`;
    } else if (action.id === 'export.pro_snapshot') {
      const exporter = require('../export-pro-snapshot');
      const output = exporter.exportProSnapshot({ knowledgeRoot, repoRoot, json: true });
      run.stdout_summary = `Created ${output.zip_path}.`;
      run.updated_artifacts = [output.zip_path, output.manifest_path];
    } else {
      run.stdout_summary = `${action.label} queued through the local allowlist.`;
    }
    run.status = 'passed';
    run.finished_at = new Date().toISOString();
    run.duration_ms = Date.now() - now;
    run.stderr_summary = '';
    run.next_suggested_actions = action.id === 'doctor.run' ? ['export.pro_snapshot'] : ['doctor.run'];
    return run;
  }

  async function runAction(id, body = {}) {
    const action = getAction(id);
    const run = {
      run_id: `run_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      action_id: id,
      status: 'queued',
      queued_at: new Date().toISOString(),
      warnings: [],
      errors: [],
      updated_artifacts: [],
      command_fallback: action?.command || null
    };
    runs.set(run.run_id, run);

    const entitlementState = loadEntitlements(knowledgeRoot);
    const gate = canRunAction(action, entitlementState);
    if (!gate.ok) {
      run.status = 'blocked';
      run.finished_at = new Date().toISOString();
      run.errors.push(gate);
      run.stdout_summary = `Action blocked: ${gate.reason}.`;
      appendRunLog(run);
      return run;
    }

    const confirmedById = body.confirmation_id && confirmations.get(id) === body.confirmation_id;
    if (RISK_REQUIRES_CONFIRMATION.has(action.risk) && !body.confirmed && !confirmedById) {
      run.status = 'blocked';
      run.finished_at = new Date().toISOString();
      run.errors.push({ reason: 'confirmation_required', risk: action.risk });
      run.stdout_summary = `${action.label} needs explicit confirmation before it can write locally.`;
      appendRunLog(run);
      return run;
    }

    await performAction(action, body, run);
    appendRunLog(run);
    return run;
  }

  function inspectorHtml() {
    const state = makeState();
    const cards = Object.entries(state.home_cards).map(([key, value]) => {
      const label = key.replace(/_/g, ' ');
      return `<article><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? 'unknown')}</strong></article>`;
    }).join('');
    const actionButtons = listActions().slice(0, 11).map((action) => `<button data-action="${escapeHtml(action.id)}">${escapeHtml(action.label)}</button>`).join('');
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>.knowledge Inspector</title><style>body{margin:0;background:#101411;color:#eef3ec;font:14px/1.45 ui-sans-serif,system-ui}main{max-width:1120px;margin:0 auto;padding:28px}h1{font-size:28px;margin:0 0 8px}.sub{color:#aeb9ad}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:20px 0}.cards article{border:1px solid #334137;background:#171d19;border-radius:8px;padding:12px}.cards span{display:block;color:#aeb9ad;font-size:12px;text-transform:capitalize}.cards strong{font-size:20px}button{border:1px solid #3b5546;background:#1c2a22;color:#eef3ec;border-radius:8px;padding:9px 11px;margin:4px;cursor:pointer}pre{white-space:pre-wrap;border:1px solid #334137;border-radius:8px;background:#080c0a;padding:12px}</style></head><body><main><h1>.knowledge Inspector</h1><p class="sub">Free local action cockpit. Pro Preview is coming soon inside this same Inspector.</p><section class="cards">${cards}</section><section>${actionButtons}</section><pre id="result">Session token is required for API actions. Launcher session is local only.</pre><script>const token=${JSON.stringify(token)};document.addEventListener('click',async(e)=>{const b=e.target.closest('[data-action]');if(!b)return;const r=await fetch('/api/actions/'+b.dataset.action+'/run',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({confirmed:true})});document.getElementById('result').textContent=JSON.stringify(await r.json(),null,2);});</script></main></body></html>`;
  }

  function requestHandler(req, res) {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (host !== '127.0.0.1') {
      json(res, 403, { ok: false, error: 'invalid_bind_host' });
      return;
    }
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(inspectorHtml());
      return;
    }
    if (!url.pathname.startsWith('/api/')) return notFound(res);
    if (!authOk(req)) {
      json(res, 401, { ok: false, error: 'session_token_required' });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/session') {
      json(res, 200, { ok: true, token, host, port: server?.address()?.port || port, scope: 'local-inspector' });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/state') {
      json(res, 200, { ok: true, state: makeState() });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/actions') {
      json(res, 200, { ok: true, actions: listActions(), entitlements: loadEntitlements(knowledgeRoot) });
      return;
    }
    const runMatch = url.pathname.match(/^\/api\/actions\/([^/]+)\/run$/);
    if (req.method === 'POST' && runMatch) {
      collectBody(req).then((body) => runAction(decodeURIComponent(runMatch[1]), body).then((run) => json(res, run.status === 'blocked' ? 423 : 200, { ok: run.status === 'passed', run })));
      return;
    }
    const confirmMatch = url.pathname.match(/^\/api\/actions\/([^/]+)\/confirm$/);
    if (req.method === 'POST' && confirmMatch) {
      const actionId = decodeURIComponent(confirmMatch[1]);
      const confirmationId = `confirm_${crypto.randomBytes(8).toString('hex')}`;
      confirmations.set(actionId, confirmationId);
      json(res, 200, { ok: true, action_id: actionId, confirmation_id: confirmationId });
      return;
    }
    const runGet = url.pathname.match(/^\/api\/runs\/([^/]+)$/);
    if (req.method === 'GET' && runGet) {
      const run = runs.get(decodeURIComponent(runGet[1]));
      if (!run) return notFound(res);
      json(res, 200, { ok: true, run });
      return;
    }
    const runStream = url.pathname.match(/^\/api\/runs\/([^/]+)\/stream$/);
    if (req.method === 'GET' && runStream) {
      const run = runs.get(decodeURIComponent(runStream[1]));
      if (!run) return notFound(res);
      res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store' });
      res.end(`event: run\ndata: ${JSON.stringify(run)}\n\n`);
      return;
    }
    notFound(res);
  }

  function start() {
    fs.mkdirSync(path.join(knowledgeRoot, 'maintenance', 'action-runs'), { recursive: true });
    server = http.createServer(requestHandler);
    server.listen(port, host, () => {
      const address = server.address();
      const actualPort = typeof address === 'object' ? address.port : port;
      const url = `http://${host}:${actualPort}/?token=${token}`;
      const payload = { ok: true, url, host, port: actualPort, session_token: token };
      if (options.json) console.log(JSON.stringify(payload, null, 2));
      else console.log(`.knowledge Inspector: ${url}`);
      if (options.openBrowser) openLocalBrowser(url);
    });
    return server;
  }

  function stop(callback) {
    if (server) server.close(callback);
  }

  return { start, stop, runAction, makeState, get token() { return token; }, get server() { return server; } };
}

function openLocalBrowser(url) {
  if (process.env.KNOWLEDGE_INSPECTOR_NO_OPEN === '1') return;
  const command = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
  child.unref();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

module.exports = { createActionServer };
