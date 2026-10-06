'use strict';

const MAX_JSON_BODY_BYTES = 1024 * 1024;

function requestError(code, statusCode) {
  return Object.assign(new Error(code), { code, statusCode });
}

function assertLoopbackRequest(req, port) {
  // Binding a socket to loopback alone does not prevent DNS rebinding: the
  // session bootstrap must also reject requests for a foreign authority.
  const isLocalAuthority = (value) => {
    try {
      const url = new URL(value);
      return url.protocol === 'http:' && !url.username && !url.password &&
        ['127.0.0.1', 'localhost'].includes(url.hostname) &&
        Number(url.port || 80) === port;
    } catch { return false; }
  };
  const authority = String(req.headers.host || '');
  if (!authority || /[/\\\s?#@]/.test(authority) || !isLocalAuthority(`http://${authority}`)) {
    throw requestError('invalid_request_host', 403);
  }
  if (req.headers.origin && !isLocalAuthority(String(req.headers.origin))) {
    throw requestError('cross_origin_request_forbidden', 403);
  }
}

function readJsonBody(req, limit = MAX_JSON_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let bytes = 0;
    const chunks = [];
    const fail = (error) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      reject(error);
    };
    const failOversize = () => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      // A close response while a client is still writing can replace HTTP 413
      // with ECONNRESET. Drain without retaining bytes, but never wait forever
      // for a client that declares an oversized body and stops sending it.
      const error = requestError('request_body_too_large', 413);
      const finish = () => {
        clearTimeout(timer);
        req.removeListener('end', finish);
        req.removeListener('error', onError);
        req.removeListener('aborted', onAborted);
        reject(error);
      };
      const onError = (transportError) => { error.code = transportError.code || 'request_aborted'; error.statusCode = 400; finish(); };
      const onAborted = () => { error.code = 'request_aborted'; error.statusCode = 400; finish(); };
      const timer = setTimeout(finish, 1000);
      timer.unref();
      req.once('end', finish);
      req.once('error', onError);
      req.once('aborted', onAborted);
      req.resume();
    };
    req.on('error', (error) => fail(error));
    req.on('aborted', () => fail(requestError('request_aborted', 400)));
    const contentLength = Number(req.headers['content-length']);
    if (Number.isFinite(contentLength) && contentLength > limit) {
      failOversize();
      return;
    }
    req.on('data', (chunk) => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > limit) {
        failOversize();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      let body;
      try {
        const raw = Buffer.concat(chunks).toString('utf8').trim();
        body = raw ? JSON.parse(raw) : {};
      } catch {
        fail(requestError('invalid_json', 400));
        return;
      }
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        fail(requestError('json_object_required', 400));
        return;
      }
      settled = true;
      resolve(body);
    });
  });
}

function reportRequestError(res, error, sendJson) {
  if (res.destroyed || res.writableEnded) return;
  if (res.headersSent) { res.destroy(); return; }
  sendJson(res, error.statusCode || 500, {
    ok: false,
    error: error.code || 'inspector_request_failed',
    message: error.statusCode ? error.message : 'Inspector could not complete the request.'
  });
}

module.exports = { MAX_JSON_BODY_BYTES, requestError, assertLoopbackRequest, readJsonBody, reportRequestError };
