'use strict';
const http = require('node:http');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const TARGET_HOST = process.env.TARGET_HOST || 'httpbin';
const TARGET_PORT = Number(process.env.TARGET_PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET;
const LOGIN_USER = process.env.LOGIN_USER;
const LOGIN_PASSWORD = process.env.LOGIN_PASSWORD;
if (!JWT_SECRET || JWT_SECRET.length < 32 || !LOGIN_USER || !LOGIN_PASSWORD) {
  throw new Error('Set JWT_SECRET (at least 32 characters), LOGIN_USER and LOGIN_PASSWORD');
}

function b64url(value) { return Buffer.from(value).toString('base64url'); }
function sign(input) { return crypto.createHmac('sha256', JWT_SECRET).update(input).digest('base64url'); }
function createToken(subject) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: subject, iat: now, exp: now + 3600 }));
  const content = `${header}.${payload}`;
  return `${content}.${sign(content)}`;
}
function verifyToken(token) {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [header, payload, signature] = parts;
  const expected = Buffer.from(sign(`${header}.${payload}`));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return false;
  try {
    const h = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
    const p = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    return h.alg === 'HS256' && h.typ === 'JWT' && typeof p.sub === 'string' && Number.isInteger(p.iat) && Number.isInteger(p.exp) && p.iat <= now && p.exp > now;
  } catch { return false; }
}
function sendJson(res, code, data) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(data));
}
function safeEqualString(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

const server = http.createServer((req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  if (path === '/login') {
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'Use POST /login' });
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 8192) req.destroy();
    });
    req.on('end', () => {
      let body;
      try { body = JSON.parse(raw); } catch { return sendJson(res, 400, { error: 'Invalid JSON' }); }
      if (!safeEqualString(body.username ?? '', LOGIN_USER) || !safeEqualString(body.password ?? '', LOGIN_PASSWORD)) {
        return sendJson(res, 401, { error: 'Invalid credentials' });
      }
      return sendJson(res, 200, { token: createToken(LOGIN_USER), token_type: 'Bearer', expires_in: 3600 });
    });
    return;
  }
  const match = /^Bearer (\S+)$/i.exec(req.headers.authorization || '');
  if (!match || !verifyToken(match[1])) return sendJson(res, 401, { error: 'Missing or invalid JWT' });
  const headers = { ...req.headers };
  delete headers.authorization;
  delete headers.connection;
  delete headers['proxy-authorization'];
  headers.host = `${TARGET_HOST}:${TARGET_PORT}`;
  const upstream = http.request({ hostname: TARGET_HOST, port: TARGET_PORT, method: req.method, path: req.url, headers }, upstreamRes => {
    const responseHeaders = { ...upstreamRes.headers };
    delete responseHeaders['transfer-encoding'];
    delete responseHeaders.connection;
    res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
    upstreamRes.pipe(res);
  });
  upstream.on('error', () => { if (!res.headersSent) sendJson(res, 502, { error: 'Upstream unavailable' }); else res.destroy(); });
  req.pipe(upstream);
});
server.listen(PORT, '0.0.0.0', () => console.log(`JWT proxy listening on port ${PORT}`));
