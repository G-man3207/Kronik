#!/usr/bin/env node
'use strict';
/*
 * Admin UI keyboard focus for actor and dead-letter paging (issue 251).
 * Next and First must leave focus on that section, not the document.
 * Opening a view still focuses the heading. Choosing a row still focuses
 * its detail.
 * Run: node scripts/test-ui-paging-focus.cjs
 * Chrome: $KRONIK_CHROME or /usr/bin/google-chrome. No package install.
 */
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ui = path.join(__dirname, '..', 'ui');
const chromeBin = process.env.KRONIK_CHROME || '/usr/bin/google-chrome';

function actor(n) {
  return { kind: 'counter', key: 'a' + n, schema_version: 1, turns: 1, last_turn_id: 't' + n, sql: false };
}
function letter(n) {
  return {
    id: 'dl' + n,
    actor: 'counter/a' + n,
    input: { type: 'message', summary: 'n' + n },
    error_code: 'FAILED',
    message: 'failed',
    resent_as: null,
  };
}
function history() {
  return {
    status: 200,
    body: {
      turns: [{
        turn_id: 't0', lsn: 1, logical_time_ms: 1, input: { type: 'message', summary: 'hi' },
        outcome: 'ok', writes: [], sql_changes: 0, fuel_used: 1, effects: [],
      }],
      next: null,
    },
  };
}
function actors(after) {
  const page2 = after === 'page-2';
  return { status: 200, body: { actors: page2 ? [actor(2)] : [actor(0), actor(1)], next: page2 ? null : 'page-2' } };
}
function letters(after) {
  const rows = after === 'dl49' ? [letter(50)] : Array.from({ length: 50 }, (_, n) => letter(n));
  return { status: 200, body: { dead_letters: rows } };
}

function driver() {
  return `'use strict';
const status = () => document.getElementById('status').textContent;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(fn, detail) {
  const start = performance.now();
  for (;;) {
    if (fn()) return;
    if (performance.now() - start > 8000) {
      const active = document.activeElement;
      throw new Error('timeout: ' + detail + ' status=' + status() + ' active=' + (active && (active.id || active.tagName)) + ' error=' + document.getElementById('error').textContent);
    }
    await sleep(20);
  }
}
function assertFocus(id, detail) {
  const node = document.getElementById(id);
  const active = document.activeElement;
  if (!node || active !== node || node.getAttribute('tabindex') !== '-1') {
    throw new Error(detail + ' active=' + (active && (active.id || active.tagName)) + ' tabindex=' + (node && node.getAttribute('tabindex')));
  }
}
async function activate(body) {
  const reply = await fetch('/activate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!reply.ok) throw new Error('activate failed ' + reply.status + ' ' + await reply.text());
}
async function finish(ok, detail) {
  await fetch('/result', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok, detail }) });
}
async function run() {
  await waitFor(() => status().includes('History loaded.'), 'history');
  await activate({ id: 'nav-deadletters' });
  await waitFor(() => status().includes('Dead letters loaded.'), 'dead letters');
  assertFocus('view-title', 'opening dead letters stole focus');
  if (!document.getElementById('deadletters-next')) throw new Error('next dead letters missing');
  await activate({ id: 'deadletters-next' });
  await waitFor(() => document.getElementById('deadletters-first') && document.getElementById('view-content').textContent.includes('dl50'), 'dead letter page 2');
  assertFocus('deadletter-list', 'next dead letters dropped focus');
  await activate({ id: 'deadletters-first' });
  await waitFor(() => document.getElementById('deadletters-next') && !document.getElementById('deadletters-first'), 'dead letter page 1');
  assertFocus('deadletter-list', 'first dead letters dropped focus');
  await activate({ testid: 'deadletter-open' });
  await waitFor(() => document.getElementById('deadletter-detail').textContent.includes('Dead letter dl0'), 'dead letter detail');
  assertFocus('deadletter-detail', 'choosing a dead letter did not move focus');
  await activate({ id: 'nav-history' });
  await waitFor(() => status().includes('History loaded.'), 'history again');
  assertFocus('view-title', 'opening history stole focus');
  if (!document.getElementById('actors-next')) throw new Error('next actors missing');
  await activate({ id: 'actors-next' });
  await waitFor(() => document.getElementById('actors-first') && document.getElementById('view-content').textContent.includes('counter/a2'), 'actor page 2');
  assertFocus('actors', 'next actors dropped focus');
  await activate({ id: 'actors-first' });
  await waitFor(() => document.getElementById('actors-next') && !document.getElementById('actors-first'), 'actor page 1');
  assertFocus('actors', 'first actors dropped focus');
  await activate({ testid: 'actor-open' });
  await waitFor(() => status().includes('Loaded 1 turns.'), 'actor history');
  assertFocus('actor-history', 'choosing an actor did not move focus');
}
run().then(() => finish(true, 'ok')).catch((error) => finish(false, String(error && error.message || error)));
`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
async function devtoolsPort(profile) {
  const file = path.join(profile, 'DevToolsActivePort');
  const start = Date.now();
  for (;;) {
    if (fs.existsSync(file)) {
      const port = Number(fs.readFileSync(file, 'utf8').split('\n')[0]);
      if (port) return port;
    }
    if (Date.now() - start > 8000) throw new Error('devtools port missing');
    await sleep(50);
  }
}
async function connect(profile) {
  const port = await devtoolsPort(profile);
  const list = await fetch(`http://127.0.0.1:${port}/json/list`).then((reply) => reply.json());
  const page = list.find((item) => item.type === 'page' && item.url.includes('/ui/'))
    || list.find((item) => item.type === 'page' && item.webSocketDebuggerUrl);
  if (!page) throw new Error('no page target');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve);
    ws.addEventListener('error', () => reject(new Error('devtools socket failed')));
  });
  let next = 0;
  const pending = new Map();
  ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  });
  function send(method, params = {}) {
    const id = ++next;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('cdp timeout ' + method)), 5000);
      pending.set(id, (msg) => {
        clearTimeout(timer);
        if (msg.error) reject(new Error(method + ': ' + JSON.stringify(msg.error)));
        else resolve(msg.result);
      });
      ws.send(JSON.stringify({ id, method, params }));
    });
  }
  return send;
}
async function activate(send, body) {
  const selector = body.testid ? `[data-testid="${body.testid}"]` : `#${body.id}`;
  const expression = `(() => {
    const node = document.querySelector(${JSON.stringify(selector)});
    if (!node) return 'missing';
    node.focus();
    return document.activeElement === node ? 'focused' : 'unfocused';
  })()`;
  const evaluated = await send('Runtime.evaluate', { expression, returnByValue: true });
  if (evaluated.exceptionDetails) throw new Error('focus failed ' + JSON.stringify(evaluated.exceptionDetails));
  if (!evaluated.result || evaluated.result.value !== 'focused') throw new Error('focus ' + (evaluated.result && evaluated.result.value) + ' ' + selector);
  const enter = {
    key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13,
    text: '\r', unmodifiedText: '\r',
  };
  await send('Input.dispatchKeyEvent', { type: 'keyDown', ...enter });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 });
}

async function main() {
  if (!fs.existsSync(chromeBin)) throw new Error(`chrome not found: ${chromeBin}`);
  const seen = [];
  let resultDone = null;
  const result = new Promise((resolve) => { resultDone = resolve; });
  let sendReady = null;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const json = (status, body) => {
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    if (req.method === 'GET' && (url.pathname === '/ui' || url.pathname === '/ui/')) {
      const html = fs.readFileSync(path.join(ui, 'index.html'), 'utf8').replace(
        '<script src="/ui/app.js" defer></script>',
        '<script src="/ui/app.js" defer></script>\n  <script src="/ui/driver.js" defer></script>',
      );
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(html);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/ui/driver.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(driver());
      return;
    }
    if (req.method === 'GET' && ['/ui/app.js', '/ui/app.css', '/ui/icon.svg'].includes(url.pathname)) {
      const file = path.basename(url.pathname);
      const type = file.endsWith('.js') ? 'text/javascript; charset=utf-8'
        : file.endsWith('.css') ? 'text/css; charset=utf-8' : 'image/svg+xml';
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
      res.end(fs.readFileSync(path.join(ui, file)));
      return;
    }
    if (req.method === 'POST' && url.pathname === '/result') {
      readBody(req).then((raw) => {
        res.writeHead(204);
        res.end();
        resultDone(JSON.parse(raw || '{}'));
      }).catch((error) => {
        res.writeHead(400);
        res.end();
        resultDone({ ok: false, detail: String(error) });
      });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/activate') {
      readBody(req).then(async (raw) => {
        try {
          await activate(await sendReady, JSON.parse(raw || '{}'));
          res.writeHead(204);
          res.end();
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
          res.end(String(error && error.message || error));
        }
      }).catch((error) => {
        res.writeHead(400);
        res.end(String(error));
      });
      return;
    }
    if (!url.pathname.startsWith('/v1/')) {
      res.writeHead(404);
      res.end();
      return;
    }
    seen.push(req.method + ' ' + url.pathname + url.search);
    if (req.method === 'GET' && url.pathname === '/v1/auth/session') {
      json(200, { authenticated: true, oidc_enabled: false, scopes: ['read'], principal: 'fixture-operator', csrf_token: null, expires_at_ms: null });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/v1/actors') {
      const reply = actors(url.searchParams.get('after'));
      json(reply.status, reply.body);
      return;
    }
    if (req.method === 'GET' && url.pathname.endsWith('/history')) {
      const reply = history();
      json(reply.status, reply.body);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/v1/dead-letters') {
      const reply = letters(url.searchParams.get('after'));
      json(reply.status, reply.body);
      return;
    }
    json(404, { error: { code: 'NOT_FOUND', message: url.pathname } });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'kronik-ui-'));
  const child = spawn(chromeBin, [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
    '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`, `${origin}/ui/`,
  ], { stdio: ['ignore', 'ignore', 'pipe'], detached: true });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  sendReady = connect(profile).then(async (cdp) => {
    await cdp('Emulation.setFocusEmulationEnabled', { enabled: true });
    return cdp;
  });
  let timer;
  const timed = new Promise((resolve) => { timer = setTimeout(() => resolve({ ok: false, detail: 'chrome timeout' }), 45000); });
  const outcome = await Promise.race([result, timed]);
  clearTimeout(timer);
  try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ }
  fs.rmSync(profile, { recursive: true, force: true });
  server.close();
  if (!outcome.ok) {
    console.error(outcome.detail || 'failed');
    if (seen.length) console.error(seen.join('\n'));
    if (stderr) console.error(stderr.slice(-2000));
    process.exit(1);
  }
  console.log('ok paging-focus');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
