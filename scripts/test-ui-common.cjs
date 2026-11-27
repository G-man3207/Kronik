#!/usr/bin/env node
'use strict';
/*
 * Shared fixture plumbing for the admin UI test scripts (test-ui-*.cjs):
 * the DevTools client, Chrome's launch flags and the UI file serving with
 * driver injection. No package install.
 */
const fs = require('node:fs');
const path = require('node:path');
const { setTimeout: sleep } = require('node:timers/promises');

const ui = path.join(__dirname, '..', 'ui');
const chromeBin = process.env.KRONIK_CHROME || '/usr/bin/google-chrome';

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

// The DevTools client of the headless Chrome the fixture launched: waits
// for the profile's DevToolsActivePort, attaches to the page target and
// returns send(method, params) — a promise per CDP call with a 5 s timeout —
// plus close().
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
  return { send, close: () => ws.close() };
}

// Chrome's headless flags the UI fixtures launch it with: a fresh profile
// per run and DevTools on an ephemeral port.
function chromeArgs(profile, url) {
  return [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
    '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`, url,
  ];
}

// Serves the files a fixture's Chrome session loads: index.html with the
// driver script injected after app.js, the driver source itself, and the
// app's static files. Returns 'page', 'driver' or 'file' when the request
// was served, null for anything else.
function serveUi(req, res, driver) {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (req.method === 'GET' && (url.pathname === '/ui' || url.pathname === '/ui/')) {
    const html = fs.readFileSync(path.join(ui, 'index.html'), 'utf8').replace(
      '<script src="/ui/app.js" defer></script>',
      '<script src="/ui/app.js" defer></script>\n  <script src="/ui/driver.js" defer></script>',
    );
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(html);
    return 'page';
  }
  if (req.method === 'GET' && url.pathname === '/ui/driver.js') {
    res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(driver);
    return 'driver';
  }
  if (req.method === 'GET' && ['/ui/app.js', '/ui/app.css', '/ui/icon.svg'].includes(url.pathname)) {
    const file = path.basename(url.pathname);
    const type = file.endsWith('.js') ? 'text/javascript; charset=utf-8'
      : file.endsWith('.css') ? 'text/css; charset=utf-8' : 'image/svg+xml';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(fs.readFileSync(path.join(ui, file)));
    return 'file';
  }
  return null;
}

module.exports = { chromeBin, sleep, connect, chromeArgs, serveUi };
