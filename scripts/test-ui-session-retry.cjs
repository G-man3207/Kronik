#!/usr/bin/env node
'use strict';
/*
 * Admin UI session check for a non-auth first load (issue 167) and a
 * policy 403 on promote (issue 190).
 * Run: node scripts/test-ui-session-retry.cjs
 * Chrome: $KRONIK_CHROME or /usr/bin/google-chrome. No package install.
 */
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ui = path.join(__dirname, '..', 'ui');
const TOKEN = 'fixture-bearer';
const KEPT = 'kept-secret';
const PRINCIPAL = 'fixture-operator';
const chromeBin = process.env.KRONIK_CHROME || '/usr/bin/google-chrome';

function session(authenticated) {
  return {
    authenticated,
    oidc_enabled: false,
    scopes: authenticated ? ['read', 'approve', 'promote'] : [],
    principal: authenticated ? PRINCIPAL : null,
    csrf_token: authenticated ? 'fixture-csrf' : null,
    expires_at_ms: null,
  };
}
function fail(status, code, message, hint, docs) {
  const error = { code, message };
  if (hint) error.hint = hint;
  if (docs) error.docs = docs;
  return { status, body: { error } };
}
function invalid(status) {
  return { status, raw: 'not-json' };
}
const drop = { drop: true };
const okSession = () => ({ status: 200, body: session(true) });
const anonSession = () => ({ status: 200, body: session(false) });
const okActors = () => ({ status: 200, body: { actors: [], next: null } });
const unavailable = () => fail(500, 'UNAVAILABLE', 'Synthetic load failure.');
const denied = () => fail(401, 'UNAUTHENTICATED', 'Synthetic auth failure.');
const forbidden = () => fail(403, 'SCOPE_MISSING', 'Synthetic scope failure.');
function policy(code) {
  return fail(403, code, 'The change was refused.', 'Read the diff.', `kronik explain ${code}`);
}
function okProposal() {
  return {
    status: 200,
    body: {
      id: 'p-1', status: 'running', fork: 'f-1', fork_lsn: 1, verified_through_lsn: 1,
      diff_hash: 'abc', kinds: [], unchanged: false, policy: 'open', approvals: [], approval_requests: [],
    },
  };
}

// reply(n, headers) -> HTTP reply. n is 1-based for that path.
const cases = [
  { name: 'startup-actors-500', recipe: 'keep-load', session: () => okSession(), actors: (n) => n === 1 ? unavailable() : okActors() },
  { name: 'startup-actors-invalid-json', recipe: 'keep-load', session: () => okSession(), actors: (n) => n === 1 ? invalid(200) : okActors() },
  { name: 'startup-actors-network', recipe: 'keep-load', network: 'actors', session: () => okSession(), actors: () => okActors() },
  { name: 'startup-session-500', recipe: 'keep-session', session: (n) => n === 1 ? unavailable() : okSession(), actors: () => okActors() },
  { name: 'startup-session-invalid-json', recipe: 'keep-session', session: (n) => n === 1 ? invalid(200) : okSession(), actors: () => okActors() },
  { name: 'startup-session-network', recipe: 'keep-session', network: 'session', session: () => okSession(), actors: () => okActors() },
  { name: 'startup-actors-401', recipe: 'clear-load', session: () => okSession(), actors: () => invalid(401) },
  { name: 'startup-actors-403', recipe: 'clear-load', session: () => okSession(), actors: () => forbidden() },
  { name: 'bearer-session-500', recipe: 'keep-connect', session: (n) => n === 1 ? anonSession() : n === 2 ? unavailable() : okSession(), actors: () => okActors() },
  { name: 'bearer-session-invalid-json', recipe: 'keep-connect', session: (n) => n === 1 ? anonSession() : n === 2 ? invalid(200) : okSession(), actors: () => okActors() },
  { name: 'bearer-session-network', recipe: 'keep-connect', network: 'session-after-1', session: (n) => n === 1 ? anonSession() : okSession(), actors: () => okActors() },
  { name: 'bearer-actors-500', recipe: 'keep-bearer-load', session: (n) => n === 1 ? anonSession() : okSession(), actors: (n) => n === 1 ? unavailable() : okActors() },
  { name: 'bearer-success', recipe: 'connect-ok', session: (n) => n === 1 ? anonSession() : okSession(), actors: () => okActors() },
  { name: 'bearer-401', recipe: 'clear-connect', session: (n) => n === 1 ? anonSession() : denied(), actors: () => okActors() },
  { name: 'bearer-403', recipe: 'clear-connect', session: (n) => n === 1 ? anonSession() : invalid(403), actors: () => okActors() },
  { name: 'promote-approval-required', recipe: 'keep-policy', hash: '#proposals/p-1', code: 'APPROVAL_REQUIRED', session: () => okSession(), proposal: () => okProposal(), promote: () => policy('APPROVAL_REQUIRED') },
  { name: 'promote-policy-denied', recipe: 'keep-policy', hash: '#proposals/p-1', code: 'POLICY_DENIED', session: () => okSession(), proposal: () => okProposal(), promote: () => policy('POLICY_DENIED') },
  { name: 'promote-other-403', recipe: 'keep-policy', hash: '#proposals/p-1', code: 'CAPABILITY_NOT_GRANTED', session: () => okSession(), proposal: () => okProposal(), promote: () => policy('CAPABILITY_NOT_GRANTED') },
  { name: 'promote-unauthenticated', recipe: 'clear-policy', hash: '#proposals/p-1', code: 'UNAUTHENTICATED', session: () => okSession(), proposal: () => okProposal(), promote: () => fail(401, 'UNAUTHENTICATED', 'No valid token.', 'Send a token.') },
  { name: 'promote-scope-missing', recipe: 'clear-policy', hash: '#proposals/p-1', code: 'SCOPE_MISSING', session: () => okSession(), proposal: () => okProposal(), promote: () => fail(403, 'SCOPE_MISSING', 'Missing scope.', 'Use another token.') },
  { name: 'promote-bearer-approval', recipe: 'keep-policy-bearer', hash: '#proposals/p-1', code: 'APPROVAL_REQUIRED', session: (n) => n === 1 ? anonSession() : okSession(), proposal: () => okProposal(), promote: () => policy('APPROVAL_REQUIRED') },
];

function driver() {
  return `'use strict';
const CASE = new URLSearchParams(location.search).get('case');
const TOKEN = ${JSON.stringify(TOKEN)};
const KEPT = ${JSON.stringify(KEPT)};
const PRINCIPAL = ${JSON.stringify(PRINCIPAL)};
const recipe = ${JSON.stringify(Object.fromEntries(cases.map((item) => [item.name, item.recipe])))}[CASE];
const expected = ${JSON.stringify(Object.fromEntries(cases.filter((item) => item.code).map((item) => [item.name, item.code])))}[CASE];
const status = () => document.getElementById('session-status').textContent;
const errorBox = () => document.getElementById('error');
const field = () => document.getElementById('bearer-token');
const refresh = () => document.getElementById('refresh-button');
const signedOut = () => status().includes('Not signed in');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(fn, detail) {
  const start = performance.now();
  for (;;) {
    if (fn()) return;
    if (performance.now() - start > 8000) throw new Error('timeout: ' + detail + ' status=' + status() + ' error=' + errorBox().textContent);
    await sleep(20);
  }
}
function assert(value, detail) {
  if (!value) throw new Error(detail + ' status=' + status() + ' field=' + field().value + ' refresh=' + Boolean(refresh()) + ' view=' + document.getElementById('view-content').childElementCount);
}
async function shownError() {
  await waitFor(() => !errorBox().hidden && errorBox().textContent.length > 0, 'error');
}
async function loaded() {
  await waitFor(() => document.getElementById('status').textContent.includes('History loaded.'), 'loaded');
}
function submit(value) {
  document.getElementById('token-alternative').open = true;
  if (value !== undefined) field().value = value;
  document.getElementById('token-form').requestSubmit();
}
async function finish(ok, detail) {
  await fetch('/result', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
    ok, detail, case: CASE, status: status(), field: field().value, refresh: Boolean(refresh()),
    view: document.getElementById('view-content').childElementCount, page: document.getElementById('status').textContent,
    loads: performance.getEntriesByType('navigation').length,
  }) });
}
async function release() { await fetch('/release', { method: 'POST' }); }
async function run() {
  if (!recipe) throw new Error('unknown case');
  if (CASE.startsWith('startup') || recipe === 'keep-policy' || recipe === 'clear-policy') field().value = KEPT;
  if (recipe === 'keep-load') {
    await waitFor(() => status().includes('OIDC: ' + PRINCIPAL), 'session');
    await shownError();
    assert(!signedOut() && status().includes('OIDC: ' + PRINCIPAL), 'session cleared');
    assert(field().value === KEPT, 'password field changed');
    assert(refresh() && document.getElementById('view-content').childElementCount > 0, 'retry missing');
    await release();
    refresh().click();
    await loaded();
    assert(!signedOut() && status().includes('OIDC: ' + PRINCIPAL), 'retry signed out');
    assert(field().value === KEPT, 'retry changed password field');
  } else if (recipe === 'keep-session') {
    await shownError();
    assert(!signedOut(), 'session check showed Not signed in');
    assert(field().value === KEPT, 'password field changed');
    assert(refresh(), 'retry missing');
    await release();
    refresh().click();
    await loaded();
    assert(status().includes('OIDC: ' + PRINCIPAL) && field().value === KEPT, 'retry did not keep the session');
  } else if (recipe === 'clear-load') {
    await waitFor(() => signedOut(), 'still signed in');
    await shownError();
    assert(field().value === '' && !refresh() && document.getElementById('view-content').childElementCount === 0, 'auth failure did not clear');
  } else if (recipe === 'keep-connect') {
    await waitFor(() => signedOut(), 'initial');
    submit(TOKEN);
    await shownError();
    assert(field().value === TOKEN, 'typed token dropped');
    await release();
    submit();
    await waitFor(() => status().includes('Bearer token'), 'retry');
    await loaded();
    assert(!signedOut(), 'retry signed out');
  } else if (recipe === 'keep-bearer-load') {
    await waitFor(() => signedOut(), 'initial');
    submit(TOKEN);
    await waitFor(() => status().includes('Bearer token'), 'bearer');
    await shownError();
    assert(!signedOut() && field().value === TOKEN && refresh(), 'connect load cleared auth');
    await release();
    refresh().click();
    await loaded();
    assert(status().includes('Bearer token') && field().value === TOKEN, 'refresh dropped the bearer');
  } else if (recipe === 'connect-ok') {
    await waitFor(() => signedOut(), 'initial');
    submit(TOKEN);
    await waitFor(() => status().includes('Bearer token'), 'bearer');
    await loaded();
    assert(field().value === '' && !signedOut() && refresh(), 'successful connect kept the typed token');
  } else if (recipe === 'clear-connect') {
    await waitFor(() => signedOut(), 'initial');
    submit(TOKEN);
    await shownError();
    assert(signedOut() && field().value === '' && !refresh(), 'auth failure kept the bearer');
    assert(document.getElementById('view-content').childElementCount === 0, 'auth failure left data');
  } else if (recipe === 'keep-policy' || recipe === 'keep-policy-bearer') {
    if (recipe === 'keep-policy-bearer') {
      await waitFor(() => signedOut(), 'initial');
      submit(TOKEN);
      await waitFor(() => status().includes('Bearer token'), 'bearer');
    } else {
      await waitFor(() => status().includes('OIDC: ' + PRINCIPAL), 'session');
    }
    await waitFor(() => {
      const button = document.getElementById('promote-button');
      return button && !button.disabled;
    }, 'promote');
    document.getElementById('promote-reason').value = 'Synthetic policy refusal';
    document.getElementById('promote-form').requestSubmit();
    await waitFor(() => document.activeElement === errorBox() && errorBox().textContent.includes(expected), 'focused error');
    assert(!signedOut(), 'policy error signed out');
    assert(document.getElementById('proposal-detail'), 'proposal cleared');
    assert(errorBox().textContent.includes('Read the diff.'), 'hint missing');
    assert(errorBox().textContent.includes('docs: kronik explain ' + expected), 'docs line missing');
    assert(document.getElementById('status').textContent.includes('Operation failed'), 'operation-failed not announced');
    assert(!errorBox().textContent.includes('Not signed in'), 'error announced sign-out');
    if (recipe === 'keep-policy') assert(field().value === KEPT, 'password field changed');
    else {
      document.getElementById('refresh-button').click();
      await waitFor(() => document.getElementById('status').textContent.includes('Proposals loaded.'), 'refresh');
      assert(status().includes('Bearer token') && !signedOut(), 'refresh signed out');
    }
  } else if (recipe === 'clear-policy') {
    await waitFor(() => status().includes('OIDC: ' + PRINCIPAL), 'session');
    await waitFor(() => document.getElementById('promote-button'), 'promote');
    document.getElementById('promote-reason').value = 'Synthetic auth refusal';
    document.getElementById('promote-form').requestSubmit();
    await waitFor(() => signedOut(), 'still signed in');
    await shownError();
    assert(field().value === '' && document.getElementById('view-content').childElementCount === 0, 'auth failure did not clear');
    assert(errorBox().textContent.includes(expected), 'auth code missing');
  } else throw new Error('unknown recipe');
  assert(performance.getEntriesByType('navigation').length === 1, 'page reloaded');
}
run().then(() => finish(true, 'ok')).catch((error) => finish(false, String(error && error.message || error)));
`;
}

function expects(item, seen) {
  const bearer = (value) => value === `Bearer ${TOKEN}`;
  const none = seen.authorization.every((value) => !value);
  if (item.network === 'actors') return none && seen.served.actors >= 1 && seen.pages === 1;
  if (item.network === 'session') return none && seen.served.session >= 1 && seen.served.actors >= 1;
  if (item.network === 'session-after-1') return bearer(seen.servedAuth.session.at(-1)) && bearer(seen.servedAuth.actors[0]);
  if (item.recipe === 'keep-load') return none && seen.actors === 2 && seen.session >= 1;
  if (item.recipe === 'keep-session') return none && seen.session === 2 && seen.actors === 1;
  if (item.recipe === 'clear-load') return none && seen.actors === 1 && seen.pages === 1;
  if (item.recipe === 'keep-connect') return seen.session === 3 && bearer(seen.authorization[1]) && bearer(seen.authorization[2]) && seen.actors === 1 && bearer(seen.actorAuth[0]);
  if (item.recipe === 'keep-bearer-load') return seen.actors === 2 && bearer(seen.actorAuth[0]) && bearer(seen.actorAuth[1]);
  if (item.recipe === 'connect-ok') return seen.session === 2 && bearer(seen.authorization[1]) && seen.actors === 1 && bearer(seen.actorAuth[0]);
  if (item.recipe === 'clear-connect') return seen.actors === 0 && seen.session === 2 && bearer(seen.authorization[1]);
  if (item.recipe === 'keep-policy' || item.recipe === 'clear-policy') {
    return none && seen.proposal === 1 && seen.promote === 1 && seen.pages === 1 && seen.session >= 1;
  }
  if (item.recipe === 'keep-policy-bearer') {
    return seen.session === 2 && bearer(seen.authorization[1]) && seen.promote === 1 && bearer(seen.promoteAuth[0])
      && seen.proposal === 2 && seen.proposalAuth.every(bearer) && seen.pages === 1;
  }
  return false;
}

function replyBytes(reply) {
  if (reply.raw !== undefined) return Buffer.from(reply.raw);
  return Buffer.from(JSON.stringify(reply.body));
}

async function runCase(origin, item) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'kronik-ui-'));
  const args = [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
    '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync',
    `--user-data-dir=${profile}`, `${origin}/ui/?case=${item.name}${item.hash || ''}`,
  ];
  const child = spawn(chromeBin, args, { stdio: ['ignore', 'ignore', 'pipe'], detached: true });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const result = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ ok: false, detail: 'chrome timeout', stderr }), 15000);
    function done(value) {
      clearTimeout(timer);
      resolve(value);
    }
    child.on('exit', (code) => done({ ok: false, detail: `chrome exited ${code}`, stderr }));
    global.currentResult = done;
  });
  try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ }
  fs.rmSync(profile, { recursive: true, force: true });
  return result;
}

async function main() {
  if (!fs.existsSync(chromeBin)) throw new Error(`chrome not found: ${chromeBin}`);
  let current = null;
  const seen = { session: 0, actors: 0, proposal: 0, promote: 0, pages: 0, released: false, authorization: [], actorAuth: [], proposalAuth: [], promoteAuth: [], served: { session: 0, actors: 0 }, servedAuth: { session: [], actors: [] } };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && (url.pathname === '/ui' || url.pathname === '/ui/')) {
      seen.pages += 1;
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
    if (req.method === 'GET' && (url.pathname === '/ui/app.js' || url.pathname === '/ui/app.css')) {
      const file = path.basename(url.pathname);
      const type = file.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8';
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
      res.end(fs.readFileSync(path.join(ui, file)));
      return;
    }
    if (req.method === 'POST' && url.pathname === '/release') {
      seen.released = true;
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method === 'POST' && url.pathname === '/result') {
      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        res.writeHead(204);
        res.end();
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (global.currentResult) global.currentResult({ ...body, stderr: '', seen: {
          ...seen, authorization: [...seen.authorization], actorAuth: [...seen.actorAuth],
          proposalAuth: [...seen.proposalAuth], promoteAuth: [...seen.promoteAuth],
          served: { ...seen.served }, servedAuth: { session: [...seen.servedAuth.session], actors: [...seen.servedAuth.actors] },
        } });
      });
      return;
    }
    if (!current) {
      res.writeHead(500);
      res.end();
      return;
    }
    const route = url.pathname === '/v1/auth/session' ? 'session'
      : url.pathname === '/v1/actors' ? 'actors'
      : url.pathname === '/v1/proposals/p-1' && req.method === 'GET' ? 'proposal'
      : url.pathname === '/v1/proposals/p-1/promote' && req.method === 'POST' ? 'promote'
      : '';
    if (!route) {
      res.writeHead(404, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: url.pathname } }));
      return;
    }
    seen[route] += 1;
    const authorization = req.headers.authorization || '';
    seen.authorization.push(authorization);
    if (route === 'actors') seen.actorAuth.push(authorization);
    if (route === 'proposal') seen.proposalAuth.push(authorization);
    if (route === 'promote') seen.promoteAuth.push(authorization);
    const hold = current.network && !seen.released && (
      current.network === route || (current.network === 'session-after-1' && route === 'session' && seen.session > 1)
    );
    if (hold) {
      res.destroy();
      return;
    }
    const reply = current[route](seen[route], req.headers);
    if (reply.drop) {
      res.destroy();
      return;
    }
    if (route === 'session' || route === 'actors') {
      seen.served[route] += 1;
      seen.servedAuth[route].push(authorization);
    }
    const send = () => {
      res.writeHead(reply.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(replyBytes(reply));
    };
    if (req.method === 'POST') {
      req.on('end', send);
      req.resume();
      return;
    }
    send();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const failures = [];
  try {
    for (const item of cases) {
      current = item;
      seen.session = 0;
      seen.actors = 0;
      seen.proposal = 0;
      seen.promote = 0;
      seen.pages = 0;
      seen.released = false;
      seen.authorization = [];
      seen.actorAuth = [];
      seen.proposalAuth = [];
      seen.promoteAuth = [];
      seen.served = { session: 0, actors: 0 };
      seen.servedAuth = { session: [], actors: [] };
      const result = await runCase(origin, item);
      const network = result.seen ? expects(item, result.seen) : false;
      if (!result.ok || result.loads !== 1 || !network) {
        failures.push(`${item.name}: ${result.detail || 'network'} loads=${result.loads} network=${network} status=${result.status || ''} field=${result.field || ''}`);
        console.error('FAIL', item.name, result.detail);
      } else {
        console.log('ok', item.name);
      }
    }
  } finally {
    server.close();
  }
  if (failures.length) {
    console.error(failures.join('\n'));
    process.exit(1);
  }
  console.log(`ok ${cases.length} session-retry cases`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
