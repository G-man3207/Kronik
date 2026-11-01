#!/usr/bin/env node
'use strict';
/* Finite M27 synthetic acceptance, launched by e2e-ui-oidc.py over private stdin.
 * Explicit installed @playwright/test and axe-core paths; never installs packages.
 * No screenshots/traces/HAR/storageState: those can retain PII or credentials.
 * The enclosing runner MUST have an isolated-loopback resource-bounded sandbox.
 */
const fs = require('node:fs');
const https = require('node:https');
const http = require('node:http');
const crypto = require('node:crypto');
const path = require('node:path');
const readline = require('node:readline');

const checks = [];
const observations = {};
let browser;
let activeCheck = 'input';
let deadline;
let evidenceDir;
let allowedOrigins = new Set();
function check(value, name) {
  activeCheck = name;
  if (!value) throw new Error(name);
  checks.push(name);
}
function localOrigin(value) {
  const url = new URL(value);
  check(url.protocol === 'https:' && ['localhost', '127.0.0.1'].includes(url.hostname) && url.port && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'explicit-local-TLS-origin');
  return url.origin;
}
function transport(url, {method = 'GET', headers = {}, data, socketPath, ca} = {}) {
  return new Promise((resolve, reject) => {
    const body = data === undefined ? null : Buffer.from(typeof data === 'string' ? data : JSON.stringify(data));
    const parsed = new URL(url);
    if (socketPath ? parsed.origin !== 'http://localhost' : !allowedOrigins.has(parsed.origin)) {
      reject(new Error('refusing-unowned-endpoint'));
      return;
    }
    const request = (socketPath ? http : https).request({hostname: parsed.hostname, port: parsed.port, family: 4,
      path: parsed.pathname + parsed.search, method, socketPath, ca,
      headers: {...headers, ...(body ? {'Content-Length': body.length} : {})}, timeout: 5000}, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 16 * 1024 * 1024) request.destroy(new Error('bounded-response'));
        else chunks.push(chunk);
      });
      response.on('end', () => resolve({status: response.statusCode, headers: response.headers, text: Buffer.concat(chunks).toString('utf8')}));
    });
    request.on('error', () => reject(new Error('fixture-transport')));
    request.on('timeout', () => request.destroy(new Error('fixture-timeout')));
    if (body) request.write(body);
    request.end();
  });
}

async function main() {
  const controlLines = readline.createInterface({input: process.stdin, crlfDelay: Infinity})[Symbol.asyncIterator]();
  const first = await controlLines.next();
  check(!first.done && first.value.length < 65536, 'bounded-private-input');
  const config = JSON.parse(first.value);
  evidenceDir = config.artifacts;
  deadline = setTimeout(async () => {
    process.stderr.write('browser-acceptance-timeout\n');
    process.stderr.write('Assertion failed: ' + activeCheck.replace(/[^a-zA-Z0-9_ /:,{}.-]/g, '').slice(0, 240) + '\n');
    if (browser) await browser.close().catch(() => {});
    process.exit(1);
  }, config.timeout_ms);
  async function restart(profile) {
    check(['unreachable', 'mismatch', 'correct'].includes(profile), 'owned-restart-profile');
    process.stdout.write(JSON.stringify({action: 'restart', profile}) + '\n');
    const reply = await controlLines.next();
    check(!reply.done && reply.value.length < 256 && JSON.parse(reply.value).ok === true, 'owned-daemon-restarted-' + profile);
  }
  async function inspectApprovalProtection(principal, proposal, lsns, native) {
    fs.writeFileSync(path.join(config.artifacts, 'browser-before-key-fault-result.json'), JSON.stringify({
      synthetic_not_human: true, full_acceptance: false, pending: 'stored-key-fault-and-remaining-identity-cluster-boundaries',
      checks, observations, operations: Object.fromEntries([...observed].map(([operation, rows]) => [operation, {
        requests: rows.length, success: rows.filter(row => row.status >= 200 && row.status < 400).length,
      }])),
    }, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    process.stdout.write(JSON.stringify({action: 'approval_protection', principal, proposal, lsns, native}) + '\n');
    const reply = await controlLines.next();
    check(!reply.done && reply.value.length < 512, 'bounded-private-approval-protection-result');
    const result = JSON.parse(reply.value);
    check(result.ok === true && result.approvals === 2 && result.native_legacy === true &&
      result.missing_key_status === 503 && result.restored_status === 200,
      'stored-OFF-and-ON-OIDC-approvals-sealed-native-legacy-and-missing-key-fails-closed');
  }
  async function inspectGatewayCookieBoundary() {
    const gateway = localOrigin(config.gateway);
    check(new URL(gateway).hostname === new URL(origin).hostname &&
      new URL(gateway).port !== new URL(origin).port, 'real-app-listener-shares-cookie-host-not-admin-port');
    const before = await context.cookies(origin);
    const original = before.find(cookie => cookie.name === '__Host-kronik-session');
    check(original?.httpOnly && original.secure, 'real-HttpOnly-admin-cookie-before-app-request');
    const appCookie = 'm27-app-' + crypto.randomBytes(16).toString('hex');
    await context.addCookies([{name: 'm27app', value: appCookie, url: gateway, secure: true, sameSite: 'Lax'}]);
    const appPage = await context.newPage();
    let result;
    try {
      const excludedAsset = await appPage.goto(gateway + '/ui/app.js');
      check(excludedAsset.status() === 404, 'embedded-admin-assets-are-not-mounted-on-real-app-listener');
      const landing = await appPage.goto(gateway + '/counter/m27-cookie-boundary');
      check(landing.status() === 200, 'real-browser-app-origin-loaded');
      const sent = appPage.waitForRequest(request => request.method() === 'POST' &&
        new URL(request.url()).origin === gateway && new URL(request.url()).pathname === '/counter/m27-cookie-boundary/respond');
      result = await appPage.evaluate(async () => {
        const response = await fetch('/counter/m27-cookie-boundary/respond', {
          method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'text/plain'},
          body: '200\nSet-Cookie: __Host-kronik-session=guest-overwrite; Secure; HttpOnly; Path=/; SameSite=Lax\n' +
            'Set-Cookie: __Host-kronik-login=guest-flow-overwrite; Secure; HttpOnly; Path=/; SameSite=Lax\n' +
            'Set-Cookie: m27app=application-response-retained; Secure; Path=/; SameSite=Lax\n\nCookie boundary fixture.',
        });
        return {status: response.status, turn: response.headers.get('kronik-turn-id'), text: await response.text()};
      });
      const headers = await (await sent).allHeaders();
      check(headers.cookie?.includes('__Host-kronik-session=' + original.value) &&
        headers.cookie.includes('m27app=' + appCookie), 'real-browser-sends-admin-and-app-cookie-to-other-port');
      check(result.status === 200 && result.text === 'Cookie boundary fixture.' &&
        /^main:[1-9][0-9]*$/.test(result.turn), 'real-app-cookie-response-has-committed-native-turn');
    } finally { await appPage.close(); }
    const after = await context.cookies(origin);
    check(after.find(cookie => cookie.name === '__Host-kronik-session')?.value === original.value &&
      after.find(cookie => cookie.name === '__Host-kronik-login')?.value === before.find(cookie => cookie.name === '__Host-kronik-login')?.value,
      'guest-cannot-overwrite-admin-session-or-login-cookie');
    check(after.find(cookie => cookie.name === 'm27app')?.value === 'application-response-retained',
      'ordinary-guest-Set-Cookie-still-reaches-real-browser');
    process.stdout.write(JSON.stringify({action: 'gateway_cookie_protection', turn: result.turn,
      session_value: original.value, app_cookie: appCookie}) + '\n');
    const reply = await controlLines.next();
    check(!reply.done && reply.value.length < 256, 'bounded-private-gateway-cookie-proof-result');
    const proof = JSON.parse(reply.value);
    check(proof.ok === true && proof.recorded === true,
      'real-browser-admin-cookie-absent-and-app-cookie-present-in-guest-WAL');
    check((await session()).authenticated, 'app-cookie-boundary-preserves-original-admin-session');
  }
  const origin = localOrigin(config.origin);
  const issuer = localOrigin(config.issuer);
  check(new URL(origin).hostname === 'localhost' && new URL(issuer).hostname === '127.0.0.1',
    'real-cross-site-OIDC-callback-with-host-only-cookie-isolation');
  allowedOrigins = new Set([origin, issuer, ...(config.focus === 'stream-auth' ? [] : [localOrigin(config.gateway)])]);
  check(/^[A-Za-z0-9+/]{43}=$/.test(config.tls_spki), 'owned-TLS-public-key-pin');
  const ca = fs.readFileSync(config.ca);
  let chromium;
  try { ({chromium} = require(config.playwright)); }
  catch { check(false, 'missing-installed-playwright-no-autoinstall'); }
  if (config.focus !== 'stream-auth') check(fs.existsSync(config.axe), 'installed-axe-required');
  const specReply = await transport(origin + '/v1/openapi.json', {ca, headers: {Authorization: 'Bearer ' + config.bearer}});
  check(specReply.status === 200, 'public-openapi-available');
  const spec = JSON.parse(specReply.text);
  const operations = [];
  for (const [template, methods] of Object.entries(spec.paths)) {
    const regex = new RegExp('^' + template.split('/').map(part => part.startsWith('{') && part.endsWith('}') ? '[^/]+' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('/') + '$');
    for (const method of Object.keys(methods)) if (['get', 'post', 'put', 'patch', 'delete', 'options', 'head'].includes(method)) operations.push({method: method.toUpperCase(), template, regex});
  }
  const observed = new Map();
  const violations = [];
  const responseTasks = new Set();
  const responseBodies = new WeakMap();
  const sentinel = 'M27_PRIVATE_SENTINEL_' + crypto.randomBytes(16).toString('hex');
  const encodedSentinel = Buffer.from(sentinel).toString('base64');
  let denyPII = false;
  const rawTokens = new Set([config.bearer, config.admin_bearer, config.control]);
  let callbackReplay = null;
  let bearerRequests = 0;
  activeCheck = 'browser-launch';
  browser = await chromium.launch({executablePath: config.chrome, headless: true,
    args: ['--disable-background-networking', '--disable-component-update', '--no-first-run', '--disable-sync', '--disable-default-apps',
      '--ignore-certificate-errors-spki-list=' + config.tls_spki]});
  activeCheck = 'browser-context';
  const context = await browser.newContext({ignoreHTTPSErrors: false, viewport: {width: 1280, height: 900}, serviceWorkers: 'block'});
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (!allowedOrigins.has(url.origin)) {
      violations.push('external-browser-request');
      await route.abort();
    } else {
      await route.continue();
    }
  });
  context.on('request', request => {
    const url = new URL(request.url());
    for (const token of rawTokens) if (request.url().includes(token) || (request.postData() || '').includes(token)) violations.push('raw-token-outside-Authorization');
    if (url.origin !== origin) return;
    const matches = operations.filter(item => item.method === request.method() && item.regex.test(url.pathname));
    if (matches.length !== 1) violations.push('undocumented-method-path');
    else {
      const operation = matches[0];
      const key = operation.method + ' ' + operation.template;
      const rows = observed.get(key) || [];
      rows.push({body: request.postData(), status: null});
      observed.set(key, rows);
    }
  });
  context.on('response', response => {
    if (new URL(response.url()).origin !== origin ||
        response.request().resourceType() === 'eventsource' ||
        (response.status() >= 300 && response.status() < 400) ||
        !/(json|javascript|^text\/)/.test(response.headers()['content-type'] || '')) return;
    // Start before navigation can evict Chrome's completed-response body cache.
    responseBodies.set(response.request(), response.body().then(
      body => ({body: body.toString('utf8')}), error => ({error})));
  });
  context.on('requestfinished', request => {
    let stage = 'completed-response';
    let operationName = 'unclassified';
    let status = 0;
    let timer;
    // A response event precedes body completion; navigation can cancel that body.
    const inspection = (async () => {
      const response = await request.response();
      if (!response) throw new Error('missing-completed-response');
      const url = new URL(response.url());
      status = response.status();
      const match = operations.find(item => item.method === request.method() && item.regex.test(url.pathname));
      operationName = url.origin === origin && match ? match.method + ' ' + match.template :
        url.origin === issuer ? 'owned-provider' : 'owned-gateway';
      stage = 'completed-headers';
      const headers = await request.allHeaders();
      if (headers.authorization) {
        if (headers.authorization !== 'Bearer ' + config.bearer || headers.cookie) violations.push('bearer-transport-boundary');
        bearerRequests += 1;
      }
      if (url.origin !== origin) return;
      const operation = operations.find(item => item.method === request.method() && item.regex.test(url.pathname));
      if (operation) {
        const rows = observed.get(operation.method + ' ' + operation.template) || [];
        const row = rows.find(item => item.status === null && item.body === request.postData());
        if (row) row.status = response.status();
      }
      if (!(response.status() >= 300 && response.status() < 400) &&
          response.request().resourceType() !== 'eventsource' &&
          /(json|javascript|^text\/)/.test(response.headers()['content-type'] || '')) {
        stage = 'completed-body';
        const captured = await responseBodies.get(request);
        if (!captured || captured.error) throw captured?.error || new Error('missing-completed-response-body');
        const body = captured.body;
        if (denyPII && (body.includes(sentinel) || body.includes(encodedSentinel))) violations.push('PII-in-denied-response');
        for (const token of rawTokens) if (body.includes(token)) violations.push('raw-token-in-response');
      }
    })();
    const task = Promise.race([inspection, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('bounded-network-inspection')), 5000);
    })]).catch(error => {
      const message = String(error.message || '');
      observations.network_inspection_failure = {
        stage, operation: operationName, status, body_evicted: /No resource with given identifier|No data found for resource/.test(message),
        cancelled: /ERR_ABORTED|request was canceled|Request cancelled/.test(message),
        target_closed: /Target.*closed|context.*closed|page.*closed/.test(message),
        timed_out: message === 'bounded-network-inspection',
      };
      violations.push('response-inspection-failed-' + stage);
    }).finally(() => clearTimeout(timer));
    responseTasks.add(task);
    task.finally(() => responseTasks.delete(task));
  });
  activeCheck = 'browser-page';
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', () => violations.push('uncaught-browser-error'));
  async function mode(value) {
    const result = await transport(issuer + '/fixture/control', {ca, method: 'POST', headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + config.control}, data: {mode: value}});
    check(result.status === 200, 'owned-provider-control-' + value);
    return JSON.parse(result.text);
  }
  async function session() {
    const result = await context.request.get(origin + '/v1/auth/session');
    check(result.status() === 200, 'session-status');
    return result.json();
  }
  async function api(method, route, body, headers = {}, expected = 200) {
    check(operations.filter(item => item.method === method && item.regex.test(new URL(origin + route).pathname)).length === 1, 'seed-and-security-operation-in-public-OpenAPI');
    const current = await session();
    const response = await context.request.fetch(origin + route, {method, headers: {'Content-Type': 'application/json', Origin: origin,
      ...(current.csrf_token ? {'X-Kronik-CSRF': current.csrf_token} : {}), ...headers}, ...(body === undefined ? {} : {data: body})});
    observations.last_api = {actual_status: response.status(), expected_status: expected};
    check(response.status() === expected, method + '-ordinary-API-' + route.replace(/main:[0-9]+/g, '{turn}').replace(/p-[a-f0-9]+/g, '{proposal}'));
    const value = await response.json();
    if (denyPII) check(!JSON.stringify(value).includes(sentinel) && !JSON.stringify(value).includes(encodedSentinel), 'PII-denied-ordinary-response');
    return value;
  }
  async function localControl(method, data, expected = 200) {
    const reply = await transport('http://localhost/v1/auth/config', {
      socketPath: config.socket, method, headers: {'Content-Type': 'application/json'}, data});
    check(reply.status === expected, 'ordinary-local-auth-config-' + method + '-' + expected);
    return JSON.parse(reply.text);
  }
  async function adminControl(method, data) {
    const reply = await transport(origin + '/v1/auth/config', {
      ca, method, headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + config.admin_bearer}, data});
    check(reply.status === 200, 'ordinary-M5-Admin-auth-config-' + method);
    return JSON.parse(reply.text);
  }
  const trustedProfile = {
    issuer, client_id: 'kronik-ui', redirect_uri: origin + '/v1/auth/callback', ca_file: config.ca,
    bindings: ['reviewer', 'reader', 'revoked'].map(name => ({subject: 'fixture-' + name, token: 'ui-' + name})),
  };
  const wrongCAProfile = {...trustedProfile, ca_file: config.excluded_ca};
  async function admit(profile, label) {
    return adminControl('PUT', {config: profile, reason: 'Synthetic recovery ' + label, dry_run: false});
  }
  const sameReceipt = (left, right) => left.digest === right.digest && JSON.stringify(left.source) === JSON.stringify(right.source);
  async function inactive(reason, label) {
    await context.clearCookies();
    const current = await session();
    check(current.authenticated === false && current.oidc_enabled === false && current.oidc_reason === reason, 'inactive-session-' + label);
    const denied = await context.request.get(origin + '/v1/auth/login', {maxRedirects: 0});
    check(denied.status() === 503 &&
      !(denied.headers()['set-cookie'] || '').includes('__Host-kronik-session='), 'inactive-login-503-' + label);
    const local = await localControl('GET');
    const remote = await adminControl('GET');
    check(!local.active && local.oidc_reason === reason && sameReceipt(local, remote), 'ordinary-Unix-and-M5-Admin-survive-' + label);
    for (const [url, options] of [
      ['http://localhost/v1/actors', {socketPath: config.socket}],
      [origin + '/v1/actors', {ca, headers: {Authorization: 'Bearer ' + config.admin_bearer}}],
    ]) check((await transport(url, options)).status === 200, 'ordinary-authorized-product-read-survives-' + label);
    return local;
  }
  async function stalePendingAfter(transition, label) {
    const oldSession = (await context.cookies(origin)).find(cookie => cookie.name === '__Host-kronik-session');
    check(oldSession, 'real-old-epoch-session-exists-' + label);
    await context.clearCookies();
    const before = (await mode('valid')).stats;
    const pending = await transport(origin + '/v1/auth/login', {ca});
    const binding = (pending.headers['set-cookie'] || []).find(value => value.startsWith('__Host-kronik-login='));
    check([302, 303].includes(pending.status) && binding, 'real-old-epoch-browser-binding-issued-' + label);
    const authorization = await transport(pending.headers.location, {ca});
    check(authorization.status === 302 && new URL(authorization.headers.location).origin === origin,
      'real-old-epoch-code-state-nonce-PKCE-issued-' + label);
    await transition();
    const denied = await transport(authorization.headers.location, {ca, headers: {Cookie: binding.split(';')[0]}});
    check([401, 503].includes(denied.status) &&
      !(denied.headers['set-cookie'] || []).some(value => /^__Host-kronik-session=([^;]+)/.test(value)),
      'old-pending-callback-cannot-mint-session-after-' + label);
    check((await context.cookies(origin)).every(cookie => cookie.name !== '__Host-kronik-session') &&
      !(await session()).authenticated &&
      (await context.request.get(origin + '/v1/actors')).status() === 401, 'old-pending-callback-has-no-new-authority-' + label);
    check((await mode('valid')).stats.authorizations === before.authorizations + 1, 'old-epoch-negative-uses-real-issuer-grant-' + label);
    check((await transport(origin + '/v1/actors', {ca, headers: {Cookie: '__Host-kronik-session=' + oldSession.value}})).status === 401,
      'old-session-is-not-upgraded-after-' + label);
    await login('valid');
    check((await context.request.get(origin + '/v1/actors')).status() === 200, 'fresh-browser-authority-after-' + label);
  }
  async function login(selected = 'valid', success = true) {
    await drain();
    await context.clearCookies();
    const before = (await mode(selected)).stats;
    await page.goto(origin + '/ui/');
    await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
    await drain();
    const callbackWait = page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.origin === origin && url.pathname === '/v1/auth/callback';
    });
    const sessionReady = success ? page.waitForResponse(response =>
      new URL(response.url()).origin === origin && new URL(response.url()).pathname === '/v1/auth/session') : null;
    await page.locator('#login-link').click();
    const callbackResponse = await callbackWait;
    // Redirected callback evidence comes from the real response, not interception.
    const callbackHeaders = await callbackResponse.request().allHeaders();
    callbackReplay = {url: callbackResponse.url(), cookie: callbackHeaders.cookie || ''};
    check(success ? [302, 303].includes(callbackResponse.status()) : callbackResponse.status() === 401, 'OIDC-callback-validation-' + selected);
    await page.waitForURL(url => url.origin === origin && !url.pathname.endsWith('/v1/auth/login'), {timeout: 15000});
    if (sessionReady) await (await sessionReady).finished();
    const current = await session();
    check(current.authenticated === success, 'OIDC-session-' + selected);
    const after = (await mode(selected)).stats;
    const exchanges = selected === 'state' ? 0 : 1;
    check(after.authorizations === before.authorizations + 1 &&
      after.exchanges === before.exchanges + exchanges &&
      after.pkce_verified === before.pkce_verified + exchanges, 'actual-provider-trust-path-' + selected);
    if (success) {
      check(current.identity && current.identity.issuer === issuer && current.identity.subject.startsWith('fixture-'), 'dummy-bound-identity-' + selected);
      check(/^oidc:[a-f0-9]{64}$/.test(current.principal), 'own-session-opaque-protected-principal-' + selected);
      check(Array.isArray(current.scopes) && typeof current.csrf_token === 'string' && current.expires_at_ms > Date.now(), 'bounded-scoped-session-' + selected);
      const cookie = (await context.cookies(origin)).find(item => item.name === '__Host-kronik-session');
      check(cookie && cookie.httpOnly && cookie.secure && cookie.sameSite === 'Lax' && cookie.path === '/', 'secure-cookie-' + selected);
      check(!(await page.evaluate(() => document.cookie)).includes('__Host-kronik-session'), 'HttpOnly-unreadable-' + selected);
      await page.waitForURL(url => url.origin === origin && url.pathname === '/ui/');
      await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
      await drain();
    }
    return current;
  }
  async function logout(dryRun = false) {
    await page.locator('#logout-reason').fill('Synthetic fixture logout; not human proof');
    await page.locator('#logout-dry-run').setChecked(dryRun);
    await Promise.all([page.waitForResponse(response => new URL(response.url()).pathname === '/v1/auth/logout' && response.request().method() === 'POST'), page.locator('#logout-button').click()]);
    await page.waitForFunction(() => !document.getElementById('logout-button').disabled);
    await drain();
    check((await session()).authenticated === dryRun, dryRun ? 'logout-dry-run-preserves-session' : 'logout-revokes-session');
  }
  async function drain() {
    while (responseTasks.size) await Promise.all([...responseTasks]);
    check(violations.length === 0, violations[0] || 'no-browser-or-network-violations');
  }
  async function storageSafe(label) {
    await drain();
    await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
    const state = await page.evaluate(async () => ({local: {...localStorage}, session: {...sessionStorage},
      dom: document.documentElement.outerHTML, indexed: typeof indexedDB.databases === 'function' ? await indexedDB.databases() : [],
      caches: typeof caches === 'object' ? await caches.keys() : [], cookies: document.cookie}));
    const persistent = JSON.stringify({local: state.local, session: state.session, indexed: state.indexed, caches: state.caches, cookies: state.cookies});
    check(Object.keys(state.local).length === 0 && Object.keys(state.session).length === 0 && state.indexed.length === 0 && state.caches.length === 0, 'no-credential-or-PII-persistence-' + label);
    for (const token of rawTokens) check(!persistent.includes(token), 'bearer-not-persisted-' + label);
    if (denyPII) check(!JSON.stringify(state).includes(sentinel) && !JSON.stringify(state).includes(encodedSentinel), 'PII-not-in-DOM-or-storage-' + label);
  }
  async function accessibility(label) {
    await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
    await page.evaluate(fs.readFileSync(config.axe, 'utf8'));
    for (const [variant, width, height, forcedColors] of [
      ['desktop', 1280, 900, 'none'], ['responsive', 375, 812, 'none'],
      ['high-contrast', 1280, 900, 'active'], ['responsive-high-contrast', 375, 812, 'active'],
    ]) {
      activeCheck = 'axe-' + label + '-' + variant;
      await page.setViewportSize({width, height});
      await page.emulateMedia({forcedColors});
      const result = await page.evaluate(async () => {
        const report = await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']}});
        return report.violations.map(item => ({id: item.id, count: item.nodes.length}));
      });
      check(result.length === 0, 'WCAG22AA-' + label + '-' + variant + (result.length ? '-' + result.map(item => item.id).join(',') : ''));
      check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'no-horizontal-overflow-' + label + '-' + variant);
      check(await page.locator('#status[role="status"]').count() === 1 && await page.locator('#error[role="alert"]').count() === 1, 'accessible-announcements-' + label + '-' + variant);
    }
    await page.emulateMedia({forcedColors: 'none'});
    await page.setViewportSize({width: 1280, height: 900});
    await storageSafe(label);
  }
  async function navigate(id, expectedPath, label) {
    activeCheck = 'navigate-' + label;
    const response = page.waitForResponse(reply => new URL(reply.url()).pathname === expectedPath && reply.request().method() === 'GET');
    const targetHash = await page.locator(id).getAttribute('href');
    const control = new URL(page.url()).hash === targetHash ? page.locator('#refresh-button') : page.locator(id);
    await control.focus();
    await page.keyboard.press('Enter');
    const received = await response;
    check(received.status() === 200, 'real-view-response-' + label);
    await page.locator('#view-title').waitFor({state: 'visible'});
    check(await page.locator('#view-title').evaluate(element => document.activeElement === element), 'keyboard-navigation-focus-' + label);
    check(await page.locator(id).getAttribute('aria-current') === 'page' &&
      await page.locator('nav [aria-current="page"]').count() === 1, 'keyboard-current-view-semantics-' + label);
    await accessibility(label);
    return received.json();
  }
  async function openTurn(id, label) {
    await page.locator('#nav-turn').focus();
    await page.keyboard.press('Enter');
    await page.locator('#turn-id').waitFor({state: 'visible'});
    await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
    check(await page.locator('#view-title').evaluate(element => document.activeElement === element), 'keyboard-navigation-focus-' + label);
    check(await page.locator('#nav-turn').getAttribute('aria-current') === 'page' &&
      await page.locator('nav [aria-current="page"]').count() === 1, 'keyboard-current-view-semantics-' + label);
    await accessibility(label + '-entry');
    await page.locator('#turn-id').fill(id);
    await page.locator('#turn-id').focus();
    await page.keyboard.press('Tab');
    check(await page.locator('#turn-form button[type="submit"]').evaluate(element => document.activeElement === element), 'keyboard-turn-id-to-submit-' + label);
    const detailWait = page.waitForResponse(reply => new URL(reply.url()).pathname === '/v1/turns/' + encodeURIComponent(id) && reply.request().method() === 'GET');
    const traceWait = page.waitForResponse(reply => new URL(reply.url()).pathname === '/v1/turns/' + encodeURIComponent(id) + '/trace' && reply.request().method() === 'GET');
    await page.keyboard.press('Enter');
    check((await detailWait).status() === 200, 'real-turn-detail-response-' + label);
    const traceReply = await traceWait;
    check(traceReply.status() === 200, 'real-causal-trace-response-' + label);
    await page.locator('#causal-tree').waitFor({state: 'attached'});
    check(await page.locator('#view-title').evaluate(element => document.activeElement === element), 'keyboard-turn-submit-focus-' + label);
    return traceReply.json();
  }
  async function submitMutation(name, route, dryRun) {
    await page.waitForFunction(id => {
      const button = document.getElementById(id);
      return button && !button.disabled;
    }, name + '-button');
    await page.locator('#' + name + '-reason').fill('Synthetic M27 acceptance ' + name);
    await page.locator('#' + name + '-dry-run').setChecked(dryRun);
    const responseWait = page.waitForResponse(reply => new URL(reply.url()).pathname === route && reply.request().method() === 'POST');
    await page.locator('#' + name + '-reason').focus();
    await page.keyboard.press('Tab');
    check(await page.locator('#' + name + '-dry-run').evaluate(element => document.activeElement === element), 'keyboard-reason-to-dry-run-' + name);
    await page.keyboard.press('Tab');
    check(await page.locator('#' + name + '-button').evaluate(element => document.activeElement === element), 'keyboard-dry-run-to-submit-' + name);
    await page.keyboard.press('Enter');
    const response = await responseWait;
    check(response.status() === 200, 'successful-' + name + '-' + dryRun);
    const body = response.request().postDataJSON();
    check(body.reason === 'Synthetic M27 acceptance ' + name && body.dry_run === dryRun, 'actual-reason-dry-run-' + name + '-' + dryRun);
    const result = await response.json();
    check(result.dry_run === dryRun, 'public-mutation-result-' + name + '-' + dryRun);
    if (name === 'resend') check(dryRun ? result.turn_id === null : typeof result.turn_id === 'string' && result.outcome?.kind === 'committed', 'real-resend-outcome-' + dryRun);
    const label = {approve: 'Approve proposal', promote: 'Promote proposal', resend: 'Resend dead letter'}[name];
    await page.locator('#' + name + '-result h3').filter({hasText: dryRun ? 'Dry run result — nothing changed' : label + ' result'}).waitFor({state: 'visible'});
    await storageSafe(name + '-' + dryRun);
    return result;
  }

  if (config.focus === 'stream-auth') {
    const source = config.stream_source;
    check(['actor-native', 'metadata'].includes(source), 'explicit-real-native-or-metadata-stream-source');
    for (const route of ['/v1/events', '/v1/events/stream', '/v1/events/ws', '/v1/tokens']) {
      check(operations.some(item => item.template === route && item.method === (route === '/v1/tokens' ? 'POST' : 'GET')),
        'independent-stream-operation-is-public-OpenAPI-' + route);
    }
    const activated = await admit(trustedProfile, 'independent-stream-only');
    check(activated.active && activated.oidc_reason == null, 'ordinary-admin-activates-real-stream-login');
    const reviewer = await login('valid');
    check(reviewer.scopes.includes('admin'), 'stream-principal-has-actual-admin-scope');
    const oldCookie = (await context.cookies(origin)).find(cookie => cookie.name === '__Host-kronik-session');
    check(oldCookie?.httpOnly && oldCookie.secure, 'original-stream-session-is-real-HttpOnly-cookie');
    async function eventPage(cursor) {
      const query = new URLSearchParams({source, limit: '256'});
      if (cursor) query.set('cursor', JSON.stringify(cursor));
      const reply = await transport(origin + '/v1/events?' + query, {ca,
        headers: {Authorization: 'Bearer ' + config.admin_bearer}});
      check(reply.status === 200, 'actual-ordinary-admin-event-page');
      const value = JSON.parse(reply.text);
      check(Array.isArray(value.events) && value.events.length <= 256 &&
        value.cursor?.schema === 'kronik.events-cursor/v1' && value.cursor.streams?.[source],
        'actual-configured-source-cursor-not-invented-node-zero');
      return value;
    }
    async function createProbe(label, cursor) {
      const reply = await transport(origin + '/v1/tokens', {ca, method: 'POST',
        headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + config.admin_bearer},
        data: {name: 'ui-stream-' + label + '-' + crypto.randomBytes(8).toString('hex'), scopes: ['read'],
          reason: 'Independent browser stream authentication fixture', dry_run: false}});
      check(reply.status === 200, 'real-ordinary-token-operation-' + label);
      const created = JSON.parse(reply.text);
      check(typeof created.secret === 'string', 'probe-token-is-real-not-mocked-' + label);
      rawTokens.add(created.secret);
      const value = await eventPage(cursor);
      const matches = value.events.filter(event => event.schema === 'kronik.event/v1' && event.data?.action === 'token.create');
      check(value.more === false && matches.length === 1 && typeof matches[0].id === 'string' && matches[0].source,
        'distinct-real-durable-token-event-identity-' + label);
      return {event: matches[0], cursor: value.cursor};
    }
    let baseline;
    for (let pages = 0; pages < 16; pages++) {
      const value = await eventPage(baseline);
      baseline = value.cursor;
      if (!value.more) break;
      check(pages < 15, 'bounded-independent-fixture-history');
    }
    const before = await createProbe('before', baseline);
    const expected = new Map([[before.event.id, before.event]]);
    const delivered = {sse: [], ws: []};
    const network = [];
    const requests = new Map();
    let phase = 'admin';
    const cdp = await context.newCDPSession(page);
    await cdp.send('Network.enable');
    function rememberRequest(id, raw, websocket) {
      const url = new URL(raw);
      if (!websocket && url.protocol === 'wss:') return; // Observed by the actual WebSocket handshake events.
      const normalized = websocket ? 'https://' + url.host : url.origin;
      if (!['/v1/events/stream', '/v1/events/ws'].includes(url.pathname)) return;
      if (normalized !== origin || (websocket && url.protocol !== 'wss:')) {
        violations.push('unowned-stream-browser-request');
        return;
      }
      if (operations.filter(item => item.method === 'GET' && item.regex.test(url.pathname)).length !== 1) {
        violations.push('undocumented-actual-browser-stream-operation');
        return;
      }
      const row = {method: 'GET', path: url.pathname, phase, status: null};
      requests.set(id, row);
      network.push(row);
    }
    function inspectFrame(id, raw, kind, lastEventId) {
      const request = requests.get(id);
      if (!request) return;
      if (request.phase !== 'admin') violations.push('unauthorized-browser-received-stream-frame');
      if (raw.length > 1 << 20) { violations.push('unbounded-stream-frame'); return; }
      for (const token of rawTokens) if (raw.includes(token)) violations.push('raw-credential-in-stream-frame');
      try {
        const event = JSON.parse(raw);
        if (event.schema !== 'kronik.event/v1') return; // Real cursor/gap/error controls are not operational data.
        if (typeof event.id !== 'string' || !event.source || !event.data?.record_hash) throw new Error();
        if (delivered[kind].length >= 256) throw new Error();
        delivered[kind].push(event.id);
        const actual = expected.get(event.id);
        if (actual && JSON.stringify(actual.source) !== JSON.stringify(event.source)) throw new Error();
        if (kind === 'sse') {
          const cursor = JSON.parse(lastEventId);
          const position = cursor.streams?.[source];
          if (cursor.schema !== 'kronik.events-cursor/v1' || !position ||
              JSON.stringify(position.source) !== JSON.stringify(event.source) ||
              position.subindex !== event.subindex + 1) throw new Error();
        }
      } catch { violations.push('invalid-actual-stream-event-or-resume-cursor'); }
    }
    cdp.on('Network.requestWillBeSent', event => rememberRequest(event.requestId, event.request.url, false));
    cdp.on('Network.responseReceived', event => {
      const row = requests.get(event.requestId);
      if (row) row.status = event.response.status;
    });
    cdp.on('Network.webSocketCreated', event => rememberRequest(event.requestId, event.url, true));
    cdp.on('Network.webSocketHandshakeResponseReceived', event => {
      const row = requests.get(event.requestId);
      if (row) row.status = event.response.status;
    });
    cdp.on('Network.eventSourceMessageReceived', event =>
      inspectFrame(event.requestId, event.data, 'sse', event.eventId));
    cdp.on('Network.webSocketFrameReceived', event => {
      if (event.response.opcode === 1) inspectFrame(event.requestId, event.response.payloadData, 'ws');
    });
    async function openStreams(cursor) {
      const query = new URLSearchParams({source, cursor: JSON.stringify(cursor)}).toString();
      await page.evaluate(({sse, ws}) => {
        const state = {sseOpen: false, sseError: false, wsOpen: false, wsClosed: false, sseIds: [], wsIds: [], invalid: false};
        const append = (raw, target) => {
          try {
            const value = JSON.parse(raw);
            if (value.schema === 'kronik.event/v1') {
              if (target.length >= 256 || typeof value.id !== 'string') throw new Error();
              target.push(value.id);
            }
          } catch { state.invalid = true; }
        };
        state.sse = new EventSource(sse);
        state.sse.onopen = () => { state.sseOpen = true; };
        state.sse.onerror = () => { state.sseError = true; };
        state.sse.addEventListener('operational', event => append(event.data, state.sseIds));
        state.ws = new WebSocket(ws);
        state.ws.onopen = () => { state.wsOpen = true; };
        state.ws.onclose = () => { state.wsClosed = true; };
        state.ws.onmessage = event => append(event.data, state.wsIds);
        window.__m27IndependentStreams = state;
      }, {sse: origin + '/v1/events/stream?' + query,
        ws: origin.replace('https:', 'wss:') + '/v1/events/ws?' + query});
    }
    async function closeStreams() {
      await page.evaluate(() => {
        const state = window.__m27IndependentStreams;
        state?.sse.close();
        state?.ws.close();
        delete window.__m27IndependentStreams;
      });
      await drain();
    }
    await openStreams(baseline);
    await page.waitForFunction(id => {
      const state = window.__m27IndependentStreams;
      return state?.sseOpen && state.wsOpen && state.sseIds.includes(id) && state.wsIds.includes(id);
    }, before.event.id);
    check(delivered.sse.includes(before.event.id) && delivered.ws.includes(before.event.id),
      'actual-browser-SSE-and-WS-observe-same-real-token-event');
    check(network.some(row => row.phase === 'admin' && row.path.endsWith('/stream') && row.status === 200) &&
      network.some(row => row.phase === 'admin' && row.path.endsWith('/ws') && row.status === 101),
      'actual-cookie-SSE200-and-WebSocket101-network');
    await logout(false);
    const after = await createProbe('after-logout-ACK', before.cursor);
    await page.waitForFunction(() => {
      const state = window.__m27IndependentStreams;
      return state?.sseError && state.wsClosed;
    });
    check(!delivered.sse.includes(after.event.id) && !delivered.ws.includes(after.event.id),
      'post-logout-ACK-new-durable-event-not-disclosed-to-revoked-streams');
    // Already-admitted older frames may complete; neither global rollback nor close code 1000 is claimed.
    await closeStreams();
    async function deniedStreams(label, status) {
      phase = label;
      await openStreams(after.cursor);
      await page.waitForFunction(() => {
        const state = window.__m27IndependentStreams;
        return state?.sseError && state.wsClosed;
      });
      check(network.some(row => row.phase === label && row.path.endsWith('/stream') && row.status === status) &&
        network.some(row => row.phase === label && row.path.endsWith('/ws') && row.status === status),
        'real-browser-stream-http-denial-' + label + '-' + status);
      check(await page.evaluate(() => {
        const state = window.__m27IndependentStreams;
        return !state.sseOpen && !state.wsOpen && !state.sseIds.length && !state.wsIds.length && !state.invalid;
      }), 'denied-cookie-receives-no-stream-feed-' + label);
      await closeStreams();
    }
    await context.addCookies([oldCookie]);
    await deniedStreams('revoked-session-reconnect', 401);
    const reader = await login('reader');
    check(!reader.scopes.includes('admin'), 'real-reader-OIDC-principal-is-not-stream-admin');
    await deniedStreams('read-only-cookie', 403);
    check((await transport(origin + '/v1/actors', {ca,
      headers: {Authorization: 'Bearer ' + config.admin_bearer}})).status === 200,
      'unrelated-ordinary-bearer-remains-working-after-self-logout');
    await eventPage(after.cursor);
    await storageSafe('independent-stream-reader');
    await drain();
    check(violations.length === 0, 'independent-stream-network-and-credential-boundaries');
    fs.writeFileSync(path.join(config.artifacts, 'browser-stream-auth-result.json'), JSON.stringify({
      synthetic_not_human: true, full_acceptance: false, scope: 'independent-cookie-stream-authentication-only',
      no_guest_fork_kernel_body_model_or_key_fault: true, source, checks, network,
      before_event_id: before.event.id, after_logout_ack_event_id: after.event.id,
      actual_source: before.event.source, received: {sse: delivered.sse.length, ws: delivered.ws.length},
      not_claimed: ['global rollback of admitted frames', 'graceful close code', 'browser Ping API',
        'whole M27/WCAG/healthy cluster/human/publicC4', 'stopped M24Fork work'],
    }, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    await cdp.detach();
    await context.close();
    return;
  }

  // Native trust includes CA1, but the configured exclusive CA2 must not inherit it.
  check((await transport(issuer + '/.well-known/openid-configuration')).status === 200,
    'real-provider-is-native-trusted-positive-control');
  await inactive('not_configured', 'unadmitted-wrong-CA-startup');
  const wrongCA = await admit(wrongCAProfile, 'admit-exclusive-wrong-CA');
  check(wrongCA.changed && !wrongCA.active && wrongCA.oidc_reason === 'provider_unavailable' &&
    /^[a-f0-9]{64}$/.test(wrongCA.digest) && wrongCA.source, 'wrong-CA-commits-without-killing-ordinary-API');
  check(sameReceipt(wrongCA, await inactive('provider_unavailable', 'exclusive-wrong-CA')),
    'wrong-CA-real-durable-receipt-remains-inactive');
  const correctCA = await admit(trustedProfile, 'correct-exclusive-CA');
  check(correctCA.changed && correctCA.active && correctCA.oidc_reason == null && !correctCA.restart_required,
    'authorized-correct-CA-activates-without-repair-endpoint');
  await login('valid');
  check((await context.request.get(origin + '/v1/actors')).status() === 200,
    'real-browser-product-access-after-wrong-CA-repair');
  await stalePendingAfter(async () => {
    await admit(wrongCAProfile, 'invalidate-pending-with-wrong-CA');
    await inactive('provider_unavailable', 'pending-repair-unavailable');
    const restored = await admit(trustedProfile, 'repair-old-pending-runtime');
    check(restored.active && restored.oidc_reason == null, 'repaired-runtime-is-active-before-old-callback');
  }, 'profile-repair');
  await stalePendingAfter(async () => {
    const original = await adminControl('GET');
    const refreshed = await admit(trustedProfile, 'same-profile-runtime-refresh');
    check(!refreshed.changed && refreshed.active && sameReceipt(original, refreshed),
      'same-profile-activation-retains-original-durable-source');
  }, 'same-source-runtime-refresh');
  const unavailable = await admit({...trustedProfile, issuer: localOrigin(config.unreachable_issuer)}, 'unreachable-owned-loopback');
  check(unavailable.changed && !unavailable.active && unavailable.oidc_reason === 'provider_unavailable',
    'unreachable-real-issuer-profile-commits-inactive');
  await inactive('provider_unavailable', 'unreachable-before-restart');
  await restart('unreachable');
  check(sameReceipt(unavailable, await inactive('provider_unavailable', 'unreachable-startup')),
    'unreachable-restart-preserves-real-durable-profile-and-native-authority');
  const reachable = await admit(trustedProfile, 'reachable-issuer-restored');
  check(reachable.active && reachable.oidc_reason == null, 'authorized-correct-profile-recovers-unreachable-issuer');
  await login('valid');
  check((await context.request.get(origin + '/v1/actors')).status() === 200,
    'real-browser-product-access-after-unreachable-repair');
  const beforeMismatch = await adminControl('GET');
  await restart('mismatch');
  check(sameReceipt(beforeMismatch, await inactive('profile_mismatch', 'valid-startup-file-mismatch')),
    'valid-file-never-auto-replaces-durable-digest-or-source');
  const reactivated = await admit(trustedProfile, 'explicit-same-durable-profile-reactivation');
  check(!reactivated.changed && reactivated.active && reactivated.oidc_reason == null &&
    sameReceipt(beforeMismatch, reactivated), 'authorized-idempotent-PUT-reactivates-mismatched-startup');
  await login('valid');
  check((await context.request.get(origin + '/v1/actors')).status() === 200,
    'real-browser-product-access-after-mismatch-reactivation');
  await restart('correct');
  await context.clearCookies();
  const matching = await adminControl('GET');
  check(matching.active && matching.oidc_reason == null && sameReceipt(reactivated, matching) &&
    (await session()).oidc_enabled, 'already-admitted-matching-startup-activates-without-new-durable-admission');
  await login('valid');
  check((await context.request.get(origin + '/v1/actors')).status() === 200,
    'real-browser-product-access-after-matching-durable-restart');
  await context.clearCookies();

  await context.addCookies([{name: '__Host-kronik-session', value: 'stale-private-session',
    url: origin, httpOnly: true, secure: true, sameSite: 'Lax'}]);
  await page.goto(origin + '/ui/');
  await page.locator('#login-link').waitFor({state: 'visible'});
  check(!(await session()).authenticated, 'stale-cookie-discovery-is-unauthenticated');
  await accessibility('unauthenticated-shell');
  const recoveryLogin = await transport(origin + '/v1/auth/login', {
    ca, headers: {Cookie: '__Host-kronik-session=stale-private-session'}});
  check(recoveryLogin.status === 303 && recoveryLogin.headers.location.startsWith(issuer + '/authorize?'),
    'stale-cookie-cannot-block-new-OIDC-flow');
  await context.clearCookies();

  // The provider denies malformed/replayed grants; product still has to prove S256.
  const verifier = crypto.randomBytes(32).toString('base64url');
  const authorization = await transport(issuer + '/authorize?' + new URLSearchParams({client_id: 'kronik-ui', response_type: 'code', redirect_uri: origin + '/v1/auth/callback', scope: 'openid', state: crypto.randomBytes(24).toString('hex'), nonce: crypto.randomBytes(24).toString('hex'), code_challenge_method: 'S256', code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url')}), {ca});
  check(authorization.status === 302, 'real-provider-code-issued');
  const code = new URL(authorization.headers.location).searchParams.get('code');
  const grant = {grant_type: 'authorization_code', client_id: 'kronik-ui', redirect_uri: origin + '/v1/auth/callback', code};
  const badGrant = await transport(issuer + '/token', {ca, method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, data: new URLSearchParams({...grant, code_verifier: 'x'.repeat(43)}).toString()});
  check(badGrant.status === 400, 'provider-enforces-PKCE');
  const replay = await transport(issuer + '/token', {ca, method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, data: new URLSearchParams({...grant, code_verifier: verifier}).toString()});
  check(replay.status === 400, 'provider-code-single-use');
  const unboundLogin = await transport(origin + '/v1/auth/login', {ca});
  check([302, 303].includes(unboundLogin.status), 'unbound-login-starts-real-flow');
  const unboundAuthorization = await transport(unboundLogin.headers.location, {ca});
  check(unboundAuthorization.status === 302, 'unbound-flow-gets-real-code');
  const unboundCallback = await transport(unboundAuthorization.headers.location, {ca});
  check(unboundCallback.status === 401 && !(unboundCallback.headers['set-cookie'] || []).some(value => value.startsWith('__Host-kronik-session=') && !value.startsWith('__Host-kronik-session=;')), 'callback-requires-browser-binding');

  const reviewer = await login();
  check(reviewer.scopes.includes('pii:read'), 'positive-control-reviewer-has-pii-read');
  const approvalIdentity = reviewer.principal;
  check(callbackReplay !== null && callbackReplay.cookie.includes('__Host-kronik-login='), 'successful-bound-callback-observed');
  const replayedCallback = await transport(callbackReplay.url, {ca, headers: {Cookie: callbackReplay.cookie}});
  check(replayedCallback.status === 401, 'successful-bound-callback-cannot-be-replayed');
  const wasm = filename => fs.readFileSync(filename).toString('base64');
  await api('POST', '/v1/deployments', {wasm_base64: wasm(config.counter), reason: 'Synthetic M27 counter deployment', dry_run: false});
  // Fork replay fixes capability policy at its base, before the recorded traffic.
  await api('POST', '/v1/grants', {kind: 'counter', capability: 'http:127.0.0.1', reason: 'Synthetic private fixture HTTP effect', dry_run: false});
  await inspectGatewayCookieBoundary();
  const send = (key, name, text = '', extra = {}) => api('POST', '/v1/actors/counter/' + key + '/messages', {name, text, reason: 'Synthetic M27 traffic', dry_run: false, ...extra});
  const gatewayReply = await transport(localOrigin(config.gateway) + '/counter/m27-root/increment', {ca, method: 'POST'});
  check(gatewayReply.status === 200, 'real-public-HTTP-response-recorded');
  await send('m27-root', 'increment');
  const turn = await send('m27-root', 'call', 'counter/m27-child increment');
  check(typeof turn.turn_id === 'string', 'real-causal-root-created');
  const privacy = await api('POST', '/v1/privacy/mode', {mode: 'on', reason: 'Synthetic M27 private-field boundary', dry_run: false});
  check(privacy.mode === 'on', 'real-server-privacy-enabled-before-private-input');
  const privateTurn = await send('m27-private', 'note', sentinel, {subject: 'm27:dummy-private-subject'});
  await send('m27-private', 'increment', '', {subject: 'm27:dummy-private-subject'});
  const privateActor = await api('GET', '/v1/actors/counter/m27-private');
  check(JSON.stringify(privateActor).includes(sentinel) || JSON.stringify(privateActor).includes(encodedSentinel), 'sentinel-positive-control-visible-with-pii-scope');
  const privateResponse = await transport(localOrigin(config.gateway) + '/counter/m27-private-response/respond', {
    ca, method: 'POST', headers: {'Content-Type': 'text/plain'},
    data: '200\nSet-Cookie: m27=' + sentinel + '; Secure; HttpOnly\n\nSynthetic credential-header fixture'});
  check(privateResponse.status === 200 && privateResponse.text === 'Synthetic credential-header fixture', 'real-credential-response-produced-before-replay');
  await send('m27-deadletter', 'flaky');
  await send('m27-deadletter', 'allow');
  const effectSeed = await send('m27-effect', 'fetch-ok', 'GET ' + config.effect + '/synthetic');
  check(effectSeed.outcome?.kind === 'committed' && effectSeed.reply?.text?.startsWith('200 '),
    'real-owned-http-effect-response');
  const effectPayload = JSON.parse(effectSeed.reply.text.slice(4));
  check(effectPayload.synthetic_fixture === true && effectPayload.value === 27,
    'real-owned-http-effect-fixture-observed');
  await api('PUT', '/v1/policy', {rules_toml: '[[rule]]\nname="m27-review"\nwhen="true"\naction="require_approval"\n', reason: 'Synthetic M27 mandatory approval policy', dry_run: false});
  const proposalReply = await api('POST', '/v1/proposals', {wasm_base64: [wasm(config.candidate)], reason: 'Synthetic M27 behavior proposal', dry_run: false, threads: 1, mode: 'both'});
  const proposal = proposalReply.proposal || proposalReply;
  check(typeof proposal.id === 'string', 'real-proposal-created');
  check(proposal.policy?.outcome === 'require_approval', 'real-proposal-requires-approval');
  const proposalRoute = '/v1/proposals/' + encodeURIComponent(proposal.id);
  const diff = await api('GET', proposalRoute + '/diff');
  // Counts and booleans diagnose the real producer without exporting private diff values.
  observations.diff = {
    responses_present: !!diff.responses, effects_present: !!diff.effects,
    state_present: !!diff.state, grounding_rows: Array.isArray(diff.grounding) ? diff.grounding.length : -1,
    root_inputs: diff.summary?.root_inputs ?? -1, replayed: diff.summary?.replayed ?? -1,
    responses_changed: diff.responses?.changed ?? -1,
    effect_items: diff.effects?.items?.length ?? -1,
    isolated_state_items: diff.state?.isolated?.length ?? -1,
    continuous_state_items: diff.state?.continuous?.length ?? -1,
    introduced_errors: diff.errors?.introduced ?? -1,
  };
  check(diff.responses && diff.effects && diff.state && Array.isArray(diff.grounding) && diff.grounding.length > 0, 'real-diff-has-response-effect-state-and-target-grounding');
  check(diff.responses.changed > 0 && (diff.state.isolated.length > 0 || diff.state.continuous.length > 0), 'nonempty-response-and-state-differences');
  check(diff.responses.items.some(item => item.route === 'POST /counter/{key}/{op}' &&
    item.status.prod === 200 && item.status.fork === 200 &&
    item.body.some(operation => operation.op === 'replace' && operation.path === '' &&
      operation.prod === 1 && operation.fork === 2)), 'real-successful-public-increment-diff-is-one-to-two');
  const privateResponseItem = diff.responses.items.find(item => item.headers.some(header =>
    header.name === 'set-cookie' && Array.isArray(header.prod) &&
    header.prod.includes('m27=' + sentinel + '; Secure; HttpOnly') && header.fork === null));
  check(privateResponseItem && privateResponseItem.status.prod === 200 &&
    privateResponseItem.status.fork === null && typeof privateResponseItem.turn_prod === 'string' &&
    typeof privateResponseItem.turn_fork === 'string', 'changed-diff-credential-entry-positive-control-with-pii-scope');
  const privateState = diff.state.isolated.find(item => item.actor === 'counter/m27-private' &&
    item.keys.some(key => key.key === 'n' && key.prod?.redacted === true && key.fork?.redacted === true &&
      key.prod.hash !== key.fork.hash));
  check(privateState && privateState.keys.some(key => key.key === 'n' &&
    /^s:[a-f0-9]{12}$/.test(key.prod.subject) && /^k:[a-f0-9]{16}$/.test(key.prod.hash)), 'subject-tagged-changed-state-has-real-server-redaction');
  const effectTarget = new URL(config.effect);
  const recordedGrounding = diff.grounding.find(row => row.kind === 'http.fetch' &&
    row.method === 'GET' && row.host === effectTarget.hostname && row.route === '/synthetic');
  check(recordedGrounding && recordedGrounding.exact > 0 && recordedGrounding.approximate === 0 &&
    recordedGrounding.synthetic === 0 && recordedGrounding.live === 0 &&
    recordedGrounding.forked === 0 && recordedGrounding.confidence === 1, 'real-recorded-target-has-exact-not-synthetic-grounding');
  const deadletters = await api('GET', '/v1/dead-letters?limit=50');
  const deadRows = deadletters.dead_letters || deadletters.deadletters;
  check(Array.isArray(deadRows) && deadRows.length > 0, 'real-dead-letter-created');
  await page.reload();
  await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
  const actors = await navigate('#nav-history', '/v1/actors', 'actor-history-list');
  check(actors.actors.some(actor => actor.key === 'm27-root'), 'history-contains-synthetic-actor');
  const historyWait = page.waitForResponse(reply => new URL(reply.url()).pathname === '/v1/actors/counter/m27-root/history');
  await page.getByTestId('actor-open').filter({hasText: 'counter/m27-root'}).focus();
  await page.keyboard.press('Enter');
  check((await historyWait).status() === 200, 'actor-history-real-response');
  await page.locator('#actor-history [data-testid="turn-open"]').first().waitFor({state: 'visible'});
  check(await page.locator('#actor-history').evaluate(element => document.activeElement === element), 'actor-selection-moves-focus-to-history');
  await accessibility('actor-history-detail');
  const trace = await openTurn(turn.turn_id, 'turn');
  check(JSON.stringify(trace).includes('m27-child'), 'causal-trace-has-real-child');
  const selectedTurnUrl = page.url();
  await page.locator('a[href="#main"]').focus();
  await page.keyboard.press('Enter');
  check(page.url() === selectedTurnUrl &&
    await page.locator('#main').evaluate(element => document.activeElement === element) &&
    await page.locator('#causal-tree').count() === 1, 'skip-link-preserves-selected-turn-and-focuses-main');
  check((await page.locator('#view-content').textContent()).includes('m27-child'), 'causal-child-rendered');
  await accessibility('selected-turn-causal-tree');
  await navigate('#nav-proposals', '/v1/proposals', 'proposal-list');
  const proposalWait = page.waitForResponse(reply => new URL(reply.url()).pathname === proposalRoute + '/diff');
  await page.getByTestId('proposal-open').filter({hasText: proposal.id}).focus();
  await page.keyboard.press('Enter');
  check((await proposalWait).status() === 200, 'proposal-diff-real-response');
  await page.locator('#approve-form').waitFor({state: 'attached'});
  check(await page.locator('#view-title').evaluate(element => document.activeElement === element), 'keyboard-proposal-selection-focus');
  for (const heading of ['Responses', 'Effects', 'State', 'Grounding']) check((await page.locator('#view-content').textContent()).toLowerCase().includes(heading.toLowerCase()), 'diff-section-' + heading);
  check(diff.responses.items.length > 0 && await page.locator('#diff-responses article').count() === diff.responses.items.length, 'actual-response-differences-rendered');
  check((await page.locator('#diff-responses').textContent()).includes(sentinel), 'changed-credential-entry-rendered-for-pii-reader');
  for (const row of diff.grounding) {
    check(await page.getByRole('table', {name: 'External target grounding', exact: true})
      .getByRole('cell', {name: `${row.kind}: ${row.method} ${row.host}${row.route}`, exact: true}).count() === 1,
      'actual-per-target-grounding-rendered');
  }
  await accessibility('proposal-diff');
  const policyRefusal = await api('POST', proposalRoute + '/promote', {reason: 'Synthetic unapproved policy refusal', dry_run: false}, {}, 403);
  check(policyRefusal.error?.code === 'APPROVAL_REQUIRED', 'policy-prevents-unapproved-real-promotion');
  await submitMutation('approve', proposalRoute + '/approve', true);
  check((await api('GET', proposalRoute)).approvals.length === 0, 'approval-dry-run-does-not-persist');
  for (const [field, value] of [
    ['token_id', 'oidc:' + '0'.repeat(64)], ['principal', 'oidc:' + '0'.repeat(64)],
    ['identity', {issuer: issuer + '/spoof', subject: 'spoof-subject'}],
    ['verified_identity', {state: 'VERIFIED', issuer: issuer + '/spoof', subject: 'spoof-subject'}],
    ['protected_payload', {subject: approvalIdentity, plain: 'spoof-payload'}],
  ]) await api('POST', proposalRoute + '/approve', {reason: 'Synthetic rejected identity body', dry_run: false, [field]: value}, {}, 400);
  check((await api('GET', proposalRoute)).approvals.length === 0, 'spoofed-body-never-creates-approval-authority');
  async function privacyMode(value) {
    const reply = await transport('http://localhost/v1/privacy/mode', {socketPath: config.socket, method: 'POST',
      headers: {'Content-Type': 'application/json'}, data: {mode: value, reason: 'Synthetic approval protection ' + value, dry_run: false}});
    check(reply.status === 200 && JSON.parse(reply.text).mode === value, 'real-authorized-Actor-privacy-mode-' + value);
  }
  // No Actor PII is written while off. The new login must force-protect its own payload.
  await privacyMode('off');
  check((await login('valid')).principal === approvalIdentity, 'fresh-OFF-session-has-stable-opaque-principal');
  const offApproval = await api('POST', proposalRoute + '/approve', {
    reason: 'Synthetic fresh OFF approval with ignored spoof headers', dry_run: false,
  }, {'X-Kronik-Principal': 'oidc:' + '0'.repeat(64),
    'X-Kronik-Verified-Identity': JSON.stringify({issuer: issuer + '/spoof', subject: 'spoof-subject'}),
    'X-Kronik-Protected-Payload': 'spoof-payload'});
  await privacyMode('on');
  check((await login('valid')).principal === approvalIdentity, 'fresh-ON-session-has-stable-opaque-principal');
  await navigate('#nav-proposals', '/v1/proposals', 'fresh-ON-approval-proposals');
  const freshDiff = page.waitForResponse(reply => new URL(reply.url()).pathname === proposalRoute + '/diff');
  await page.getByTestId('proposal-open').filter({hasText: proposal.id}).focus();
  await page.keyboard.press('Enter');
  check((await freshDiff).status() === 200, 'fresh-ON-approval-uses-real-proposal-diff');
  await page.locator('#approve-form').waitFor({state: 'attached'});
  const realApproval = await submitMutation('approve', proposalRoute + '/approve', false);
  const approved = await api('GET', proposalRoute);
  const historicalApprovals = [offApproval.approval, realApproval.approval];
  function verifiedHistorical(value) {
    return historicalApprovals.every(expected => {
      const actual = value.approvals.find(item => item.lsn === expected.lsn);
      return actual && actual.token_id === approvalIdentity && actual.diff_hash === expected.diff_hash &&
        actual.verified_through_lsn === expected.verified_through_lsn &&
        actual.verified_identity?.state === 'VERIFIED' &&
        actual.verified_identity.issuer === issuer && actual.verified_identity.subject === 'fixture-reviewer';
    });
  }
  check(verifiedHistorical(approved), 'actual-stored-OFF-and-ON-history-reveals-exact-authenticated-provider-pair');
  const storedApproval = approved.approvals.find(item => item.lsn === realApproval.approval.lsn);
  check(storedApproval && storedApproval.token_id === approvalIdentity &&
    storedApproval.reason === 'Synthetic M27 acceptance approve' &&
    storedApproval.diff_hash === realApproval.approval.diff_hash &&
    storedApproval.verified_through_lsn === realApproval.approval.verified_through_lsn &&
    storedApproval.wall_time_ms > 0, 'completed-approval-persists-exact-verified-identity-and-diff');
  const audit = await api('GET', '/v1/audit?from=' + storedApproval.lsn + '&limit=50');
  const approvalLine = audit.lines.find(line => line.lsn === storedApproval.lsn && line.kind === 'approval' && line.action === 'approve');
  check(approvalLine && approvalLine.token_id === approvalIdentity &&
    approvalLine.reason === storedApproval.reason && approvalLine.at_wall_ms === storedApproval.wall_time_ms &&
    approvalLine.details.proposal_id === proposal.id && approvalLine.details.diff_hash === storedApproval.diff_hash &&
    approvalLine.details.verified_through_lsn === storedApproval.verified_through_lsn &&
    typeof approvalLine.record_hash === 'string' && approvalLine.record_hash.length > 0, 'ordinary-audit-matches-real-Approval-log-projection');
  const offAudit = await api('GET', '/v1/audit?from=' + offApproval.approval.lsn + '&limit=50');
  const oidcAudit = offAudit.lines.filter(line => line.token_id?.startsWith('oidc:'));
  check(oidcAudit.length >= 2 && oidcAudit.every(line => /^oidc:[a-f0-9]{64}$/.test(line.token_id)) &&
    offAudit.lines.some(line => line.lsn === offApproval.approval.lsn && line.token_id === approvalIdentity),
    'all-observed-normal-OIDC-audit-origins-are-opaque-including-OFF-approval');
  await page.locator('#refresh-button').click();
  await page.getByRole('table', {name: 'Completed approvals', exact: true}).getByRole('cell', {name: approvalIdentity, exact: true}).first().waitFor({state: 'visible'});
  await accessibility('completed-approval-verified-identity');
  await submitMutation('promote', proposalRoute + '/promote', true);
  await submitMutation('promote', proposalRoute + '/promote', false);
  check((await api('GET', proposalRoute)).status === 'promoted', 'real-proposal-is-promoted');
  const switchedReply = await transport(localOrigin(config.gateway) + '/counter/m27-switched/increment', {ca, method: 'POST'});
  check(switchedReply.status === 200 && switchedReply.text.trim() === '2' && gatewayReply.text.trim() === '1', 'public-gateway-executes-promoted-step-two-code');
  // Native compatibility must not supply the approval that enabled the OIDC-only product change.
  const nativeHeaders = {'Content-Type': 'application/json', Authorization: 'Bearer ' + config.admin_bearer};
  const nativeCandidate = await transport(origin + '/v1/proposals', {ca, method: 'POST', headers: nativeHeaders,
    data: {wasm_base64: [wasm(config.counter)], reason: 'Synthetic native producer compatibility',
      dry_run: false, threads: 1, mode: 'both'}});
  check(nativeCandidate.status === 200, 'ordinary-bearer-creates-distinct-post-promotion-proposal');
  const nativeProposalValue = JSON.parse(nativeCandidate.text);
  const nativeProposal = nativeProposalValue.proposal || nativeProposalValue;
  check(typeof nativeProposal.id === 'string' && nativeProposal.id !== proposal.id,
    'native-compatibility-cannot-mask-OIDC-required-approval-policy');
  const nativeRoute = '/v1/proposals/' + encodeURIComponent(nativeProposal.id);
  const nativeSpoof = await transport(origin + nativeRoute + '/approve', {ca, method: 'POST', headers: nativeHeaders,
    data: {reason: 'Synthetic rejected native protected-body spoof', dry_run: false,
      verified_identity: {subject: approvalIdentity, value: {plain: 'spoof-native-verified'}}}});
  check(nativeSpoof.status === 400, 'native-bearer-cannot-supply-protected-approval-identity');
  const nativeAccepted = await transport(origin + nativeRoute + '/approve', {ca, method: 'POST',
    headers: {...nativeHeaders, 'X-Kronik-Principal': approvalIdentity,
      'X-Kronik-Verified-Identity': JSON.stringify({issuer: issuer + '/spoof', subject: 'spoof-native-verified'})},
    data: {reason: 'Synthetic native producer ignores identity headers', dry_run: false}});
  check(nativeAccepted.status === 200, 'ordinary-bearer-approval-remains-working-without-OIDC-claims');
  const nativeApproval = JSON.parse(nativeAccepted.text).approval;
  const nativeHistoryReply = await transport(origin + nativeRoute, {ca, headers: nativeHeaders});
  check(nativeHistoryReply.status === 200, 'ordinary-bearer-native-approval-history');
  const nativeStored = JSON.parse(nativeHistoryReply.text).approvals.find(item => item.lsn === nativeApproval.lsn);
  check(nativeStored && nativeStored.token_id.startsWith('token:') &&
    !Object.hasOwn(nativeStored, 'verified_identity'), 'actual-native-producer-has-no-verified-identity-field');
  const nativeFixture = {proposal: nativeProposal.id, lsn: nativeApproval.lsn};
  const deployed = await navigate('#nav-deployments', '/v1/deployments', 'deployment-timeline');
  check(deployed.deployments.length >= 2, 'deployment-timeline-includes-real-promotion');
  check(await page.locator('#deployment-timeline > li').count() === deployed.deployments.length &&
    (await page.locator('#deployment-timeline > li').last().textContent()).includes('Synthetic M27 acceptance promote'), 'actual-promoted-deployment-rendered');
  await navigate('#nav-deadletters', '/v1/dead-letters', 'deadletters-list');
  await page.getByTestId('deadletter-open').first().focus();
  await page.keyboard.press('Enter');
  check(await page.locator('#deadletter-detail').evaluate(element => document.activeElement === element), 'keyboard-deadletter-selection-focus');
  await accessibility('deadletter-resend');
  const resendId = deadRows[0].id;
  check(resendId !== undefined, 'deadletter-has-real-id');
  await submitMutation('resend', '/v1/dead-letters/' + encodeURIComponent(resendId) + '/resend', true);
  await submitMutation('resend', '/v1/dead-letters/' + encodeURIComponent(resendId) + '/resend', false);
  await inspectApprovalProtection(approvalIdentity, proposal.id, historicalApprovals.map(item => item.lsn), nativeFixture);
  check((await login('valid')).principal === approvalIdentity, 'fresh-browser-login-after-private-key-fault-restoration');
  check(verifiedHistorical(await api('GET', proposalRoute)), 'historical-pair-reveals-only-after-original-keystore-restored');
  const erased = await transport('http://localhost/v1/privacy/erase', {socketPath: config.socket, method: 'POST',
    headers: {'Content-Type': 'application/json'}, data: {subject: approvalIdentity,
      reason: 'Synthetic completed-approval historical identity erasure', dry_run: false}});
  const erasure = JSON.parse(erased.text);
  check(erased.status === 200 && !erasure.dry_run && erasure.subject === approvalIdentity &&
    erasure.key_version > 0 && erasure.lsn > 0, 'actual-authorized-opaque-principal-key-erasure-after-product-proof');
  const erasedHistory = await api('GET', proposalRoute);
  check(historicalApprovals.every(expected => {
    const actual = erasedHistory.approvals.find(item => item.lsn === expected.lsn);
    return actual && actual.token_id === approvalIdentity &&
      JSON.stringify(actual.verified_identity) === '{"state":"ERASED"}';
  }), 'authorized-historical-approval-pair-is-ERASED-not-freshened-from-own-session');

  const authenticated = await session();
  for (const [name, overrides] of [['missing-CSRF', {'X-Kronik-CSRF': null}], ['wrong-CSRF', {'X-Kronik-CSRF': 'invalid'}], ['missing-Origin', {Origin: null}], ['wrong-Origin', {Origin: issuer}]]) {
    for (const route of [proposalRoute + '/approve', '/v1/auth/logout']) {
      const headers = {'Content-Type': 'application/json', Origin: origin, 'X-Kronik-CSRF': authenticated.csrf_token};
      for (const [header, value] of Object.entries(overrides)) {
        if (value === null) delete headers[header];
        else headers[header] = value;
      }
      const response = await context.request.post(origin + route, {headers, data: {reason: 'Synthetic rejected cookie mutation', dry_run: true}});
      check(response.status() === 403, 'cookie-mutation-rejects-' + name);
      check((await session()).authenticated, 'rejected-mutation-preserves-auth-' + name);
    }
  }
  await logout(true);
  const oldCookie = (await context.cookies(origin)).find(cookie => cookie.name === '__Host-kronik-session');
  await logout(false);
  const revokedCookieResponse = await transport(origin + '/v1/actors', {ca, headers: {Cookie: oldCookie.name + '=' + oldCookie.value}});
  check(revokedCookieResponse.status === 401, 'logged-out-cookie-cannot-be-replayed');

  for (const negative of ['issuer', 'audience', 'nonce', 'state', 'keys', 'signature', 'expired', 'unmapped']) {
    await login(negative, false);
    const denied = await context.request.get(origin + '/v1/actors');
    check(denied.status() === 401, 'trust-path-rejects-' + negative);
  }
  // A valid signature and all-scope JWT claim cannot increase mapped scopes.
  denyPII = true;
  const reader = await login('reader');
  check(reader.scopes.includes('read') && !reader.scopes.includes('pii:read') && !reader.scopes.includes('approve') && !reader.scopes.includes('promote') && !reader.scopes.includes('admin'), 'mapped-scopes-ignore-JWT-escalation');
  for (const route of ['/v1/actors/counter/m27-private', '/v1/actors/counter/m27-private/history', '/v1/turns/' + encodeURIComponent(privateTurn.turn_id), '/v1/turns/' + encodeURIComponent(privateTurn.turn_id) + '/trace']) {
    const result = await api('GET', route);
    check(!JSON.stringify(result).includes(sentinel) && !JSON.stringify(result).includes(encodedSentinel), 'denied-principal-response-redaction');
  }
  const readerDiff = await api('GET', proposalRoute + '/diff');
  const deniedResponseItem = readerDiff.responses.items.find(item => item.turn_prod === privateResponseItem.turn_prod &&
    item.turn_fork === privateResponseItem.turn_fork && item.root_lsn === privateResponseItem.root_lsn);
  check(deniedResponseItem && deniedResponseItem.headers.some(header => header.name === 'set-cookie' &&
    Array.isArray(header.prod) && header.prod.length === 1 && header.prod[0] === '[redacted]' &&
    header.fork === null), 'same-changed-credential-entry-is-server-redacted-for-reader');
  check(readerDiff.state.isolated.some(item => item.actor === privateState.actor &&
    item.root_lsn === privateState.root_lsn && JSON.stringify(item.keys) === JSON.stringify(privateState.keys)),
    'reader-receives-same-server-redacted-changed-private-state');
  check(readerDiff.grounding.some(row => JSON.stringify(row) === JSON.stringify(recordedGrounding)),
    'reader-receives-actual-exact-target-grounding');
  await navigate('#nav-history', '/v1/actors', 'PII-denied-history');
  const deniedHistory = page.waitForResponse(reply => new URL(reply.url()).pathname === '/v1/actors/counter/m27-private/history');
  activeCheck = 'keyboard-select-exact-private-actor';
  await page.getByRole('button', {name: 'counter/m27-private', exact: true}).focus();
  await page.keyboard.press('Enter');
  await deniedHistory;
  await page.locator('#actor-history').filter({hasText: 'note from operator'}).waitFor({state: 'visible'});
  await accessibility('PII-denied-actor');
  await openTurn(privateTurn.turn_id, 'PII-denied-turn');
  await accessibility('PII-denied-selected-turn');
  await navigate('#nav-proposals', '/v1/proposals', 'reader-proposals');
  const readerDiffWait = page.waitForResponse(reply => new URL(reply.url()).pathname === proposalRoute + '/diff');
  await page.getByTestId('proposal-open').filter({hasText: proposal.id}).focus();
  await page.keyboard.press('Enter');
  await readerDiffWait;
  await page.locator('#approve-form').waitFor({state: 'attached'});
  check((await page.locator('#diff-responses').textContent()).includes('[redacted]') &&
    await page.locator('#diff-responses article').count() === readerDiff.responses.items.length,
    'actual-server-redacted-changed-response-rendered-for-reader');
  check(await page.getByRole('table', {name: 'External target grounding', exact: true})
    .getByRole('cell', {name: `${recordedGrounding.kind}: ${recordedGrounding.method} ${recordedGrounding.host}${recordedGrounding.route}`, exact: true}).count() === 1,
    'reader-renders-real-recorded-target-grounding');
  check(await page.locator('#approve-button').isDisabled() && await page.locator('#promote-button').isDisabled(), 'scope-gates-disable-approve-promote');
  await api('PUT', '/v1/auth/config', {config: null, reason: 'Synthetic denied Admin scope', dry_run: true}, {}, 403);
  const deniedApproval = await api('GET', proposalRoute);
  check(historicalApprovals.every(expected => {
    const actual = deniedApproval.approvals.find(approval => approval.lsn === expected.lsn);
    return actual && actual.token_id === approvalIdentity && !Object.hasOwn(actual, 'verified_identity');
  }) && !JSON.stringify(deniedApproval).includes('fixture-reviewer'),
  'no-PII-history-keeps-opaque-origin-and-omits-even-erased-verified-payload');
  for (const operation of ['approve', 'promote']) await api('POST', proposalRoute + '/' + operation, {reason: 'Synthetic denied scope', dry_run: true}, {}, 403);
  await accessibility('PII-denied-diff');
  await logout();
  denyPII = false;
  await login('revoked');
  const bodySession = await session();
  const bodyCookie = (await context.cookies(origin)).find(cookie => cookie.name === '__Host-kronik-session');
  check(bodySession.authenticated && bodyCookie, 'real-original-session-before-HTTP-body-wait');
  check(bodySession.scopes.includes('approve'), 'body-wait-original-session-has-real-required-approval-scope');
  const beforeBodyApproval = JSON.parse((await transport('http://localhost' + proposalRoute,
    {socketPath: config.socket})).text).approvals.length;
  const pendingBody = Buffer.from(JSON.stringify({reason: 'Synthetic denied approval after original body capture', dry_run: false}));
  let bodyAdmission = false;
  let tokenRevocation = false;
  const deniedBodyStatus = await new Promise((resolve, reject) => {
    const endpoint = new URL(origin);
    const request = https.request({hostname: endpoint.hostname, port: endpoint.port, family: 4, ca,
      path: proposalRoute + '/approve', method: 'POST',
      headers: {'Content-Type': 'application/json', 'Content-Length': pendingBody.length, Expect: '100-continue',
        Origin: origin, 'X-Kronik-CSRF': bodySession.csrf_token, Cookie: bodyCookie.name + '=' + bodyCookie.value}},
    response => { response.resume(); response.on('end', () => resolve(response.statusCode)); });
    const bound = setTimeout(() => request.destroy(new Error('bounded-original-body-wait')), 10000);
    request.on('close', () => clearTimeout(bound));
    request.on('error', () => reject(new Error('original-body-wait-transport')));
    request.once('continue', () => {
      bodyAdmission = true;
      (async () => {
        const revoke = await transport('http://localhost/v1/tokens/ui-revoked/revoke', {
          socketPath: config.socket, method: 'POST', headers: {'Content-Type': 'application/json'},
          data: {reason: 'Synthetic original token revocation while admitted HTTP body is pending', dry_run: false}});
        check(revoke.status === 200, 'ordinary-bound-token-revoked');
        tokenRevocation = true;
        request.end(pendingBody);
      })().catch(error => { request.destroy(); reject(error); });
    });
    request.flushHeaders();
  });
  observations.body_wait = {continue_observed: bodyAdmission, token_revocation_observed: tokenRevocation,
    actual_status: deniedBodyStatus, expected_status: 401};
  check(bodyAdmission && tokenRevocation && deniedBodyStatus === 401,
    'original-cookie-authority-rechecked-after-real-HTTP-body-wait');
  const afterBodyApproval = JSON.parse((await transport('http://localhost' + proposalRoute,
    {socketPath: config.socket})).text).approvals.length;
  check(afterBodyApproval === beforeBodyApproval, 'revoked-pending-body-cannot-append-approval');
  check((await transport(origin + '/v1/actors', {ca,
    headers: {Authorization: 'Bearer ' + config.bearer}})).status === 200,
    'unrelated-original-bearer-survives-session-body-revocation');
  check((await context.request.get(origin + '/v1/auth/session')).status() === 401, 'revoked-token-invalidates-session');
  check((await context.request.get(origin + '/v1/actors')).status() === 401, 'revoked-session-refuses-public-read');

  await context.clearCookies();
  await page.goto(origin + '/ui/');
  await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
  await drain();
  async function connectBearer() {
    await page.locator('#token-alternative > summary').click();
    await page.locator('#bearer-token').fill(config.bearer);
    const loaded = page.waitForResponse(response => new URL(response.url()).origin === origin &&
      new URL(response.url()).pathname === '/v1/actors' && response.request().method() === 'GET');
    await page.locator('#token-connect').click();
    check((await loaded).status() === 200, 'bearer-connect-loads-live-authorized-history');
    await page.locator('#session-status').filter({hasText: 'Bearer token'}).waitFor({state: 'visible'});
    await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
    await page.locator('#refresh-button').waitFor({state: 'visible'});
  }
  await connectBearer();
  await navigate('#nav-history', '/v1/actors', 'bearer-memory-history');
  await storageSafe('bearer-connected');
  check(await page.locator('#bearer-token').inputValue() === '', 'bearer-password-cleared-after-connect');
  check(bearerRequests > 0, 'bearer-only-Authorization-observed');
  await page.locator('#logout-reason').fill('Synthetic memory-only bearer logout');
  await page.locator('#logout-dry-run').setChecked(false);
  await page.locator('#logout-button').click();
  await page.locator('#session-status').filter({hasText: 'Not signed in'}).waitFor({state: 'visible'});
  check(await page.locator('#logout-reason').inputValue() === '' &&
    await page.locator('#error').textContent() === '', 'logout-clears-auth-shell-sensitive-strings');
  await storageSafe('bearer-logout');
  check(!(await session()).authenticated, 'bearer-logout-discards-memory-credential');
  await connectBearer();
  await page.locator('#view-content[aria-busy="false"]').waitFor({state: 'attached'});
  const revokeBearer = await transport('http://localhost/v1/tokens/ui-reader/revoke', {socketPath: config.socket, method: 'POST', headers: {'Content-Type': 'application/json'}, data: {reason: 'Synthetic bearer expiry transition', dry_run: false}});
  check(revokeBearer.status === 200, 'bearer-token-revoked');
  await page.locator('#refresh-button').click();
  await page.locator('#error').filter({hasText: /.+/}).waitFor({state: 'visible'});
  check((await page.locator('#session-status').textContent()).includes('Not signed in'), 'bearer-auth-error-clears-memory-identity');
  const afterError = page.waitForRequest(request => new URL(request.url()).pathname === '/v1/auth/session');
  await page.reload();
  await afterError;
  await storageSafe('bearer-auth-error');
  const stale = await page.evaluate(async () => (await fetch('/v1/actors')).status);
  check(stale === 401, 'no-persisted-auth-after-reload');
  await drain();
  // Keep the strict cluster gate last so standalone failures do not hide auth checks.
  await login('valid');
  const admittedProfile = await localControl('GET');
  check(admittedProfile.enabled && admittedProfile.active &&
    /^[a-f0-9]{64}$/.test(admittedProfile.digest) && admittedProfile.source,
    'startup-profile-has-real-durable-control-receipt');
  await localControl('PUT', {reason: 'Synthetic missing profile must not disable', dry_run: true}, 400);
  const plannedDisable = await localControl('PUT', {config: null, reason: 'Synthetic config dry run', dry_run: true});
  check(plannedDisable.dry_run && plannedDisable.changed &&
    (await localControl('GET')).digest === admittedProfile.digest &&
    (await session()).authenticated, 'auth-config-dry-run-keeps-profile-and-session');
  const oldSession = (await context.cookies(origin)).find(cookie => cookie.name === '__Host-kronik-session');
  check(oldSession, 'pre-transition-real-session-cookie');
  const disabledProfile = await localControl('PUT', {config: null, reason: 'Synthetic durable disable', dry_run: false});
  check(disabledProfile.changed && !disabledProfile.active && disabledProfile.oidc_reason === 'not_configured' && disabledProfile.source &&
    JSON.stringify(disabledProfile.source) !== JSON.stringify(admittedProfile.source) &&
    !(await session()).authenticated &&
    (await context.request.get(origin + '/v1/actors')).status() === 401,
    'durable-disable-invalidates-existing-cookie-before-further-product-access');
  const restoredProfile = await localControl('PUT', {config: trustedProfile,
    reason: 'Synthetic restore of trusted profile', dry_run: false});
  check(restoredProfile.digest === admittedProfile.digest && restoredProfile.active && restoredProfile.oidc_reason == null && !restoredProfile.restart_required &&
    (await localControl('GET')).active, 'same-profile-new-revision-allows-only-new-logins');
  const oldCookieReply = await transport(origin + '/v1/actors', {
    ca, headers: {Cookie: '__Host-kronik-session=' + oldSession.value}});
  check(oldCookieReply.status === 401, 'old-session-is-not-upgraded-when-profile-is-restored');
  await login('valid');


  await drain();
  let auditCursor;
  let normalOIDCAuditOrigins = 0;
  for (let index = 0; index < 64; index += 1) {
    const batch = await api('GET', '/v1/audit?limit=100' + (auditCursor === undefined ? '' : '&from=' + auditCursor));
    for (const line of batch.lines) {
      check(typeof line.token_id !== 'string' || !line.token_id.includes('fixture-reviewer'),
        'normal-audit-origin-never-exposes-raw-subject');
      if (line.token_id?.startsWith('oidc:')) {
        check(/^oidc:[a-f0-9]{64}$/.test(line.token_id), 'normal-OIDC-audit-origin-is-protected-opaque-principal');
        normalOIDCAuditOrigins += 1;
      }
    }
    if (batch.next == null) break;
    check(index < 63 && Number.isSafeInteger(batch.next) && batch.next > (auditCursor || 0),
      'all-normal-audit-origin-pages-are-bounded-and-complete');
    auditCursor = batch.next;
  }
  check(normalOIDCAuditOrigins >= 5, 'actual-normal-OIDC-mutations-have-observed-opaque-audit-origins');

  const mandatory = ['GET /ui/', 'GET /ui/app.js', 'GET /ui/app.css', 'GET /v1/auth/session', 'GET /v1/auth/login', 'GET /v1/auth/callback', 'POST /v1/auth/logout',
    'GET /v1/actors', 'GET /v1/actors/{kind}/{key}/history', 'GET /v1/turns/{id}', 'GET /v1/turns/{id}/trace',
    'GET /v1/proposals', 'GET /v1/proposals/{id}', 'GET /v1/proposals/{id}/diff', 'POST /v1/proposals/{id}/approve',
    'POST /v1/proposals/{id}/promote', 'GET /v1/dead-letters', 'POST /v1/dead-letters/{id}/resend', 'GET /v1/deployments'];
  for (const operation of mandatory) {
    const rows = observed.get(operation) || [];
    check(rows.some(row => row.status >= 200 && row.status < 400), 'mandatory-browser-operation-' + operation);
  }
  for (const operation of ['POST /v1/proposals/{id}/approve', 'POST /v1/proposals/{id}/promote', 'POST /v1/dead-letters/{id}/resend']) {
    const bodies = (observed.get(operation) || []).filter(row => row.status === 200).map(row => JSON.parse(row.body));
    check(bodies.some(body => body.dry_run === true && body.reason) && bodies.some(body => body.dry_run === false && body.reason), 'mandatory-real-and-dry-run-' + operation);
  }
  const stats = (await mode('valid')).stats;
  check(stats.pkce_verified >= 10 && stats.exchanges === stats.pkce_verified && stats.rejections >= 2, 'actual-code-exchange-PKCE-and-replay-evidence');
  check(stats.app_cookie_observed === 0, 'host-only-app-credentials-never-reach-cross-site-provider');
  fs.writeFileSync(path.join(config.artifacts, 'browser-native-result.json'), JSON.stringify({
    synthetic_not_human: true, full_acceptance: false, pending: 'healthy-current-three-member-cluster',
    checks, operations: Object.fromEntries([...observed].map(([operation, rows]) => [operation, {
      requests: rows.length, success: rows.filter(row => row.status >= 200 && row.status < 400).length,
    }])),
  }, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  const cluster = await navigate('#nav-cluster', '/v1/cluster/status', 'cluster-status');
  check((observed.get('GET /v1/cluster/status') || []).some(row => row.status === 200), 'mandatory-browser-operation-GET /v1/cluster/status');
  check(cluster && cluster.member === true, 'cluster-membership-required-not-standalone');
  // Contract: kronik-cluster/src/status.rs, authenticated current-boot observations.
  const uint = value => Number.isSafeInteger(value) && value >= 0;
  const positive = value => uint(value) && value > 0;
  check(typeof cluster.cluster_id === 'string' && cluster.cluster_id.length > 0 &&
    positive(cluster.local_member_id) && positive(cluster.metadata_durable_index) &&
    positive(cluster.observation_timeout_ms) && positive(cluster.configuration_epoch) &&
    cluster.active_barrier === null, 'cluster-durable-control-index-and-applied-epoch-with-no-active-barrier');
  check(Array.isArray(cluster.members) && cluster.members.length >= 3 &&
    cluster.members.every(member => member && positive(member.member_id)) &&
    new Set(cluster.members.map(member => member.member_id)).size === cluster.members.length,
    'cluster-distinct-member-identities');
  const members = cluster.members.filter(member => member.persisted_phase !== 'REMOVED');
  const memberIds = new Set(members.map(member => member.member_id));
  check(members.length >= 3 && memberIds.has(cluster.local_member_id) &&
    new Set(members.map(member => member.advertise)).size === members.length &&
    new Set(members.map(member => member.registered_boot_id)).size === members.length &&
    members.every(member => member.persisted_phase === 'ACTIVE' && member.ready === true &&
      member.live === true && member.fresh === true && member.metadata_recovery_admitted === true &&
      member.execution_admitted === true && typeof member.name === 'string' && member.name.length > 0 &&
      typeof member.advertise === 'string' && member.advertise.length > 0 &&
      member.labels && typeof member.labels === 'object' && !Array.isArray(member.labels) &&
      Object.values(member.labels).every(value => typeof value === 'string') &&
      typeof member.engine_version === 'string' && member.engine_version.length > 0 &&
      member.engine_version === member.committed_engine_version &&
      /^[a-f0-9]{64}$/.test(member.registered_boot_id) && member.registered_boot_id === member.observed_boot_id &&
      positive(member.registered_incarnation) && member.registered_incarnation === member.observed_incarnation &&
      positive(member.registration_metadata_index) && member.registration_metadata_index <= cluster.metadata_durable_index &&
      uint(member.observation_age_ms) && member.observation_age_ms < cluster.observation_timeout_ms &&
      positive(member.free_disk_bytes) && positive(member.clock_unix_ms) && member.metadata_lag === 0),
    'real-current-live-three-member-runtime-engine-clock-disk-lag-and-boot-authority');
  check(new Set(members.map(member => member.engine_version)).size === 1, 'current-cluster-engines-match');
  check(cluster.metadata && cluster.metadata.shard_id === null &&
    Array.isArray(cluster.shards) && cluster.shards.length > 0 &&
    cluster.shards.every((shard, index) => shard.shard_id === index), 'concrete-metadata-and-contiguous-shard-groups');
  const groups = [cluster.metadata, ...cluster.shards];
  function healthyGroup(status, leader, reporter) {
    return status && positive(status.term) && ['LEADER', 'FOLLOWER'].includes(status.role) &&
      status.leader_member_id === leader && memberIds.has(leader) &&
      (status.role === 'LEADER' ? leader === reporter && status.leader_term === status.term :
        leader !== reporter && status.leader_term === null) &&
      ['commit_index', 'applied_index', 'persisted_index', 'durable_index'].every(field => uint(status[field])) &&
      status.applied_index <= status.commit_index && status.persisted_index >= status.commit_index &&
      status.backfilling === false && Array.isArray(status.voters) && status.voters.length >= 3 &&
      new Set(status.voters).size === status.voters.length && status.voters.includes(leader) &&
      status.voters.every(id => memberIds.has(id)) && Array.isArray(status.learners) && status.learners.length === 0;
  }
  for (const group of groups) {
    check(group.under_replicated === false &&
      healthyGroup(group.local, group.leader_member_id, cluster.local_member_id),
      'current-group-has-concrete-healthy-leader-and-replication');
    for (const voter of group.local.voters) {
      const member = members.find(member => member.member_id === voter);
      const hosted = Array.isArray(member.groups) ? member.groups.filter(item => item.shard_id === group.shard_id) : [];
      check(hosted.length === 1 && hosted[0].replication_lag === 0 &&
        uint(hosted[0].lag_reference_commit_index) &&
        hosted[0].lag_reference_commit_index === hosted[0].status.applied_index &&
        healthyGroup(hosted[0].status, group.leader_member_id, voter) &&
        hosted[0].status.term === group.local.term,
        'current-voter-hosts-same-term-caught-up-group-with-real-leader');
    }
  }
  // The durable image can precede the Raft loop's applied notification.
  check(cluster.metadata.local.durable_index >= cluster.metadata_durable_index,
    'control-authority-is-durable-metadata-index-not-actor-lsn');
  const clusterText = await page.locator('#cluster-status').textContent();
  check(await page.locator('#cluster-status').isVisible(), 'actual-cluster-status-rendered');
  for (const member of members) check(clusterText.includes(member.advertise), 'actual-current-cluster-member-rendered');
  await drain();
  const evidence = {synthetic_not_human: true, full_acceptance: true, checks, operations: Object.fromEntries([...observed].map(([operation, rows]) => [operation, {requests: rows.length, success: rows.filter(row => row.status >= 200 && row.status < 400).length}]))};
  fs.writeFileSync(path.join(config.artifacts, 'browser-result.json'), JSON.stringify(evidence, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  await context.close();
}

(async () => {
  try { await main(); }
  catch (error) {
    // Playwright error messages include target URLs/DOM; never emit them.
    process.stderr.write('Assertion failed: ' + activeCheck.replace(/[^a-zA-Z0-9_ /:,{}.-]/g, '').slice(0, 240) + '\n');
    const locations = [...new Set((String(error.stack || '').match(/\/work\/scripts\/test-ui-browser\.cjs:\d+:\d+/g) || []))];
    for (const location of locations) process.stderr.write('Source: ' + location + '\n');
    if (evidenceDir) fs.writeFileSync(path.join(evidenceDir, 'browser-failure-result.json'), JSON.stringify({
      synthetic_not_human: true, full_acceptance: false, failed_stage: activeCheck,
      source_locations: locations, passed_checks: checks, observations,
    }, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    process.exitCode = 1;
  } finally {
    clearTimeout(deadline);
    process.stdin.destroy();
    if (browser) {
      const cleanupLimit = setTimeout(() => {
        process.stderr.write('browser-cleanup-failed\n');
        process.exit(1);
      }, 5000);
      cleanupLimit.unref();
      try { await browser.close(); }
      catch {
        process.stderr.write('browser-cleanup-failed\n');
        process.exitCode = 1;
      }
      finally { clearTimeout(cleanupLimit); }
    }
  }
})();
