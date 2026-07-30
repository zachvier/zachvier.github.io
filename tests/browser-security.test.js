'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const root = path.join(__dirname, '..');
const chromeCandidates = [
  process.env.CHROME_BIN,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser'
].filter(Boolean);
const chrome = chromeCandidates.find(candidate => fs.existsSync(candidate));

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitFor(check, message, timeout = 10000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await delay(50);
  }
  throw new Error(message);
}

class CdpClient {
  constructor(url) {
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.waiters = [];
    this.socket = new WebSocket(url);
  }

  async open() {
    await new Promise((resolve, reject) => {
      this.socket.addEventListener('open', resolve, { once: true });
      this.socket.addEventListener('error', reject, { once: true });
    });
    this.socket.addEventListener('message', event => {
      const message = JSON.parse(String(event.data));
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
        return;
      }
      this.events.push(message);
      for (const waiter of this.waiters.splice(0)) waiter();
    });
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify(message));
    });
  }

  async waitEvent(method, sessionId, timeout = 10000) {
    return waitFor(() => {
      const index = this.events.findIndex(event => event.method === method && (!sessionId || event.sessionId === sessionId));
      if (index === -1) return null;
      return this.events.splice(index, 1)[0];
    }, `timed out waiting for ${method}`, timeout);
  }

  close() {
    this.socket.close();
  }
}

function startServer() {
  const mime = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.har': 'application/json',
    '.eml': 'message/rfc822'
  };
  const server = http.createServer((request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const filename = path.resolve(root, relative);
    if (filename !== root && !filename.startsWith(root + path.sep)) {
      response.writeHead(403).end('Forbidden');
      return;
    }
    fs.readFile(filename, (error, body) => {
      if (error) {
        response.writeHead(404).end('Not found');
        return;
      }
      response.writeHead(200, { 'Content-Type': mime[path.extname(filename)] || 'application/octet-stream' });
      response.end(body);
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

async function launchChrome() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'zachvivier-security-'));
  const process = childProcess.spawn(chrome, [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    'about:blank'
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  let client;
  process.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8000); });
  const close = async () => {
    if (client) client.close();
    if (process.exitCode === null) {
      await new Promise(resolve => {
        const timer = setTimeout(() => {
          if (process.exitCode === null) process.kill('SIGKILL');
          resolve();
        }, 2000);
        process.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
        process.kill('SIGTERM');
      });
    }
    fs.rmSync(profile, { recursive: true, force: true });
  };
  try {
    const activePort = path.join(profile, 'DevToolsActivePort');
    const details = await waitFor(() => {
      if (process.exitCode !== null) throw new Error(`Chrome exited early: ${stderr}`);
      if (!fs.existsSync(activePort)) return null;
      const lines = fs.readFileSync(activePort, 'utf8').trim().split('\n');
      return lines.length >= 2 ? lines : null;
    }, 'Chrome did not expose a DevTools port');
    client = new CdpClient(`ws://127.0.0.1:${details[0]}${details[1]}`);
    await client.open();
    return { client, close };
  } catch (error) {
    await close();
    throw error;
  }
}

async function createPage(client) {
  const { targetId } = await client.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await client.send('Target.attachToTarget', { targetId, flatten: true });
  await Promise.all([
    client.send('Page.enable', {}, sessionId),
    client.send('DOM.enable', {}, sessionId),
    client.send('Runtime.enable', {}, sessionId),
    client.send('Network.enable', {}, sessionId)
  ]);
  return sessionId;
}

async function navigate(client, sessionId, url) {
  const loaded = client.waitEvent('Page.loadEventFired', sessionId);
  await client.send('Page.navigate', { url }, sessionId);
  await loaded;
}

async function evaluate(client, sessionId, expression) {
  const result = await client.send('Runtime.evaluate', {
    expression,
    returnByValue: true,
    awaitPromise: true
  }, sessionId);
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || 'browser evaluation failed');
  return result.result.value;
}

async function setFile(client, sessionId, selector, filename) {
  const { root: document } = await client.send('DOM.getDocument', {}, sessionId);
  const { nodeId } = await client.send('DOM.querySelector', { nodeId: document.nodeId, selector }, sessionId);
  assert.ok(nodeId, `missing file input ${selector}`);
  await client.send('DOM.setFileInputFiles', { nodeId, files: [filename] }, sessionId);
}

test('diagnostic pages run under CSP and hostile HAR values remain inert', { timeout: 30000 }, async t => {
  if (!chrome) {
    t.skip('Chrome/Chromium is not installed');
    return;
  }
  if (typeof WebSocket === 'undefined') {
    t.skip('This optional browser test requires a Node runtime with global WebSocket support');
    return;
  }

  const adversarialHar = path.join(root, 'tests', 'fixtures', 'adversarial.har');
  assert.ok(fs.existsSync(adversarialHar), 'adversarial HAR fixture must exist');
  const mailFixture = path.join(root, 'tests', 'fixtures', 'good-multipart.eml');
  const complexMailFixture = path.join(root, 'tests', 'fixtures', 'complex-multihop-header-sample.eml');
  const server = await startServer();
  let browser;

  try {
    browser = await launchChrome();
    const origin = `http://127.0.0.1:${server.address().port}`;
    const harSession = await createPage(browser.client);
    await navigate(browser.client, harSession, `${origin}/har-viewer.html`);
    const requestStart = browser.client.events.length;
    await setFile(browser.client, harSession, '#file', adversarialHar);
    await waitFor(() => evaluate(browser.client, harSession, "getComputedStyle(document.querySelector('#app')).display === 'flex' && document.querySelectorAll('#rows tr').length > 0"), 'HAR viewer did not render the fixture');

    await evaluate(browser.client, harSession, "document.querySelector('#rows tr').click(); true");
    await waitFor(() => evaluate(browser.client, harSession, "document.querySelector('.cpv') && document.querySelector('#dBody').textContent.includes('X-Correlation-ID')"), 'HAR details did not render correlation data');
    assert.equal(
      await evaluate(browser.client, harSession, "document.querySelector('.cpv').dataset.copy"),
      `sentinel-copy-\"><img id=\"xss-copy\" src=\"https://attacker.invalid/copy\" onerror=\"globalThis.__xss=1\">'`,
      'data-copy must round-trip as inert attribute data'
    );

    await evaluate(browser.client, harSession, "document.querySelector('[data-t=body]').click(); true");
    await waitFor(() => evaluate(browser.client, harSession, "document.querySelector('#dBody').textContent.includes('xss-body')"), 'HAR body tab did not render hostile body text');
    await evaluate(browser.client, harSession, "document.querySelector('#hdrBtn').click(); true");
    await waitFor(() => evaluate(browser.client, harSession, "document.querySelector('#hdrBody').textContent.includes('sentinel-copy')"), 'HAR header index did not render hostile header text');

    const injectedCount = await evaluate(browser.client, harSession, `(() => {
      const allowedPreview = element => element.matches('img.prev:not([onerror])');
      return Array.from(document.querySelectorAll('[id^="xss-"], [onerror], [onload], form[action*="attacker.invalid"], img[src^="https://attacker.invalid"]'))
        .filter(element => !allowedPreview(element)).length;
    })()`);
    assert.equal(injectedCount, 0, 'hostile HAR strings must not create executable DOM');
    assert.equal(await evaluate(browser.client, harSession, 'globalThis.__xss || 0'), 0, 'no injected script may run');

    const outbound = browser.client.events.slice(requestStart)
      .filter(event => event.sessionId === harSession && event.method === 'Network.requestWillBeSent')
      .map(event => event.params.request.url)
      .filter(url => !url.startsWith(origin) && !url.startsWith('data:'));
    assert.deepEqual(outbound, [], `HAR viewer made unexpected requests: ${outbound.join(', ')}`);

    const mailSession = await createPage(browser.client);
    const mailRequestStart = browser.client.events.length;
    await navigate(browser.client, mailSession, `${origin}/mail-analyzer.html`);
    await setFile(browser.client, mailSession, '#file', mailFixture);
    await waitFor(() => evaluate(browser.client, mailSession, "document.querySelector('#report').classList.contains('visible') && document.querySelectorAll('#summary .summary-card').length === 5"), 'mail analyzer did not run under CSP');

    await setFile(browser.client, mailSession, '#file', complexMailFixture);
    await waitFor(() => evaluate(browser.client, mailSession, "document.querySelector('#headerCount').textContent.includes('60 FIELDS') && document.querySelectorAll('#hops .hop').length === 8"), 'mail analyzer did not render the complex fixture');
    const complexProjection = await evaluate(browser.client, mailSession, `(() => ({
      routes: Array.from(document.querySelectorAll('#hops .hop-route')).map(node => node.textContent),
      timing: document.querySelector('#timingSummary').textContent,
      auth: document.querySelector('#auth').textContent,
      mime: document.querySelector('#mimeTree').textContent,
      findings: document.querySelector('#findings').textContent
    }))()`);
    assert.match(complexProjection.routes[0], /origin not stated/);
    assert.match(complexProjection.routes[1], /origin not stated/);
    assert.match(complexProjection.routes[6], /198\.51\.100\.203/);
    assert.match(complexProjection.timing, /53s total/);
    assert.match(complexProjection.auth, /d=northwind-labs\.example.*s=selector1/i);
    assert.match(complexProjection.auth, /neutral.*gateway\.corp-relay\.example\.net/i);
    assert.match(complexProjection.mime, /disposition attachment.*filename q3-action-items\.txt/i);
    assert.match(complexProjection.findings, /Received trace does not connect at hop 8/);
    assert.match(complexProjection.findings, /Plaintext SMTP reported at hop 8/);

    await evaluate(browser.client, mailSession, "const select=document.querySelector('#trustedHop');select.value='3';select.dispatchEvent(new Event('change',{bubbles:true}));true");
    await waitFor(() => evaluate(browser.client, mailSession, "document.querySelectorAll('#hops .hop.untrusted').length === 5 && document.querySelectorAll('#findings .trust-note').length >= 5"), 'trust boundary did not label hops and findings');

    const unmatchedDkimMessage = [
      'Authentication-Results: mx.example; dkim=fail header.i=@unmatched.example header.b=missing123',
      'From: sender@example.org',
      'To: receiver@example.net',
      'Date: Wed, 29 Jul 2026 10:00:00 +0000',
      'Message-ID: <unmatched-dkim@example.org>',
      '',
      'body'
    ].join('\r\n');
    await evaluate(browser.client, mailSession, `(() => { const raw=document.querySelector('#raw');raw.value=${JSON.stringify(unmatchedDkimMessage)};raw.dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#analyzeBtn').click();return true })()`);
    await waitFor(() => evaluate(browser.client, mailSession, "/signature identity not matched/i.test(document.querySelector('#auth').textContent) && /dkim.*fail/i.test(document.querySelector('#auth').textContent)"), 'unmatched reported DKIM claim was not rendered');

    const mailOutbound = browser.client.events.slice(mailRequestStart)
      .filter(event => event.sessionId === mailSession && event.method === 'Network.requestWillBeSent')
      .map(event => event.params.request.url)
      .filter(url => !url.startsWith(origin) && !url.startsWith('data:'));
    assert.deepEqual(mailOutbound, [], `mail analyzer made unexpected requests: ${mailOutbound.join(', ')}`);

    const evtxSession = await createPage(browser.client);
    await navigate(browser.client, evtxSession, `${origin}/event-viewer.html`);
    assert.equal(await evaluate(browser.client, evtxSession, "typeof EVTX === 'object'"), true, 'EVTX parser script did not run under CSP');
    await setFile(browser.client, evtxSession, '#file', adversarialHar);
    await waitFor(() => evaluate(browser.client, evtxSession, "getComputedStyle(document.querySelector('#err')).display !== 'none'"), 'EVTX UI script did not handle an invalid file');
    assert.match(
      await evaluate(browser.client, evtxSession, "document.querySelector('#err').textContent"),
      /No event records found|Not an EVTX file|Could not parse/
    );

    const exceptions = browser.client.events.filter(event => event.method === 'Runtime.exceptionThrown');
    assert.deepEqual(exceptions, [], 'diagnostic pages raised an uncaught browser exception');
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
});
