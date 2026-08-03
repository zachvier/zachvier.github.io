'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const toolPages = ['har-viewer.html', 'event-viewer.html', 'mail-analyzer.html'];

function readPage(name) {
  return fs.readFileSync(path.join(root, name), 'utf8');
}

function inlineScripts(html) {
  return Array.from(html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi), match => match[1]);
}

function cspContent(html) {
  const matches = Array.from(html.matchAll(/<meta\s+[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/gi));
  assert.equal(matches.length, 1, 'expected exactly one Content-Security-Policy meta tag');
  const content = /\bcontent="([^"]*)"/i.exec(matches[0][0]);
  assert.ok(content, 'CSP meta tag must use a double-quoted content attribute');
  return { value: content[1], index: matches[0].index };
}

function directives(policy) {
  const result = new Map();
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length) result.set(tokens[0], tokens.slice(1));
  }
  return result;
}

function scriptHash(script) {
  return `'sha256-${crypto.createHash('sha256').update(script, 'utf8').digest('base64')}'`;
}

test('diagnostic pages enforce a strict hash-based meta CSP before active content', () => {
  for (const page of toolPages) {
    const html = readPage(page);
    const csp = cspContent(html);
    const policy = directives(csp.value);
    const firstActiveContent = Math.min(
      ...['<style', '<script'].map(token => {
        const index = html.toLowerCase().indexOf(token);
        return index === -1 ? Infinity : index;
      })
    );

    assert.ok(csp.index < firstActiveContent, `${page}: CSP must precede styles and scripts`);
    assert.deepEqual(policy.get('default-src'), ["'none'"], `${page}: default-src`);
    assert.deepEqual(policy.get('connect-src'), ["'none'"], `${page}: connect-src`);
    assert.deepEqual(policy.get('object-src'), ["'none'"], `${page}: object-src`);
    assert.deepEqual(policy.get('base-uri'), ["'none'"], `${page}: base-uri`);
    assert.deepEqual(policy.get('form-action'), ["'none'"], `${page}: form-action`);
    assert.deepEqual(policy.get('style-src'), ["'self'", "'unsafe-inline'"], `${page}: only same-origin and intentional inline styles are allowed`);
    assert.deepEqual(policy.get('img-src'), ["'self'", 'data:'], `${page}: local and data images only`);

    const scriptPolicy = policy.get('script-src') || [];
    assert.ok(scriptPolicy.includes("'self'"), `${page}: same-origin scripts must be allowed`);
    assert.ok(!scriptPolicy.includes("'unsafe-inline'"), `${page}: inline script must not be broadly allowed`);
    assert.ok(!scriptPolicy.includes("'unsafe-eval'"), `${page}: eval must not be allowed`);

    const expectedHashes = inlineScripts(html).map(scriptHash);
    assert.ok(expectedHashes.length > 0, `${page}: expected at least one inline script`);
    for (const hash of expectedHashes) {
      assert.ok(scriptPolicy.includes(hash), `${page}: CSP is missing current inline-script hash ${hash}`);
    }
    const actualHashes = scriptPolicy.filter(token => token.startsWith("'sha256-"));
    assert.deepEqual(actualHashes.sort(), expectedHashes.sort(), `${page}: CSP contains a stale or extra script hash`);
  }
});

test('HAR and EVTX HTML encoders cover text and both quoted attribute contexts', () => {
  for (const page of ['har-viewer.html', 'event-viewer.html']) {
    const html = readPage(page);
    const source = /function esc\(s\) \{[^\n]+\}/.exec(html);
    assert.ok(source, `${page}: esc() must remain directly testable`);
    const esc = vm.runInNewContext(`(${source[0]})`);
    assert.equal(
      esc(`&<>"'`),
      '&amp;&lt;&gt;&quot;&#39;',
      `${page}: esc() must encode ampersand, angle brackets, and both quote types`
    );
  }
});

test('mail analyzer continues to render parsed content without innerHTML assignments', () => {
  assert.doesNotMatch(readPage('mail-analyzer.html'), /\.innerHTML\s*=/);
});
