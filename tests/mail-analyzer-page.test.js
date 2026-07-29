'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');

test('mail analyzer page exposes local file and paste workflows with report regions', () => {
  const html = fs.readFileSync(path.join(root, 'mail-analyzer.html'), 'utf8');
  assert.match(html, /id="file"[^>]*accept="[^\"]*\.eml/);
  assert.match(html, /id="raw"/);
  assert.match(html, /id="analyzeBtn"/);
  assert.match(html, /Beta tool/i);
  assert.match(html, /mailto:site@zachvivier\.com\?subject=Mail%20Header%20Analyzer%20feedback/);
  assert.match(html, /id="findings"/);
  assert.match(html, /id="hops"/);
  assert.match(html, /id="mimeTree"/);
  assert.match(html, /mail-analyzer-core\.js/);
  assert.match(html, /does not (?:query DNS|verify DKIM)/i);
  assert.match(html, /role="tablist"/);
  assert.match(html, /role="tab"/);
  assert.match(html, /role="tabpanel"/);
  assert.match(html, /MAX_FILE_BYTES=20\*1024\*1024/);
  assert.match(html, /MAX_RENDER_ITEMS=500/);
  assert.match(html, /FileReader/);
  assert.match(html, /originalFileText=String\(r\.result\|\|''\)/);
  assert.match(html, /inputSource:fromFile\?'file':'paste'/);
  assert.doesNotMatch(html, /fetch\s*\(/);
  assert.doesNotMatch(html, /innerHTML\s*=/);
});

test('homepage links the mail analyzer as an available third utility', () => {
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  assert.match(html, /href="mail-analyzer\.html"/);
  assert.match(html, /UTILITY \/ 03/);
  assert.match(html, /class="badge beta">Beta<\/span>/);
  assert.match(html, /Mail (?:Header )?Analyzer/i);
});
