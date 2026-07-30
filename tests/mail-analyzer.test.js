'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { analyzeMessage, decodeHeaderValue } = require('../mail-analyzer-core.js');

function codes(report, severity) {
  return report.findings.filter(f => !severity || f.severity === severity).map(f => f.code);
}

const baseHeaders = [
  'From: Sender <sender@example.com>',
  'To: receiver@example.net',
  'Date: Wed, 29 Jul 2026 10:32:13 +0000',
  'Message-ID: <test@example.com>',
  'MIME-Version: 1.0'
];

function message(extraHeaders, body, eol = '\r\n') {
  return baseHeaders.concat(extraHeaders || []).join(eol) + eol + eol + (body || 'Hello') + eol;
}

test('tracked sanitized known-good message parses as a two-leaf multipart message', () => {
  const fixture = path.join(__dirname, 'fixtures', 'good-multipart.eml');
  const report = analyzeMessage(fs.readFileSync(fixture, 'utf8'));
  assert.equal(report.summary.errors, 0);
  assert.equal(report.mime.leafParts, 2);
  assert.equal(report.mime.totalParts, 3);
  assert.equal(report.hops.length, 2);
  assert.equal(report.headers.subjectDecoded, "Apple smart home 🏠, Anthropic cracks encryption 🔒, orchestrator's tax 🤖");
  assert.deepEqual(report.authentication.observed.dkim, ['pass', 'pass']);
  assert.deepEqual(report.authentication.observed.spf, ['pass']);
  assert.deepEqual(report.authentication.observed.dmarc, ['pass']);
});

test('decodes adjacent RFC 2047 Q and Base64 encoded words', () => {
  assert.equal(decodeHeaderValue('=?UTF-8?Q?Hello_=F0=9F=8F=A0?= =?UTF-8?B?4pyF?='), 'Hello 🏠✅');
});

test('reports malformed header lines, orphan folds, duplicate singleton fields, and bare line endings', () => {
  const raw = ' orphan fold\nFrom: a@example.com\nFrom: b@example.com\nBroken header\nTo: c@example.net\n\nbody';
  const report = analyzeMessage(raw);
  const found = codes(report);
  assert.ok(found.includes('header-orphan-continuation'));
  assert.ok(found.includes('header-missing-colon'));
  assert.ok(found.includes('duplicate-singleton-header'));
  assert.ok(found.includes('non-crlf-line-endings'));
});

test('reports missing required origin fields without treating Subject as required', () => {
  const report = analyzeMessage('Subject: hello\r\n\r\nbody');
  const missing = report.findings.filter(f => f.code === 'missing-header').map(f => f.context.header).sort();
  assert.deepEqual(missing, ['date', 'from']);
  assert.ok(!missing.includes('subject'));
});

test('detects an overlong physical line', () => {
  const report = analyzeMessage(message(['X-Long: ' + 'a'.repeat(1000)]));
  assert.ok(codes(report, 'error').includes('line-too-long'));
});

test('measures the hard physical-line limit in UTF-8 octets, not JavaScript characters', () => {
  const report = analyzeMessage(message(['X-Long: ' + '😀'.repeat(300)]));
  assert.ok(codes(report, 'error').includes('line-too-long'));
});

test('builds a nested MIME tree and validates transfer encodings', () => {
  const raw = message([
    'Content-Type: multipart/mixed; boundary="outer"'
  ], [
    '--outer',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'hello=20world',
    '--outer',
    'Content-Type: application/octet-stream',
    'Content-Transfer-Encoding: base64',
    '',
    'SGVsbG8=',
    '--outer--'
  ].join('\r\n'));
  const report = analyzeMessage(raw);
  assert.equal(report.mime.totalParts, 3);
  assert.equal(report.mime.leafParts, 2);
  assert.equal(report.summary.errors, 0);
});

test('detects missing MIME boundary parameter and missing closing delimiter', () => {
  const noParam = analyzeMessage(message(['Content-Type: multipart/mixed'], 'hello'));
  assert.ok(codes(noParam, 'error').includes('mime-boundary-missing'));

  const unclosed = analyzeMessage(message(['Content-Type: multipart/mixed; boundary=x'], [
    '--x', 'Content-Type: text/plain', '', 'hello'
  ].join('\r\n')));
  assert.ok(codes(unclosed, 'error').includes('mime-boundary-unclosed'));
});

test('detects invalid base64 and quoted-printable escapes', () => {
  const bad64 = analyzeMessage(message(['Content-Transfer-Encoding: base64'], 'abc$'));
  assert.ok(codes(bad64, 'error').includes('invalid-base64'));
  const badQp = analyzeMessage(message(['Content-Transfer-Encoding: quoted-printable'], 'hello=QZ'));
  assert.ok(codes(badQp, 'warning').includes('invalid-quoted-printable'));
});

test('hard-stops MIME part bombs using configurable limits', () => {
  const raw = message(['Content-Type: multipart/mixed; boundary=b'], '--b\r\n\r\na\r\n--b\r\n\r\nb\r\n--b--');
  const report = analyzeMessage(raw, { maxMimeParts: 2 });
  assert.ok(codes(report, 'error').includes('mime-part-limit'));
  assert.ok(report.mime.totalParts <= 2);
  assert.equal(report.meta.truncated, true);
});

test('flags invalid multipart transfer encoding and reused nested boundaries', () => {
  const raw = message([
    'Content-Type: multipart/mixed; boundary=x',
    'Content-Transfer-Encoding: base64'
  ], [
    '--x',
    'Content-Type: multipart/alternative; boundary=x',
    '',
    '--x',
    'Content-Type: text/plain',
    '',
    'hello',
    '--x--',
    '--x--'
  ].join('\r\n'));
  const report = analyzeMessage(raw);
  assert.ok(codes(report, 'error').includes('multipart-transfer-encoding'));
  assert.ok(codes(report, 'error').includes('mime-boundary-reused'));
});

test('warns when multipart alternative repeats a media type', () => {
  const raw = message(['Content-Type: multipart/alternative; boundary=x'], [
    '--x', 'Content-Type: text/plain', '', 'one',
    '--x', 'Content-Type: text/plain', '', 'two',
    '--x--'
  ].join('\r\n'));
  const report = analyzeMessage(raw);
  assert.ok(codes(report, 'warning').includes('alternative-duplicate-type'));
});

test('parses Received hops and flags chronology inversions', () => {
  const raw = message([
    'Received: from new.example by mx.example with ESMTPS; Wed, 29 Jul 2026 10:00:00 +0000',
    'Received: from old.example by new.example with ESMTP; Wed, 29 Jul 2026 10:06:00 +0000'
  ]);
  const report = analyzeMessage(raw);
  assert.equal(report.hops[0].from, 'old.example');
  assert.equal(report.hops[0].by, 'new.example');
  assert.equal(report.hops[0].with, 'ESMTP');
  assert.ok(codes(report, 'warning').includes('received-time-inversion'));
});

test('parses a Received date after the final grammar-level semicolon, ignoring comment punctuation', () => {
  const raw = message([
    'Received: from edge.example (note; internal) by mx.example with ESMTPS; Wed, 29 Jul 2026 10:00:00 +0000 (route; clock)'
  ]);
  const report = analyzeMessage(raw);
  assert.equal(report.hops[0].from, 'edge.example');
  assert.equal(report.hops[0].timestamp, Date.parse('Wed, 29 Jul 2026 10:00:00 +0000'));
  assert.ok(!codes(report).includes('received-date-unparseable'));
});

test('does not mistake declared authentication results for live verification', () => {
  const raw = message([
    'Authentication-Results: mx.example; dkim=pass header.d=example.com; spf=fail smtp.mailfrom=bad.example; dmarc=pass header.from=example.com',
    'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; bh=abc; b=xyz'
  ]);
  const report = analyzeMessage(raw);
  assert.deepEqual(report.authentication.observed, { dkim: ['pass'], spf: ['fail'], dmarc: ['pass'], arc: [] });
  assert.equal(report.authentication.verified, false);
  assert.match(report.authentication.caveat, /reported|observed/i);
});

test('flags malformed encoded words, control characters, and MIME headers without MIME-Version', () => {
  const raw = [
    'From: a@example.com',
    'Date: Wed, 29 Jul 2026 10:32:13 +0000',
    'Subject: =?UTF-8?Q?broken\u0000',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Hello</p>'
  ].join('\r\n');
  const report = analyzeMessage(raw);
  assert.ok(codes(report, 'warning').includes('invalid-encoded-word'));
  assert.ok(codes(report, 'warning').includes('mime-version-missing'));
  assert.ok(codes(report, 'error').includes('header-control-character'));
});

test('handles empty and header-only input without throwing', () => {
  assert.ok(analyzeMessage('').summary.errors > 0);
  assert.doesNotThrow(() => analyzeMessage('From: a@example.com\r\n'));
});
