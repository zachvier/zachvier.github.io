'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeMessage } = require('../mail-analyzer-core.js');

function message(headers, body = 'body') {
  return ['From: a@example.com', 'Date: Wed, 29 Jul 2026 10:32:13 +0000'].concat(headers || []).join('\r\n') + '\r\n\r\n' + body + '\r\n';
}
function has(report, code) { return report.findings.some(f => f.code === code); }

test('treats browser-normalized LF endings as informational for pasted input', () => {
  const raw = message(['Subject: pasted'], 'body').replace(/\r\n/g, '\n');
  const report = analyzeMessage(raw, { inputSource: 'paste' });
  const lineEnding = report.findings.find(f => f.code === 'non-crlf-line-endings');
  assert.equal(lineEnding.severity, 'info');
  assert.equal(report.summary.warnings, 0);
  assert.equal(report.summary.errors, 0);
});

test('tolerates leading blank lines in pasted top-level messages without discarding valid headers', () => {
  const body = [
    '--x', 'Content-Type: text/plain', '', 'hello', '--x--'
  ].join('\r\n');
  const raw = '\r\n\r\n' + message([
    'Subject: Mimecast report',
    'Authentication-Results: relay.example; dkim=pass header.d=example.com',
    'Received: from outbound.example by relay.example; Wed, 29 Jul 2026 09:01:08 +0000',
    'Content-Type: multipart/mixed; boundary=x'
  ], body);
  const report = analyzeMessage(raw);
  assert.equal(report.summary.errors, 0);
  assert.equal(report.headers.subjectDecoded, 'Mimecast report');
  assert.equal(report.hops.length, 1);
  assert.equal(report.mime.totalParts, 2);
  assert.ok(has(report, 'leading-blank-lines-ignored'));
});

test('reports top-level header syntax findings exactly once', () => {
  const report = analyzeMessage('From: a@example.com\r\nDate: Wed, 29 Jul 2026 10:32:13 +0000\r\nBroken header\r\n\r\nbody');
  assert.equal(report.findings.filter(f => f.code === 'header-missing-colon').length, 1);
});

test('preserves MIME separators for valid empty body parts', () => {
  const body = [
    '--x', '', '--x', 'Content-Type: text/plain', '', '--x--'
  ].join('\r\n');
  const report = analyzeMessage(message(['MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary=x'], body));
  assert.equal(report.mime.tree.children.length, 2);
  assert.equal(report.findings.filter(f => f.code === 'mime-part-header-separator-missing').length, 0);
});

test('stops at first closing MIME boundary and ignores delimiter-looking epilogue lines', () => {
  const report = analyzeMessage(message(['Content-Type: multipart/mixed; boundary=x'], [
    '--x', 'Content-Type: text/plain', '', 'real', '--x--',
    'epilogue', '--x', 'Content-Type: text/plain', '', 'not a part', '--x--'
  ].join('\r\n')));
  assert.equal(report.mime.totalParts, 2);
  assert.ok(has(report, 'mime-delimiter-in-epilogue'));
});

test('does not create a phantom child for an immediate open-close boundary pair', () => {
  const report = analyzeMessage(message(['Content-Type: multipart/mixed; boundary=x'], '--x\r\n--x--'));
  assert.equal(report.mime.totalParts, 1);
  assert.equal(report.mime.tree.children.length, 0);
  assert.ok(has(report, 'mime-empty-part'));
});

test('rejects incomplete quoted-printable soft breaks and trailing literal whitespace', () => {
  const finalSoftBreak = analyzeMessage(message(['Content-Transfer-Encoding: quoted-printable'], 'hello='));
  assert.ok(has(finalSoftBreak, 'invalid-quoted-printable'));
  const trailingSpace = analyzeMessage(message(['Content-Transfer-Encoding: quoted-printable'], 'hello \r\nworld'));
  assert.ok(has(trailingSpace, 'quoted-printable-trailing-whitespace'));
});

test('rejects non-transport whitespace and non-zero Base64 padding bits', () => {
  assert.ok(has(analyzeMessage(message(['Content-Transfer-Encoding: base64'], 'ZG\u000b8=')), 'invalid-base64'));
  assert.ok(has(analyzeMessage(message(['Content-Transfer-Encoding: base64'], 'Zh==')), 'invalid-base64'));
  assert.ok(has(analyzeMessage(message(['Content-Transfer-Encoding: base64'], 'Zm9=')), 'invalid-base64'));
});

test('strictly rejects impossible RFC 5322 dates, invalid zones, and mismatched weekdays', () => {
  const impossible = analyzeMessage('From: a@example.com\r\nDate: Tue, 31 Feb 2026 10:00:00 +0000\r\n\r\nbody');
  assert.ok(has(impossible, 'invalid-date'));
  const badZone = analyzeMessage('From: a@example.com\r\nDate: Wed, 29 Jul 2026 10:00:00 +2460\r\n\r\nbody');
  assert.ok(has(badZone, 'invalid-date'));
  const badWeekday = analyzeMessage('From: a@example.com\r\nDate: Tue, 29 Jul 2026 10:00:00 +0000\r\n\r\nbody');
  assert.ok(has(badWeekday, 'invalid-date'));
});

test('invalid Received dates do not participate in chronology checks', () => {
  const report = analyzeMessage(message([
    'Received: from a by b; Tue, 31 Feb 2026 10:00:00 +0000',
    'Received: from c by a; Wed, 29 Jul 2026 11:00:00 +0000'
  ]));
  assert.equal(report.hops[0].timestamp, null);
  assert.ok(has(report, 'received-date-unparseable'));
  assert.ok(!has(report, 'received-time-inversion'));
});

test('Authentication-Results parser ignores method-like text inside quoted reasons', () => {
  const report = analyzeMessage(message([
    'Authentication-Results: mx.example; none reason="text dkim=pass; spf=fail"'
  ]));
  assert.deepEqual(report.authentication.observed.dkim, []);
  assert.deepEqual(report.authentication.observed.spf, []);
});

test('ARC presence is reported separately from an ARC method result', () => {
  const report = analyzeMessage(message([
    'ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=example.com; s=x; b=y',
    'ARC-Authentication-Results: i=1; mx.example; dkim=pass header.d=example.com'
  ]));
  assert.equal(report.authentication.arcSets, 1);
  assert.equal(report.authentication.arcAuthenticationResults, 1);
  assert.deepEqual(report.authentication.observed.arc, []);
});

function nested(depth) {
  function entity(level) {
    if (level === depth) return 'Content-Type: text/plain\r\n\r\nleaf';
    const b = 'b' + level;
    return 'Content-Type: multipart/mixed; boundary=' + b + '\r\n\r\n--' + b + '\r\n' + entity(level + 1) + '\r\n--' + b + '--';
  }
  return 'From: a@example.com\r\nDate: Wed, 29 Jul 2026 10:32:13 +0000\r\nMIME-Version: 1.0\r\n' + entity(0).replace(/^Content-Type:[^\r]+\r\n/, m => m);
}

test('hard MIME depth and part limits truncate parsing instead of merely warning', () => {
  const deep = analyzeMessage(nested(20), { maxMimeDepth: 3 });
  assert.ok(deep.mime.totalParts <= 4);
  assert.equal(deep.meta.truncated, true);
  assert.ok(has(deep, 'mime-depth-limit'));

  const body = ['--x', 'Content-Type: text/plain', '', 'a', '--x', 'Content-Type: text/plain', '', 'b', '--x', 'Content-Type: text/plain', '', 'c', '--x--'].join('\r\n');
  const wide = analyzeMessage(message(['MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary=x'], body), { maxMimeParts: 2 });
  assert.ok(wide.mime.totalParts <= 2);
  assert.equal(wide.meta.truncated, true);
  assert.ok(has(wide, 'mime-part-limit'));
});

test('hard input, header, line, and hop limits terminate safely', () => {
  const big = analyzeMessage('From: a@example.com\r\nDate: Wed, 29 Jul 2026 10:32:13 +0000\r\n\r\n' + 'x'.repeat(100), { maxInputCharacters: 50 });
  assert.equal(big.meta.truncated, true);
  assert.ok(has(big, 'input-size-limit'));

  const manyLines = analyzeMessage('From: a@example.com\r\nDate: Wed, 29 Jul 2026 10:32:13 +0000\r\n' + 'X: y\r\n'.repeat(100), { maxPhysicalLines: 5 });
  assert.equal(manyLines.meta.truncated, true);
  assert.ok(has(manyLines, 'physical-line-limit'));

  const manyHeaders = analyzeMessage(message(['X-1: a', 'X-2: b', 'X-3: c']), { maxHeaders: 3 });
  assert.ok(manyHeaders.headers.count <= 3);
  assert.ok(has(manyHeaders, 'header-limit'));

  const manyHops = analyzeMessage(message([
    'Received: from a by b; Wed, 29 Jul 2026 10:02:00 +0000',
    'Received: from c by a; Wed, 29 Jul 2026 10:01:00 +0000',
    'Received: from d by c; Wed, 29 Jul 2026 10:00:00 +0000'
  ]), { maxHops: 2 });
  assert.equal(manyHops.hops.length, 2);
  assert.ok(has(manyHops, 'received-hop-limit'));
});
