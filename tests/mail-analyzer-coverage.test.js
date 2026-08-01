'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { analyzeMessage } = require('../mail-analyzer-core.js');

const fixturePath = path.join(__dirname, 'fixtures', 'complex-multihop-header-sample.eml');
const fixture = fs.readFileSync(fixturePath, 'utf8');
function fixtureNamed(name) {
  return fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
}

function findings(report, code) {
  return report.findings.filter(f => f.code === code);
}

function one(report, code) {
  const matches = findings(report, code);
  assert.equal(matches.length, 1, `expected exactly one ${code} finding`);
  return matches[0];
}

test('complex reference fixture retains the verified parser baseline', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  assert.equal(report.headers.count, 60);
  assert.equal(report.hops.length, 8);
  assert.equal(report.mime.totalParts, 6);
  assert.equal(report.mime.maxDepth, 2);
  assert.equal(report.headers.subjectDecoded, '[dev-announce] Résumé: Q3 infra review ✅ 完了');
  assert.equal(report.hops[0].from, 'mail.internal-crm.example.biz');
  assert.equal(report.hops[7].from, '');
});

test('complex trace identifies only the planted hop 1 continuity break and correlates its timestamp inversion', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  const breaks = findings(report, 'received-chain-discontinuity');
  assert.equal(breaks.length, 1);
  assert.equal(breaks[0].severity, 'error');
  assert.equal(breaks[0].context.hop, 1);
  assert.match(breaks[0].detail, /smtp-relay\.unrelated-host\.example\.net/i);
  assert.match(breaks[0].detail, /smtp-out-03\.mailsend\.example\.com/i);
  assert.equal(breaks[0].context.correlatedTimestampInversion, true);

  const inversion = one(report, 'received-time-inversion');
  assert.equal(inversion.context.priorTraceHop, 1);
  assert.equal(inversion.context.correlatedChainBreak, true);
  assert.match(inversion.detail, /forged prepend/i);

  assert.deepEqual(
    report.findings
      .filter(finding => Number.isInteger(finding.context.hop))
      .map(finding => ({ code: finding.code, hop: finding.context.hop }))
      .sort((a, b) => a.hop - b.hop || a.code.localeCompare(b.code)),
    [
      { code: 'received-chain-discontinuity', hop: 1 },
      { code: 'helo-hostname-mismatch', hop: 1 },
      { code: 'plaintext-smtp', hop: 1 },
      { code: 'received-address-mismatch', hop: 2 },
      { code: 'tls-verification-failed', hop: 5 }
    ].sort((a, b) => a.hop - b.hop || a.code.localeCompare(b.code))
  );

  assert.ok(!breaks.some(f => f.context.hop === 4), 'loopback re-injection must be exempt');
  assert.ok(!breaks.some(f => f.context.hop === 7 || f.context.hop === 8), 'by-only hops must be skipped');
});

test('trace continuity accepts an observed peer literal matching the adjacent receiver', () => {
  const report = analyzeMessage([
    'Received: from outbound.example.org (outbound.example.org [192.0.2.1]) by mx.example.net with ESMTPS; Wed, 29 Jul 2026 10:00:02 +0000',
    'Received: from origin.example.org by [192.0.2.1] with ESMTPS; Wed, 29 Jul 2026 10:00:01 +0000',
    'From: sender@example.org',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <address-continuity@example.org>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.ok(!report.findings.some(finding => finding.code === 'received-chain-discontinuity'));
});

test('trace continuity accepts a parsed rDNS hostname matching the adjacent receiver', () => {
  const report = analyzeMessage([
    'Received: from mail (mail.example.com [192.0.2.1]) by mx.example.net with ESMTPS; Wed, 29 Jul 2026 10:00:02 +0000',
    'Received: from origin.example.org by mail.example.com with ESMTPS; Wed, 29 Jul 2026 10:00:01 +0000',
    'From: sender@example.org',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <rdns-continuity@example.org>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.ok(!report.findings.some(finding => finding.code === 'received-chain-discontinuity'));
});

test('trace continuity does not treat an unknown rDNS sentinel as an endpoint', () => {
  const report = analyzeMessage([
    'Received: from mail (unknown [192.0.2.1]) by mx.example.net with ESMTPS; Wed, 29 Jul 2026 10:00:02 +0000',
    'Received: from origin.example.org by unknown with ESMTPS; Wed, 29 Jul 2026 10:00:01 +0000',
    'From: sender@example.org',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <unknown-rdns@example.org>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.equal(report.findings.filter(finding => finding.code === 'received-chain-discontinuity').length, 1);
});

test('complex trace exposes transport, peer-address, HELO, recipient, and aggregate special-use evidence', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  const hop2 = report.hops[1];
  const hop1 = report.hops[0];
  assert.equal(hop2.origin, '198.51.100.203');
  assert.equal(hop2.observedAddress, '198.51.100.203');
  assert.equal(hop2.assertedAddress, '10.14.7.203');
  assert.equal(hop2.rdns, 'unknown');
  assert.equal(hop2.helo, 'DESKTOP-8KQ2M1');
  assert.equal(hop2.xOriginatingIpMatch, true);

  const addressMismatch = one(report, 'received-address-mismatch');
  assert.equal(addressMismatch.severity, 'warning');
  assert.equal(addressMismatch.context.hop, 2);
  assert.match(addressMismatch.detail, /10\.14\.7\.203/);
  assert.match(addressMismatch.detail, /198\.51\.100\.203/);
  assert.match(addressMismatch.detail, /unknown/i);
  assert.match(addressMismatch.detail, /RFC 1918/i);
  assert.match(addressMismatch.detail, /X-Originating-IP/i);

  assert.deepEqual(hop1.tls, { status: 'plaintext', version: '', cipher: '', bits: '', verify: 'not-applicable', label: 'Plaintext SMTP', absenceReason: 'external-smtp-no-tls-evidence' });
  assert.equal(one(report, 'plaintext-smtp').context.hop, 1);
  assert.equal(one(report, 'helo-hostname-mismatch').context.hop, 1);

  const hop5 = report.hops[4];
  assert.equal(hop5.tls.version, 'TLSv1.2');
  assert.equal(hop5.tls.cipher, 'ECDHE-RSA-AES256-GCM-SHA384');
  assert.equal(hop5.tls.bits, '256');
  assert.equal(hop5.tls.verify, 'FAIL');
  assert.equal(one(report, 'tls-verification-failed').context.hop, 5);

  const recipient = one(report, 'envelope-recipient-change');
  assert.equal(recipient.severity, 'info');
  assert.deepEqual(recipient.context.hops, [5, 6]);
  assert.match(recipient.detail, /dev-alerts@example-corp\.com/);
  assert.match(recipient.detail, /r\.okafor@example-corp\.com/);

  const special = one(report, 'special-use-addresses');
  assert.equal(special.severity, 'info');
  assert.ok(special.context.hops.includes(1));
  assert.ok(special.context.hops.includes(2));
  assert.match(special.detail, /RFC 1918/);
  assert.match(special.detail, /RFC 5737/);
  assert.match(special.detail, /RFC 2544/);
});

test('complex trace reports structured TLS posture and normal per-hop timing without a queue-delay alarm', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  assert.equal(report.hops[2].tls.version, 'TLSv1.3');
  assert.equal(report.hops[2].tls.cipher, 'TLS_AES_128_GCM_SHA256');
  assert.equal(report.hops[5].tls.version, 'TLS1_3');
  assert.equal(report.hops[6].tls.label, 'Google Transport Security');
  assert.equal(report.timing.totalSeconds, 53);
  assert.deepEqual(report.timing.largest, { fromHop: 3, toHop: 4, seconds: 21 });
  assert.ok(!report.findings.some(f => /queue|delay/i.test(f.code) && f.context && f.context.seconds === 21));
});

test('complex fixture cross-checks identities, reported DKIM verdicts, Received-SPF, DMARC alignment, and client fingerprints', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  assert.deepEqual(report.identities, {
    returnPath: 'lists.dev-community.example.org',
    sender: 'lists.dev-community.example.org',
    from: 'northwind-labs.example',
    replyTo: 'lists.dev-community.example.org'
  });
  const identity = one(report, 'identity-domain-spread');
  assert.equal(identity.severity, 'warning');
  assert.match(identity.detail, /Return-Path.*lists\.dev-community\.example\.org/i);
  assert.match(identity.detail, /From.*northwind-labs\.example/i);

  const signature = report.authentication.signatures.find(s => s.domain === 'northwind-labs.example');
  assert.equal(signature.selector, 'selector1');
  assert.ok(!/\s/.test(signature.b));
  assert.ok(!/\s/.test(signature.signedHeaders));
  assert.deepEqual(signature.reports.map(r => ({ result: r.result, evaluator: r.evaluator, arcInstance: r.arcInstance, sealer: r.sealer })), [
    { result: 'fail', evaluator: 'gateway.corp-relay.example.net', arcInstance: 2, sealer: 'corp-relay.example.net' },
    { result: 'fail', evaluator: 'mx.google.com', arcInstance: null, sealer: '' },
    { result: 'pass', evaluator: 'lists.dev-community.example.org', arcInstance: 1, sealer: 'lists.dev-community.example.org' }
  ]);
  const verdictConflict = one(report, 'dkim-verdict-conflict');
  assert.match(verdictConflict.detail, /Qm9k1vXe/);
  assert.match(verdictConflict.detail, /i=1.*pass/i);
  assert.match(verdictConflict.detail, /i=2.*fail/i);
  assert.match(verdictConflict.detail, /mx\.google\.com.*fail/i);
  assert.match(verdictConflict.detail, /consistent with.*body\/content.*changed between/i);
  assert.match(verdictConflict.detail, /do(?:es)? not establish why/i);
  assert.match(verdictConflict.detail, /header changes.*DNS\/key.*verifier behavior.*malformed\/truncated claims/i);
  assert.doesNotMatch(verdictConflict.detail, /malicious|proves? that|indicate that signed body/i);
  assert.doesNotMatch(verdictConflict.detail, /does,, but/i);
  assert.equal(verdictConflict.severity, 'info');

  const authTransition = one(report, 'authentication-instance-transition');
  assert.equal(authTransition.severity, 'info');
  assert.equal(authTransition.context.fromInstance, 1);
  assert.equal(authTransition.context.toInstance, 2);
  assert.equal(authTransition.context.fromDmarc, 'pass');
  assert.equal(authTransition.context.toDmarc, 'fail');
  assert.match(authTransition.detail, /dmarc=pass.*dmarc=fail/i);
  assert.match(authTransition.detail, /smtp\.mailfrom.*j\.moreau@northwind-labs\.example/i);
  assert.match(authTransition.detail, /dev-announce-bounces\+dev-alerts=example-corp\.com@lists\.dev-community\.example\.org/i);
  assert.match(authTransition.detail, /mailing-list/i);

  const dmarcClaims = report.authentication.records.filter(record => record.method === 'dmarc');
  assert.deepEqual(dmarcClaims.map(record => ({ result: record.result, evaluator: record.evaluator, arcInstance: record.arcInstance })), [
    { result: 'fail', evaluator: 'gateway.corp-relay.example.net', arcInstance: 2 },
    { result: 'fail', evaluator: 'mx.google.com', arcInstance: null },
    { result: 'pass', evaluator: 'lists.dev-community.example.org', arcInstance: 1 }
  ]);

  const arcClaims = report.authentication.records.filter(record => record.method === 'arc');
  assert.deepEqual(arcClaims.map(record => ({ result: record.result, evaluator: record.evaluator, arcInstance: record.arcInstance, parenthetical: record.parenthetical })), [
    { result: 'pass', evaluator: 'gateway.corp-relay.example.net', arcInstance: 2, parenthetical: 'i=1 spf=pass dkim=pass dmarc=pass' },
    { result: 'pass', evaluator: 'mx.google.com', arcInstance: null, parenthetical: 'i=2 spf=pass dkim=pass dmarc=pass' }
  ]);

  assert.deepEqual(report.authentication.receivedSpf.map(r => ({ result: r.result, evaluator: r.evaluator, domain: r.domain, clientIp: r.clientIp })), [
    { result: 'pass', evaluator: 'google.com', domain: 'lists.dev-community.example.org', clientIp: '203.0.113.47' },
    { result: 'neutral', evaluator: 'gateway.corp-relay.example.net', domain: 'northwind-labs.example', clientIp: '198.51.100.22' }
  ]);
  const spf = one(report, 'received-spf-disagreement');
  assert.match(spf.detail, /google\.com.*pass.*lists\.dev-community\.example\.org/i);
  assert.match(spf.detail, /gateway\.corp-relay\.example\.net.*neutral.*northwind-labs\.example/i);

  const alignment = one(report, 'dmarc-alignment-agreement');
  assert.equal(alignment.severity, 'info');
  assert.equal(alignment.context.derived, 'fail');
  assert.equal(alignment.context.reported, 'fail');
  assert.equal(Object.hasOwn(alignment.context, 'coverageComplete'), false);
  assert.match(alignment.detail, /strict alignment was not evaluated/i);
  assert.match(alignment.detail, /no aligned passing identifier/i);

  const clients = one(report, 'client-fingerprint-conflict');
  assert.equal(clients.severity, 'info');
  assert.match(clients.detail, /Microsoft Outlook 16\.0/);
  assert.match(clients.detail, /Mozilla Thunderbird\/128\.4\.2esr/);
});

test('an empty DKIM-Signature b tag cannot consume an unmatched reported claim', () => {
  const report = analyzeMessage([
    'Authentication-Results: mx.example; dkim=fail header.i=@unmatched.example header.b=missing123',
    'DKIM-Signature: v=1; d=malformed.example; s=s1; b=',
    'From: sender@example.org',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <empty-dkim-b@example.org>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  const claim = report.authentication.records.find(record => record.method === 'dkim');
  assert.equal(report.authentication.signatures[0].reports.length, 0);
  assert.ok(!claim.signatureDomain);
});

test('a reported DKIM header.b longer than the signature b cannot match in reverse', () => {
  const report = analyzeMessage([
    'Authentication-Results: mx.example; dkim=fail header.i=@victim.example header.b=short123LONG',
    'DKIM-Signature: v=1; d=victim.example; s=s1; b=short123',
    'From: sender@example.org',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <reverse-dkim-prefix@example.org>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.equal(report.authentication.signatures[0].reports.length, 0);
  assert.ok(!report.authentication.records.find(record => record.method === 'dkim').signatureDomain);
});

test('an ambiguous DKIM header.b prefix is not attributed to the first signature', () => {
  const report = analyzeMessage([
    'Authentication-Results: mx.example; spf=fail smtp.mailfrom=sender@other.example; dkim=pass header.i=@victim.example header.b=abcdefgh; dmarc=pass header.from=victim.example',
    'DKIM-Signature: v=1; d=victim.example; s=s1; b=abcdefgh111',
    'DKIM-Signature: v=1; d=victim.example; s=s2; b=abcdefgh222',
    'From: sender@victim.example',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <ambiguous-dkim-prefix@example.org>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.ok(report.authentication.signatures.every(signature => signature.reports.length === 0));
  assert.ok(!report.authentication.records.find(record => record.method === 'dkim').signatureDomain);
  assert.equal(report.authentication.dmarcAlignment[0].derived, 'indeterminate');
  assert.ok(!report.findings.some(finding => finding.code === 'dmarc-claim-contradiction'));
});

test('a too-short DKIM header.b prefix is not used for signature attribution', () => {
  const report = analyzeMessage([
    'Authentication-Results: mx.example; dkim=pass header.i=@victim.example header.b=a',
    'DKIM-Signature: v=1; d=victim.example; s=s1; b=abcdefgh111',
    'From: sender@example.org',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <short-dkim-prefix@example.org>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.equal(report.authentication.signatures[0].reports.length, 0);
  assert.ok(!report.authentication.records.find(record => record.method === 'dkim').signatureDomain);
});

test('golden singleton fixture reports each duplicated display field with both values', () => {
  const report = analyzeMessage(fixtureNamed('duplicate-singletons.eml'), { inputSource: 'file' });
  const duplicates = findings(report, 'duplicate-singleton-header');
  assert.equal(duplicates.length, 2);
  assert.ok(duplicates.every(f => f.severity === 'error'));
  assert.deepEqual(duplicates.map(f => f.context.header).sort(), ['from', 'message-id']);
  assert.ok(duplicates.every(f => f.context.values.length === 2));
});

test('golden message with no Received fields is handled explicitly', () => {
  const report = analyzeMessage(fixtureNamed('no-received.eml'), { inputSource: 'file' });
  assert.equal(report.hops.length, 0);
  assert.equal(one(report, 'received-headers-missing').severity, 'info');
});

test('golden old Date fixture flags a Date weeks before the earliest trace hop', () => {
  const report = analyzeMessage(fixtureNamed('date-before-trace.eml'), { inputSource: 'file' });
  const finding = one(report, 'date-before-received-trace');
  assert.equal(finding.severity, 'warning');
  assert.match(finding.detail, /Date.*1 Jun 2026/i);
  assert.match(finding.detail, /hop 1.*29 Jul 2026/i);
});

test('golden MIME fixture exposes disposition and both filenames, then flags their disagreement', () => {
  const report = analyzeMessage(fixtureNamed('filename-disagreement.eml'), { inputSource: 'file' });
  const attachment = report.mime.tree.children[1];
  assert.equal(attachment.disposition, 'attachment');
  assert.equal(attachment.contentTypeName, 'claimed-name.txt');
  assert.equal(attachment.dispositionFilename, 'actual-name.txt');
  assert.equal(attachment.filename, 'actual-name.txt');
  const mismatch = one(report, 'mime-filename-disagreement');
  assert.equal(mismatch.context.part, '1.2');
  assert.match(mismatch.detail, /claimed-name\.txt/);
  assert.match(mismatch.detail, /actual-name\.txt/);
  assert.ok(!findings(report, 'attachment-indicator-disagreement').length);
});

test('X-MS-Has-Attach yes disagrees with a message that has no attachment part', () => {
  const raw = fixtureNamed('no-received.eml').replace('Subject: No Received fixture', 'Subject: No attachment\r\nX-MS-Has-Attach: yes');
  const report = analyzeMessage(raw, { inputSource: 'file' });
  const mismatch = one(report, 'attachment-indicator-disagreement');
  assert.match(mismatch.detail, /X-MS-Has-Attach: yes/i);
  assert.match(mismatch.detail, /no attachment part/i);
});

test('DMARC-only Authentication-Results cannot derive failure from omitted SPF and DKIM clauses', () => {
  const report = analyzeMessage([
    'Authentication-Results: mx.example; dmarc=pass header.from=victim.example',
    'From: Victim <person@victim.example>',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <dmarc-only@example.net>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.equal(report.authentication.dmarcAlignment[0].derived, 'indeterminate');
  assert.ok(!report.findings.some(finding => finding.code === 'dmarc-claim-contradiction'));
});

test('DMARC derivation requires coverage for each same-domain DKIM signature', () => {
  const report = analyzeMessage([
    'Authentication-Results: mx.example; spf=fail smtp.mailfrom=sender@other.example; dkim=fail header.i=@victim.example header.b=first123; dmarc=pass header.from=victim.example',
    'DKIM-Signature: v=1; d=victim.example; s=one; b=first123abc',
    'DKIM-Signature: v=1; d=victim.example; s=two; b=second456def',
    'From: Victim <person@victim.example>',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <partial-dkim-coverage@example.net>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.equal(report.authentication.dmarcAlignment[0].derived, 'indeterminate');
  assert.ok(!report.findings.some(finding => finding.code === 'dmarc-claim-contradiction'));
});

test('one domain-only DKIM claim cannot cover multiple same-domain signatures', () => {
  const report = analyzeMessage([
    'Authentication-Results: mx.example; spf=fail smtp.mailfrom=sender@other.example; dkim=fail header.i=@victim.example; dmarc=pass header.from=victim.example',
    'DKIM-Signature: v=1; d=victim.example; s=one; b=first123abc',
    'DKIM-Signature: v=1; d=victim.example; s=two; b=second456def',
    'From: Victim <person@victim.example>',
    'To: receiver@example.net',
    'Date: Wed, 29 Jul 2026 10:00:00 +0000',
    'Message-ID: <ambiguous-dkim-coverage@example.net>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.equal(report.authentication.dmarcAlignment[0].derived, 'indeterminate');
  assert.ok(!report.findings.some(finding => finding.code === 'dmarc-claim-contradiction'));
});

test('golden forged dmarc=pass claim is a high-severity contradiction in the message own claims', () => {
  const report = analyzeMessage(fixtureNamed('forged-dmarc-pass.eml'), { inputSource: 'file' });
  const contradiction = one(report, 'dmarc-claim-contradiction');
  assert.equal(contradiction.severity, 'error');
  assert.equal(contradiction.context.reported, 'pass');
  assert.equal(contradiction.context.derived, 'fail');
  assert.match(contradiction.detail, /contradiction within the message’s own claims/i);
  assert.match(contradiction.detail, /not cryptographic verification/i);
});

test('golden clean trace connects fully and produces nothing above informational', () => {
  const report = analyzeMessage(fixtureNamed('clean-trace.eml'), { inputSource: 'file' });
  assert.equal(report.summary.errors, 0);
  assert.equal(report.summary.warnings, 0);
  assert.ok(!findings(report, 'received-chain-discontinuity').length);
  assert.ok(!findings(report, 'dmarc-claim-contradiction').length);
  assert.deepEqual(report.authentication.observed.dkim, ['pass']);
  assert.deepEqual(report.authentication.observed.spf, ['pass']);
  assert.deepEqual(report.authentication.observed.dmarc, ['pass']);
});

test('derived DMARC remains informational when relaxed organizational alignment needs unavailable suffix data', () => {
  ['a.shared.unknowncc|b.shared.unknowncc', 'foo.blogspot.com|bar.blogspot.com'].forEach(pair => {
    const [fromDomain, mailFromDomain] = pair.split('|');
    const report = analyzeMessage([
      `Authentication-Results: mx.example; spf=pass smtp.mailfrom=sender@${mailFromDomain}; dmarc=pass header.from=${fromDomain}`,
      `From: Person <person@${fromDomain}>`,
      'To: receiver@example.net',
      'Date: Wed, 29 Jul 2026 10:00:00 +0000',
      'Message-ID: <suffix@example.net>',
      '',
      'body'
    ].join('\r\n'), { inputSource: 'file' });
    assert.equal(report.authentication.dmarcAlignment[0].derived, 'indeterminate');
    assert.ok(report.findings.some(finding => finding.code === 'dmarc-alignment-indeterminate' && finding.severity === 'info'));
    assert.ok(!report.findings.some(finding => finding.code === 'dmarc-claim-contradiction'));
  });
});

test('complex fixture gives the trace-break evidence both the literal from claim and observed peer, and normalized timestamp instants', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  const discontinuity = one(report, 'received-chain-discontinuity');
  assert.equal(discontinuity.context.nextTraceFrom, '[10.14.7.203]');
  assert.equal(discontinuity.context.comparedRepresentation, 'literal from token');
  assert.equal(discontinuity.context.nextTraceObservedPeer, '198.51.100.203');
  assert.equal(Object.hasOwn(discontinuity.context, 'nextTraceFromRaw'), false);
  assert.equal(Object.hasOwn(discontinuity.context, 'comparedValue'), false);
  assert.equal(Object.hasOwn(discontinuity.context, 'nextTraceOrigin'), false);
  assert.match(discontinuity.detail, /literal from token/i);
  assert.match(discontinuity.detail, /observed peer 198\.51\.100\.203/i);

  const inversion = one(report, 'received-time-inversion');
  assert.match(inversion.detail, /normalized instant/i);
  assert.match(inversion.detail, /16:19:55 \+0000/i);
  assert.match(inversion.detail, /2026-07-21T16:13:29\.000Z/i);
  assert.match(inversion.detail, /18:13:29 \+0200/i);
  assert.equal(inversion.context.nextTraceNormalized, '2026-07-21T16:13:29.000Z');
  assert.equal(inversion.context.priorTraceNormalized, '2026-07-21T16:19:55.000Z');
});

test('complex fixture distinguishes by-only TLS absence from external SMTP without TLS evidence', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  assert.equal(report.hops[7].tls.absenceReason, 'by-only');
  assert.equal(report.hops[0].tls.absenceReason, 'external-smtp-no-tls-evidence');
});

test('received address mismatch consistently labels receiver-reported rDNS', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  const mismatch = one(report, 'received-address-mismatch');
  assert.match(mismatch.detail, /receiver-reported rDNS is unknown/i);
  assert.equal(mismatch.context.receiverReportedRdns, 'unknown');
  assert.equal(Object.hasOwn(mismatch.context, 'rdns'), false);
});

test('DKIM structured tags strip interior whitespace while unfolded display evidence retains it', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  const dkimHeader = report.headers.fields.find(header => header.lower === 'dkim-signature');
  assert.match(dkimHeader.value, /Q1aFy U0iOe2Hj/);
  assert.ok(!/\s/.test(report.authentication.signatures[0].b));
});

test('non-list DKIM verdict divergence is a warning', () => {
  const report = analyzeMessage(fixtureNamed('dkim-divergence-non-list.eml'), { inputSource: 'file' });
  const conflict = one(report, 'dkim-verdict-conflict');
  assert.equal(conflict.severity, 'warning');
});


test('findings carry inspectable evidence and the report has no overall verdict', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  assert.equal(Object.hasOwn(report.summary, 'verdict'), false);
  assert.ok(report.findings.length > 10);
  assert.ok(report.findings.every(f => typeof f.evidence === 'string' && f.evidence.length > 0));
  assert.equal(one(report, 'non-crlf-line-endings').severity, 'info');
});

test('designating hop 3 marks hops 1 and 2 and their findings unverifiable by construction', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file', trustedHop: 3 });
  assert.deepEqual(report.trustBoundary, { designated: true, trustedHop: 3, attackerControllableThroughHop: 2 });
  assert.deepEqual(report.hops.map(h => h.trust), ['untrusted', 'untrusted', 'controlled-side', 'controlled-side', 'controlled-side', 'controlled-side', 'controlled-side', 'controlled-side']);
  ['received-chain-discontinuity', 'plaintext-smtp', 'helo-hostname-mismatch', 'received-address-mismatch'].forEach(code => {
    const finding = one(report, code);
    assert.equal(finding.unverifiable, true, code);
    assert.match(finding.trustNote, /unverifiable by construction/i);
  });
});

test('numbers Received hops from the claimed origin and retains corroborated trace breaks as errors', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file', trustedHop: 6 });
  assert.deepEqual(report.hops.map(hop => hop.index), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.equal(report.hops[0].from, 'mail.internal-crm.example.biz');
  assert.equal(report.hops[0].by, 'smtp-relay.unrelated-host.example.net');
  assert.equal(report.hops[7].by, '2001:db8:4021:c0d::1a');
  assert.equal(report.hops[0].positionLabel, 'claimed origin');
  assert.equal(report.hops[7].positionLabel, 'final delivery');

  const discontinuity = one(report, 'received-chain-discontinuity');
  const inversion = one(report, 'received-time-inversion');
  assert.equal(discontinuity.context.hop, 1);
  assert.equal(discontinuity.severity, 'error');
  assert.equal(inversion.context.priorTraceHop, 1);
  assert.equal(inversion.context.nextTraceHop, 2);
  assert.equal(inversion.context.correlatedChainBreak, true);
  assert.deepEqual(one(report, 'special-use-addresses').context.hops, [1, 2, 3, 4, 5, 6, 8]);
  assert.deepEqual(report.hops.map(hop => hop.trust), ['untrusted', 'untrusted', 'untrusted', 'untrusted', 'untrusted', 'controlled-side', 'controlled-side', 'controlled-side']);
  assert.match(discontinuity.trustNote, /hop 1/i);
  assert.match(discontinuity.trustNote, /attacker-controllable/i);
  assert.deepEqual(report.timing.largest, { fromHop: 3, toHop: 4, seconds: 21 });
});

test('parses bare parenthetical peers and treats uncorroborated API-pool trace gaps as warnings', () => {
  const report = analyzeMessage([
    'Received: from mta-83-184.sparkpostmail.com (mta-83-184.sparkpostmail.com [192.174.83.184]) by mx.example.net with ESMTPS; Thu, 30 Jul 2026 22:17:18 +0000',
    'Received: from [10.90.22.233] ([10.90.22.233]) by i-098b8b5ca4756c5dc.mta2vrest.sd.prd.sparkpost (ecelerity 5.3.0.76339 r(msys-ecelerity:tags/5.3.0.2)) with REST id 0A/3C-34966-C6DCB6A6; Thu, 30 Jul 2026 22:17:16 +0000',
    'From: sender@example.org',
    'To: sanitized-recipient@example.net',
    'Date: Thu, 30 Jul 2026 22:17:15 +0000',
    'Message-ID: <sanitized-message@example.org>',
    '',
    'body'
  ].join('\r\n'), { inputSource: 'file' });
  const injection = report.hops[0];
  assert.equal(injection.observedAddress, '10.90.22.233');
  assert.equal(injection.assertedAddress, '10.90.22.233');
  assert.equal(injection.rdns, '');
  assert.equal(injection.tls.absenceReason, 'api-injection-no-tls-clause');
  assert.ok(!findings(report, 'received-address-mismatch').length);
  assert.match(one(report, 'special-use-addresses').detail, /hop 1: 10\.90\.22\.233 \(RFC 1918\)/);
  const discontinuity = one(report, 'received-chain-discontinuity');
  assert.equal(discontinuity.severity, 'warning');
  assert.match(discontinuity.detail, /missing intermediate trace field is common.*API-injection and pool-relay boundaries/i);
  assert.match(discontinuity.detail, /gap alone does not indicate forgery/i);
});

test('builds an observed-only flow diagram model with collapsed list processing and attached authentication claims', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file', trustedHop: 6 });
  const diagram = report.traceDiagram;
  assert.ok(diagram);
  assert.equal(diagram.delivery.label, 'r.okafor@example-corp.com');
  assert.equal(diagram.nodes.filter(node => node.label === 'lists.dev-community.example.org').length, 1);
  const listNode = diagram.nodes.find(node => node.label === 'lists.dev-community.example.org');
  assert.ok(listNode.annotations.some(annotation => annotation.kind === 'local-re-injection' && annotation.hop === 4));
  assert.ok(listNode.claims.some(claim => claim.arcInstance === 1));
  const gateway = diagram.nodes.find(node => node.label === 'gateway.corp-relay.example.net');
  assert.ok(gateway.claims.some(claim => claim.arcInstance === 2));
  assert.ok(gateway.claims.some(claim => claim.field === 'Received-SPF'));
  const google = diagram.nodes.find(node => node.label === 'mx.google.com');
  assert.ok(google.claims.some(claim => claim.evaluator === 'mx.google.com'));
  assert.ok(google.claims.some(claim => claim.field === 'Received-SPF' && claim.evaluator === 'google.com'));
  const breakAtOne = diagram.breaks.find(item => item.hop === 1);
  assert.deepEqual({ severity: breakAtOne.severity, from: breakAtOne.from, to: breakAtOne.to }, { severity: 'error', from: 'smtp-relay.unrelated-host.example.net', to: '[10.14.7.203]' });
  assert.equal(diagram.edges.find(edge => edge.hop === 2).interval, 'inverted');
  assert.match(diagram.edges.find(edge => edge.hop === 5).transport, /TLSv1\.2.*verify=FAIL/);
  assert.ok(diagram.edges.filter(edge => edge.peerNotStated).every(edge => /peer not stated/.test(edge.transport)));
  assert.equal(diagram.trustBoundary.attackerControllableThroughHop, 5);
});

test('diagram preserves a REST injection host, warning trace break, and Delivered-To mailbox without vendor labels', () => {
  const report = analyzeMessage([
    'Delivered-To: sanitized-recipient@example.net',
    'Received: from mta-83-184.sparkpostmail.com (mta-83-184.sparkpostmail.com [192.174.83.184]) by mx.example.net with ESMTPS; Thu, 30 Jul 2026 22:17:18 +0000',
    'Received: from [10.90.22.233] ([10.90.22.233]) by i-098b8b5ca4756c5dc.mta2vrest.sd.prd.sparkpost (ecelerity 5.3.0.76339) with REST; Thu, 30 Jul 2026 22:17:16 +0000',
    'From: sender@example.org', 'To: sanitized-recipient@example.net', 'Date: Thu, 30 Jul 2026 22:17:15 +0000', 'Message-ID: <sanitized-message@example.org>', '', 'body'
  ].join('\r\n'), { inputSource: 'file' });
  const diagram = report.traceDiagram;
  assert.equal(diagram.delivery.label, 'sanitized-recipient@example.net');
  assert.ok(diagram.nodes.some(node => node.label === 'i-098b8b5ca4756c5dc.mta2vrest.sd.prd.sparkpost'));
  assert.match(diagram.edges.find(edge => edge.hop === 1).transport, /REST.*no TLS clause stated/);
  assert.equal(diagram.breaks[0].severity, 'warning');
  assert.ok(!JSON.stringify(diagram).match(/Amazon SES|EmailOctopus campaign engine|Google mail server/i));
});

test('diagram origin uses the claimed hostname without borrowing its receiving timestamp', () => {
  const report = analyzeMessage(fixture, { inputSource: 'file' });
  const origin = report.traceDiagram.nodes[0];
  assert.equal(origin.label, 'mail.internal-crm.example.biz');
  assert.equal(origin.observedPeer, '198.18.7.11');
  assert.equal(origin.timestamp, '');
});

test('diagram keeps a bare asserted literal as the origin label and exposes DKIM signing identities', () => {
  const report = analyzeMessage([
    'Received: from [10.90.22.233] ([10.90.22.233]) by injection.example.net with REST; Thu, 30 Jul 2026 22:17:16 +0000',
    'Authentication-Results: injection.example.net; dkim=pass header.i=@sender.example header.s=campaign header.b=abc123',
    'From: sender@example.org', 'To: sanitized@example.net', 'Date: Thu, 30 Jul 2026 22:17:15 +0000', 'Message-ID: <sanitized@example.org>', '', 'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.equal(report.traceDiagram.nodes[0].label, '[10.90.22.233]');
  const claim = report.traceDiagram.nodes.find(node => node.label === 'injection.example.net').claims.find(item => item.method === 'dkim');
  assert.equal(claim.signingDomain, 'sender.example');
  assert.equal(claim.signingSelector, 'campaign');
});

test('classifies required IPv6 special-use allocations without making a traffic claim', () => {
  const report = analyzeMessage([
    'Received: from [::1] by [fe80::1] with SMTP; Thu, 30 Jul 2026 22:17:16 +0000',
    'Received: from [fc00::1] by [2002::1] with SMTP; Thu, 30 Jul 2026 22:17:17 +0000',
    'Received: from [64:ff9b::1] by [2001:db8::1] with SMTP; Thu, 30 Jul 2026 22:17:18 +0000',
    'From: sender@example.org', 'To: sanitized@example.net', 'Date: Thu, 30 Jul 2026 22:17:15 +0000', 'Message-ID: <sanitized@example.org>', '', 'body'
  ].join('\r\n'), { inputSource: 'file' });
  const special = one(report, 'special-use-addresses');
  assert.match(special.detail, /loopback/);
  assert.match(special.detail, /link-local/);
  assert.match(special.detail, /unique local/);
  assert.match(special.detail, /6to4/);
  assert.match(special.detail, /NAT64/);
});

test('treats a hostname with an observed loopback peer as a local continuation', () => {
  const report = analyzeMessage([
    'Received: from mta006-md-usw2.delv.a.intuit.com ([127.0.0.1]) by mail238.us4.mandrillapp.com with ESMTP; Thu, 30 Jul 2026 22:17:17 +0000',
    'Received: from mandrillapp.com by prior.example.net with ESMTP; Thu, 30 Jul 2026 22:17:16 +0000',
    'From: sender@example.org', 'To: sanitized@example.net', 'Date: Thu, 30 Jul 2026 22:17:15 +0000', 'Message-ID: <sanitized@example.org>', '', 'body'
  ].join('\r\n'), { inputSource: 'file' });
  assert.ok(!findings(report, 'received-chain-discontinuity').length);
  assert.ok(report.traceDiagram.nodes.some(node => node.label === 'prior.example.net'));
  assert.ok(report.traceDiagram.nodes.some(node => node.label === 'mail238.us4.mandrillapp.com'));
  assert.ok(report.traceDiagram.edges.some(edge => edge.hop === 2 && edge.loopbackPeer));
});

test('diagram omits verification status when the Received field states no TLS clause', () => {
  const report = analyzeMessage([
    'Received: from relay.example.net by mx.example.net with REST; Thu, 30 Jul 2026 22:17:16 +0000',
    'From: sender@example.org', 'To: sanitized@example.net', 'Date: Thu, 30 Jul 2026 22:17:15 +0000', 'Message-ID: <sanitized@example.org>', '', 'body'
  ].join('\r\n'), { inputSource: 'file' });
  const edge = report.traceDiagram.edges[0];
  assert.match(edge.transport, /no TLS clause stated/);
  assert.doesNotMatch(edge.transport, /verify=not-stated/);
});
