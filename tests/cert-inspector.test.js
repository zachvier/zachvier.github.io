'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const inspector = require('../cert-inspector-core.js');

const root = path.join(__dirname, '..');
const fixture = name => fs.readFileSync(path.join(__dirname, 'fixtures', name));

test('reads a safe X.509 PEM certificate with certificate and key evidence', () => {
  const report = inspector.inspect(fixture('sample-leaf.pem'), { name: 'sample-leaf.pem' });
  assert.equal(report.ok, true);
  assert.equal(report.problems.length, 0);
  assert.equal(report.documents.length, 1);

  const cert = report.documents[0];
  assert.equal(cert.kind, 'certificate');
  assert.equal(cert.version.label, 'v3');
  assert.match(cert.subject.text, /CN=example\.com/);
  assert.match(cert.issuer.text, /Example Test Root CA/);
  assert.equal(cert.publicKey.type, 'RSA');
  assert.equal(cert.publicKey.bits, 2048);
  assert.match(cert.fingerprints.sha256, /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/);
  assert.equal(cert.visual.cells.length, 64);
  assert.ok(cert.extensionSummary.subjectAltNames.some(name => name.value.includes('example.com')));
  assert.ok(cert.extensionSummary.keyUsage.includes('digitalSignature'));
});

test('reads DER and standalone RSA and EC SubjectPublicKeyInfo documents', () => {
  const der = inspector.inspect(fixture('sample-leaf.der'), { name: 'sample-leaf.der' });
  assert.equal(der.ok, true);
  assert.equal(der.source.format, 'DER');
  assert.equal(der.documents[0].kind, 'certificate');

  const rsa = inspector.inspect(fixture('sample-rsa-public-key.pem'), { name: 'rsa.pub' });
  assert.equal(rsa.ok, true);
  assert.equal(rsa.documents[0].kind, 'publicKey');
  assert.equal(rsa.documents[0].publicKey.type, 'RSA');
  assert.equal(rsa.documents[0].publicKey.bits, 2048);

  const ec = inspector.inspect(fixture('sample-ec-public-key.pem'), { name: 'ec.pub' });
  assert.equal(ec.ok, true);
  assert.equal(ec.documents[0].publicKey.type, 'EC');
  assert.match(ec.documents[0].publicKey.typeLabel, /P-256/);
});

test('parses a bare PKCS#1 RSAPublicKey from raw Base64 and RSA PUBLIC KEY PEM', () => {
  // Generate a public-only RSA key and export only its PKCS#1 RSAPublicKey
  // (SEQUENCE { modulus, exponent }). No private material is produced here.
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
  const pkcs1Der = publicKey.export({ type: 'pkcs1', format: 'der' });
  assert.match(pkcs1Der.toString('base64'), /^MIIBCgKCAQEA/);

  // Raw Base64 (no PEM armor) must parse as a standalone RSA public key.
  const raw = inspector.inspect(pkcs1Der.toString('base64'), { name: 'rsa-pkcs1.b64' });
  assert.equal(raw.ok, true);
  assert.equal(raw.containsPrivateKey, false);
  assert.equal(raw.problems.length, 0);
  assert.equal(raw.documents.length, 1);
  assert.equal(raw.documents[0].kind, 'publicKey');
  assert.equal(raw.documents[0].publicKey.type, 'RSA');
  assert.equal(raw.documents[0].publicKey.bits, 2048);
  assert.equal(raw.documents[0].publicKey.rsa.exponent, '65537');
  assert.ok(raw.documents[0].publicKey.details.some(d => /PKCS#1 RSAPublicKey/.test(String(d.value))));

  // The digest covers the RSAPublicKey SEQUENCE, so it must be scoped as such
  // and must not be offered as the SubjectPublicKeyInfo pin for the same key.
  const pkcs1Key = raw.documents[0].publicKey;
  const spkiPin = crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  assert.equal(pkcs1Key.fingerprintScope, 'PKCS#1 RSAPublicKey');
  assert.notEqual(pkcs1Key.fingerprints.sha256Base64, spkiPin);
  assert.match(raw.documents[0].observations.map(note => note.text).join(' '), /not the SubjectPublicKeyInfo digest used for key pinning/);

  // A SubjectPublicKeyInfo key keeps the SPKI scope and reproduces the real pin.
  const spki = inspector.inspect(publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), { name: 'rsa-spki.b64' });
  assert.equal(spki.documents[0].publicKey.fingerprintScope, 'SubjectPublicKeyInfo');
  assert.equal(spki.documents[0].publicKey.fingerprints.sha256Base64, spkiPin);

  // The same bytes wrapped in `BEGIN RSA PUBLIC KEY` armor must parse too.
  const body = pkcs1Der.toString('base64').match(/.{1,64}/g).join('\n');
  const pem = '-----BEGIN RSA PUBLIC KEY-----\n' + body + '\n-----END RSA PUBLIC KEY-----';
  const fromPem = inspector.inspect(pem, { name: 'rsa-pkcs1.pem' });
  assert.equal(fromPem.ok, true);
  assert.equal(fromPem.containsPrivateKey, false);
  assert.equal(fromPem.documents.length, 1);
  assert.equal(fromPem.documents[0].kind, 'publicKey');
  assert.equal(fromPem.documents[0].publicKey.type, 'RSA');
  assert.equal(fromPem.documents[0].publicKey.bits, 2048);
});

test('reads a CA certificate and an EC leaf without a trust or chain claim', () => {
  const ca = inspector.inspect(fixture('sample-ca.pem'), { name: 'sample-ca.pem' }).documents[0];
  assert.equal(ca.kind, 'certificate');
  assert.equal(ca.selfIssued, true);
  assert.equal(ca.extensionSummary.basicConstraints.ca, true);
  assert.equal(ca.extensionSummary.basicConstraints.pathLen, '1');
  assert.ok(ca.extensionSummary.keyUsage.includes('keyCertSign'));
  assert.match(ca.observations.map(note => note.text).join(' '), /basicConstraints marks this as a CA certificate with pathlen 1/);

  const ec = inspector.inspect(fixture('sample-ec-leaf.pem'), { name: 'sample-ec-leaf.pem' }).documents[0];
  assert.equal(ec.publicKey.type, 'EC');
  assert.equal(ec.publicKey.bits, 256);
  assert.match(ec.publicKey.ec.curveName, /P-256/);
  assert.equal(ec.publicKey.ec.pointFormat, 'uncompressed');
  assert.equal(ec.extensionSummary.basicConstraints.ca, false);

  // Nothing in the report may imply the signature or chain was checked.
  assert.match(ec.publicKey.fingerprintScope, /SubjectPublicKeyInfo/);
  assert.match(inspector.LIMITATIONS.join(' '), /signature on the certificate is never verified/);
  assert.match(inspector.LIMITATIONS.join(' '), /No chain building or trust evaluation/);
});

test('reads unarmoured Base64 from file bytes the same way it reads pasted Base64', () => {
  // A dropped .b64/.txt file arrives as bytes, not as a string. It must not be
  // misread as DER just because the DER branch also accepts a byte array.
  const der = fixture('sample-leaf.der');
  const asFile = new Uint8Array(Buffer.from(der.toString('base64') + '\n', 'utf8'));

  const report = inspector.inspect(asFile, { name: 'sample-leaf.b64' });
  assert.equal(report.ok, true);
  assert.equal(report.source.format, 'Base64 (no PEM header)');
  assert.equal(report.problems.length, 0);
  assert.equal(report.documents[0].kind, 'certificate');

  // Real DER is binary and must still take the DER path.
  const binary = inspector.inspect(der, { name: 'sample-leaf.der' });
  assert.equal(binary.source.format, 'DER');
  assert.equal(binary.documents[0].fingerprints.sha256, report.documents[0].fingerprints.sha256);
});

test('still rejects RSA private keys and never surfaces private material', () => {
  // A PKCS#1 RSAPrivateKey (9 INTEGERs) and a PKCS#8 PrivateKeyInfo must be
  // refused by the private-key heuristics, not parsed as public keys.
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });

  const pkcs1Priv = inspector.inspect(privateKey.export({ type: 'pkcs1', format: 'der' }).toString('base64'), { name: 'pkcs1.priv' });
  assert.equal(pkcs1Priv.ok, false);
  assert.equal(pkcs1Priv.containsPrivateKey, true);
  assert.equal(pkcs1Priv.documents.length, 0);

  const pkcs8Priv = inspector.inspect(privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'), { name: 'pkcs8.priv' });
  assert.equal(pkcs8Priv.ok, false);
  assert.equal(pkcs8Priv.containsPrivateKey, true);
  assert.equal(pkcs8Priv.documents.length, 0);
});

test('rejects private-key PEM labels before parsing or displaying key material', () => {
  const report = inspector.inspect('-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----', { name: 'private.key' });
  assert.equal(report.ok, false);
  assert.equal(report.containsPrivateKey, true);
  assert.equal(report.documents.length, 0);
  assert.match(report.problems.map(problem => problem.message).join(' '), /private key/i);
});

test('reports malformed and unsupported input without throwing', () => {
  for (const input of ['not a certificate', '-----BEGIN CERTIFICATE-----\nabc!\n-----END CERTIFICATE-----', Buffer.from([0x30, 0x81])]) {
    const report = inspector.inspect(input, { name: 'broken-input' });
    assert.equal(report.ok, false);
    assert.equal(report.documents.length, 0);
    assert.ok(report.problems.length > 0);
  }
});

test('keeps hostile certificate values as data and the UI page has strict local-only policy', () => {
  const report = inspector.inspect(fixture('adversarial-cert.pem'), { name: 'adversarial-cert.pem' });
  assert.equal(report.ok, true);
  assert.match(report.documents[0].subject.text, /\\<script\\>/);
  assert.match(report.documents[0].extensionSummary.subjectAltNames.map(name => name.value).join(' '), /<script>/);
  assert.equal(inspector.sanitizeText('<img src=x onerror=1>'), '<img src=x onerror=1>');

  const html = fs.readFileSync(path.join(root, 'cert-inspector.html'), 'utf8');
  const csp = /<meta\s+[^>]*http-equiv="Content-Security-Policy"[^>]*content="([^"]*)"/i.exec(html);
  assert.ok(csp, 'certificate page must declare CSP');
  assert.match(csp[1], /default-src 'none'/);
  assert.match(csp[1], /connect-src 'none'/);
  assert.match(csp[1], /object-src 'none'/);
  assert.doesNotMatch(html, /\.innerHTML\s*=/);

  const inline = /<script>([\s\S]*?)<\/script>/i.exec(html);
  assert.ok(inline, 'certificate page must include the reviewed UI script');
  const hash = `'sha256-${crypto.createHash('sha256').update(inline[1], 'utf8').digest('base64')}'`;
  assert.match(csp[1], new RegExp(hash.replace(/[+]/g, '\\+')));
});
