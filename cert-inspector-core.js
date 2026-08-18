(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.CertInspector = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var LIMITS = {
    maxInputBytes: 4 * 1024 * 1024,
    maxBlocks: 24,
    maxDerBytes: 512 * 1024,
    maxDepth: 32,
    maxChildren: 4096,
    maxTextLength: 4096,
    maxListItems: 512
  };

  var TAG = {
    BOOLEAN: 1,
    INTEGER: 2,
    BIT_STRING: 3,
    OCTET_STRING: 4,
    NULL: 5,
    OID: 6,
    UTF8_STRING: 12,
    SEQUENCE: 16,
    SET: 17,
    NUMERIC_STRING: 18,
    PRINTABLE_STRING: 19,
    T61_STRING: 20,
    IA5_STRING: 22,
    UTC_TIME: 23,
    GENERALIZED_TIME: 24,
    UNIVERSAL_STRING: 28,
    BMP_STRING: 30
  };

  function CertError(message) {
    this.name = 'CertError';
    this.message = message;
  }
  CertError.prototype = Object.create(Error.prototype);
  CertError.prototype.constructor = CertError;

  function fail(message) {
    throw new CertError(message);
  }

  /* ---------------------------------------------------------------- bytes */

  function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) return new Uint8Array(value);
    if (value && typeof value === 'object' && typeof value.byteLength === 'number' && value.buffer) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (Array.isArray(value)) return Uint8Array.from(value);
    fail('Unsupported input type.');
  }

  var HEX = '0123456789ABCDEF';

  function bytesToHex(bytes, separator) {
    var out = [];
    for (var i = 0; i < bytes.length; i++) out.push(HEX[bytes[i] >> 4] + HEX[bytes[i] & 15]);
    return out.join(separator === undefined ? '' : separator);
  }

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function bytesToBase64(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i += 3) {
      var a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
      out += B64[a >> 2];
      out += B64[((a & 3) << 4) | (b === undefined ? 0 : b >> 4)];
      out += b === undefined ? '=' : B64[((b & 15) << 2) | (c === undefined ? 0 : c >> 6)];
      out += c === undefined ? '=' : B64[c & 63];
    }
    return out;
  }

  function base64ToBytes(text) {
    var clean = String(text).replace(/[\s\r\n]+/g, '');
    if (!clean.length) fail('The encoded body is empty.');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) fail('The encoded body contains characters that are not valid Base64.');
    if (clean.length % 4 !== 0) fail('The encoded body is truncated or padded incorrectly.');
    var out = new Uint8Array((clean.length / 4) * 3), length = 0, i;
    for (i = 0; i < clean.length; i += 4) {
      var v = 0, pad = 0, j;
      for (j = 0; j < 4; j++) {
        var ch = clean.charAt(i + j);
        if (ch === '=') { v = v << 6; pad++; continue; }
        v = (v << 6) | B64.indexOf(ch);
      }
      out[length++] = (v >> 16) & 255;
      if (pad < 2) out[length++] = (v >> 8) & 255;
      if (pad < 1) out[length++] = v & 255;
    }
    return out.subarray(0, length);
  }

  function decodeUtf8(bytes) {
    var out = '', i = 0;
    while (i < bytes.length) {
      var b = bytes[i++], code;
      if (b < 0x80) code = b;
      else if (b >= 0xc2 && b <= 0xdf && i < bytes.length) code = ((b & 0x1f) << 6) | (bytes[i++] & 0x3f);
      else if (b >= 0xe0 && b <= 0xef && i + 1 < bytes.length) {
        code = ((b & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6);
        code |= bytes[i++] & 0x3f;
      } else if (b >= 0xf0 && b <= 0xf4 && i + 2 < bytes.length) {
        code = ((b & 0x07) << 18) | ((bytes[i++] & 0x3f) << 12) | ((bytes[i++] & 0x3f) << 6);
        code |= bytes[i++] & 0x3f;
      } else code = 0xfffd;
      out += code > 0xffff
        ? String.fromCharCode(0xd800 + ((code - 0x10000) >> 10), 0xdc00 + ((code - 0x10000) & 0x3ff))
        : String.fromCharCode(code);
    }
    return out;
  }

  function decodeUtf16be(bytes) {
    var out = '';
    for (var i = 0; i + 1 < bytes.length; i += 2) out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    return out;
  }

  function decodeUtf32be(bytes) {
    var out = '';
    for (var i = 0; i + 3 < bytes.length; i += 4) {
      var code = (bytes[i] * 0x1000000) + (bytes[i + 1] << 16) + (bytes[i + 2] << 8) + bytes[i + 3];
      if (code > 0x10ffff) { out += '\ufffd'; continue; }
      out += code > 0xffff
        ? String.fromCharCode(0xd800 + ((code - 0x10000) >> 10), 0xdc00 + ((code - 0x10000) & 0x3ff))
        : String.fromCharCode(code);
    }
    return out;
  }

  function decodeLatin1(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
    return out;
  }

  // Certificate strings are attacker-controlled. Control, bidi, and line-breaking
  // characters are escaped so a value cannot restyle or reorder the report text.
  function sanitizeText(value) {
    var text = String(value === undefined || value === null ? '' : value);
    var truncated = false;
    if (text.length > LIMITS.maxTextLength) {
      text = text.slice(0, LIMITS.maxTextLength);
      truncated = true;
    }
    text = text.replace(/[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff\ufff9-\ufffb]/g, function (ch) {
      var code = ch.charCodeAt(0).toString(16).toUpperCase();
      return '\\u' + '0000'.slice(code.length) + code;
    });
    return truncated ? text + '… (truncated)' : text;
  }

  /* ----------------------------------------------------------------- hash */

  function rotr(value, count) {
    return ((value >>> count) | (value << (32 - count))) >>> 0;
  }

  function padMessage(bytes) {
    var length = bytes.length, blocks = Math.ceil((length + 9) / 64), padded = new Uint8Array(blocks * 64);
    padded.set(bytes);
    padded[length] = 0x80;
    var high = Math.floor((length * 8) / 0x100000000), low = (length * 8) >>> 0;
    var end = padded.length;
    padded[end - 8] = (high >>> 24) & 255;
    padded[end - 7] = (high >>> 16) & 255;
    padded[end - 6] = (high >>> 8) & 255;
    padded[end - 5] = high & 255;
    padded[end - 4] = (low >>> 24) & 255;
    padded[end - 3] = (low >>> 16) & 255;
    padded[end - 2] = (low >>> 8) & 255;
    padded[end - 1] = low & 255;
    return padded;
  }

  var SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function sha256(bytes) {
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var padded = padMessage(bytes), w = new Uint32Array(64), i, t;
    for (i = 0; i < padded.length; i += 64) {
      for (t = 0; t < 16; t++) {
        w[t] = (padded[i + t * 4] << 24) | (padded[i + t * 4 + 1] << 16) | (padded[i + t * 4 + 2] << 8) | padded[i + t * 4 + 3];
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var temp1 = (hh + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e;
        e = (d + temp1) >>> 0;
        d = c; c = b; b = a;
        a = (temp1 + temp2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[i * 4] = (h[i] >>> 24) & 255;
      out[i * 4 + 1] = (h[i] >>> 16) & 255;
      out[i * 4 + 2] = (h[i] >>> 8) & 255;
      out[i * 4 + 3] = h[i] & 255;
    }
    return out;
  }

  function sha1(bytes) {
    var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    var padded = padMessage(bytes), w = new Uint32Array(80), i, t;
    for (i = 0; i < padded.length; i += 64) {
      for (t = 0; t < 16; t++) {
        w[t] = (padded[i + t * 4] << 24) | (padded[i + t * 4 + 1] << 16) | (padded[i + t * 4 + 2] << 8) | padded[i + t * 4 + 3];
      }
      for (t = 16; t < 80; t++) {
        var x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        w[t] = ((x << 1) | (x >>> 31)) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
      for (t = 0; t < 80; t++) {
        var f, k;
        if (t < 20) { f = (b & c) ^ (~b & d); k = 0x5a827999; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (t < 60) { f = (b & c) ^ (b & d) ^ (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        var temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) >>> 0;
        e = d; d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0;
        b = a; a = temp;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0;
      h[3] = (h[3] + d) >>> 0; h[4] = (h[4] + e) >>> 0;
    }
    var out = new Uint8Array(20);
    for (i = 0; i < 5; i++) {
      out[i * 4] = (h[i] >>> 24) & 255;
      out[i * 4 + 1] = (h[i] >>> 16) & 255;
      out[i * 4 + 2] = (h[i] >>> 8) & 255;
      out[i * 4 + 3] = h[i] & 255;
    }
    return out;
  }

  function digestSet(bytes) {
    var s256 = sha256(bytes), s1 = sha1(bytes);
    return {
      sha256: bytesToHex(s256, ':'),
      sha256Plain: bytesToHex(s256, '').toLowerCase(),
      sha256Base64: bytesToBase64(s256),
      sha1: bytesToHex(s1, ':'),
      sha1Plain: bytesToHex(s1, '').toLowerCase()
    };
  }

  /* --------------------------------------------------------- visual digest */

  var VISUAL_COLORS = [
    '#001219', '#012a35', '#01414f', '#005f73', '#0a7d80', '#0a9396', '#4fb3a5', '#94d2bd',
    '#c6e3cc', '#e9d8a6', '#f0c069', '#ee9b00', '#ca6702', '#bb3e03', '#ae2012', '#9b2226'
  ];
  var VISUAL_GLYPHS = ['.', '^', ':', '-', '=', '+', '*', '#', '%', '@', '&', '$', 'O', 'X', 'B', '~'];

  // A deterministic 8x8 view of the SHA-256 digest. It is a comparison aid for
  // human eyes only and asserts nothing about the certificate.
  function visualDigest(bytes) {
    var digest = sha256(bytes), size = 8, cells = [], rows = [], row, col;
    for (row = 0; row < size; row++) {
      var line = '';
      for (col = 0; col < size; col++) {
        var index = row * size + col;
        var value = index % 2 === 0 ? digest[index >> 1] >> 4 : digest[index >> 1] & 15;
        cells.push({ row: row, col: col, value: value, color: VISUAL_COLORS[value], glyph: VISUAL_GLYPHS[value] });
        line += VISUAL_GLYPHS[value];
      }
      rows.push(line);
    }
    return {
      size: size,
      cells: cells,
      art: rows,
      text: rows.join('\n'),
      source: 'sha256',
      caption: 'Deterministic 8x8 view of the SHA-256 digest. Comparison aid only.'
    };
  }

  /* ---------------------------------------------------------------- ASN.1 */

  function readNode(bytes, start, end, depth) {
    if (depth > LIMITS.maxDepth) fail('DER nesting is deeper than the ' + LIMITS.maxDepth + '-level safety limit.');
    if (start >= end) fail('DER data ended before a value could be read.');
    var identifier = bytes[start], number = identifier & 0x1f, pos = start + 1;
    if (number === 0x1f) {
      number = 0;
      var shifts = 0;
      do {
        if (pos >= end) fail('DER tag is truncated.');
        if (++shifts > 4) fail('DER tag number is larger than this parser supports.');
        number = (number << 7) | (bytes[pos] & 0x7f);
      } while (bytes[pos++] & 0x80);
    }
    if (pos >= end) fail('DER length field is missing.');
    var first = bytes[pos++], length;
    if (first === 0x80) fail('Indefinite-length BER encoding is not supported; supply DER.');
    if (first === 0xff) fail('DER length field is reserved and invalid.');
    if (first < 0x80) length = first;
    else {
      var count = first & 0x7f;
      if (count > 4) fail('DER length field is larger than this parser supports.');
      if (pos + count > end) fail('DER length field is truncated.');
      length = 0;
      for (var i = 0; i < count; i++) length = (length * 256) + bytes[pos++];
    }
    if (length > end - pos) fail('A DER value claims ' + length + ' bytes but only ' + (end - pos) + ' remain.');
    return {
      bytes: bytes,
      tag: identifier,
      cls: identifier >> 6,
      constructed: (identifier & 0x20) !== 0,
      number: number,
      depth: depth,
      start: start,
      contentStart: pos,
      contentEnd: pos + length,
      length: length
    };
  }

  function content(node) {
    return node.bytes.subarray(node.contentStart, node.contentEnd);
  }

  function raw(node) {
    return node.bytes.subarray(node.start, node.contentEnd);
  }

  function children(node) {
    if (!node.constructed) fail('Expected a constructed DER value.');
    var out = [], pos = node.contentStart;
    while (pos < node.contentEnd) {
      var child = readNode(node.bytes, pos, node.contentEnd, node.depth + 1);
      out.push(child);
      if (out.length > LIMITS.maxChildren) fail('A DER sequence holds more elements than the safety limit allows.');
      pos = child.contentEnd;
    }
    return out;
  }

  function isUniversal(node, number) {
    return node.cls === 0 && node.number === number;
  }

  function expect(node, number, what) {
    if (!isUniversal(node, number)) fail('Expected ' + what + ' in the DER structure.');
    return node;
  }

  function isContext(node, number) {
    return node.cls === 2 && node.number === number;
  }

  function parseOid(node) {
    var data = content(node);
    if (!data.length) fail('An object identifier is empty.');
    var parts = [], first = data[0];
    if (first < 40) parts.push(0, first);
    else if (first < 80) parts.push(1, first - 40);
    else parts.push(2, first - 80);
    var value = 0, started = false;
    for (var i = 1; i < data.length; i++) {
      if (!started && data[i] === 0x80) fail('An object identifier arc is not minimally encoded.');
      started = true;
      value = value * 128 + (data[i] & 0x7f);
      if (value > Number.MAX_SAFE_INTEGER) fail('An object identifier arc is too large to decode.');
      if (!(data[i] & 0x80)) {
        parts.push(value);
        value = 0;
        started = false;
      }
    }
    if (started) fail('An object identifier ends mid-arc.');
    return parts.join('.');
  }

  function integerBytes(node) {
    var data = content(node);
    if (!data.length) fail('An INTEGER value is empty.');
    return data;
  }

  function integerBitLength(data) {
    var i = 0;
    while (i < data.length && data[i] === 0) i++;
    if (i === data.length) return 0;
    return (data.length - i - 1) * 8 + (32 - Math.clz32(data[i]));
  }

  function integerToDecimal(data) {
    var negative = (data[0] & 0x80) !== 0, magnitude = data, value = BigInt(0), i;
    if (negative) {
      magnitude = new Uint8Array(data.length);
      for (i = 0; i < data.length; i++) magnitude[i] = ~data[i] & 255;
      var carry = 1;
      for (i = magnitude.length - 1; i >= 0 && carry; i--) {
        var sum = magnitude[i] + carry;
        magnitude[i] = sum & 255;
        carry = sum >> 8;
      }
    }
    for (i = 0; i < magnitude.length; i++) value = (value << BigInt(8)) | BigInt(magnitude[i]);
    return (negative ? '-' : '') + value.toString(10);
  }

  function bitString(node) {
    var data = content(node);
    if (!data.length) fail('A BIT STRING is empty.');
    var unused = data[0];
    if (unused > 7) fail('A BIT STRING declares an invalid unused-bit count.');
    return { unusedBits: unused, bytes: data.subarray(1) };
  }

  function bitStringFlags(node) {
    var parsed = bitString(node), flags = [], total = parsed.bytes.length * 8 - parsed.unusedBits;
    for (var i = 0; i < total; i++) flags.push((parsed.bytes[i >> 3] >> (7 - (i & 7))) & 1);
    return flags;
  }

  function decodeString(node) {
    var data = content(node);
    switch (node.number) {
      case TAG.BMP_STRING: return sanitizeText(decodeUtf16be(data));
      case TAG.UNIVERSAL_STRING: return sanitizeText(decodeUtf32be(data));
      case TAG.UTF8_STRING: return sanitizeText(decodeUtf8(data));
      case TAG.T61_STRING: return sanitizeText(decodeLatin1(data));
      default: return sanitizeText(decodeUtf8(data));
    }
  }

  var STRING_TYPE_NAMES = {};
  STRING_TYPE_NAMES[TAG.UTF8_STRING] = 'UTF8String';
  STRING_TYPE_NAMES[TAG.PRINTABLE_STRING] = 'PrintableString';
  STRING_TYPE_NAMES[TAG.IA5_STRING] = 'IA5String';
  STRING_TYPE_NAMES[TAG.T61_STRING] = 'T61String';
  STRING_TYPE_NAMES[TAG.BMP_STRING] = 'BMPString';
  STRING_TYPE_NAMES[TAG.UNIVERSAL_STRING] = 'UniversalString';
  STRING_TYPE_NAMES[TAG.NUMERIC_STRING] = 'NumericString';
  STRING_TYPE_NAMES[26] = 'VisibleString';

  /* ------------------------------------------------------------------ OIDs */

  var OID_NAMES = {
    '2.5.4.3': 'commonName', '2.5.4.4': 'surname', '2.5.4.5': 'serialNumber', '2.5.4.6': 'countryName',
    '2.5.4.7': 'localityName', '2.5.4.8': 'stateOrProvinceName', '2.5.4.9': 'streetAddress',
    '2.5.4.10': 'organizationName', '2.5.4.11': 'organizationalUnitName', '2.5.4.12': 'title',
    '2.5.4.13': 'description', '2.5.4.15': 'businessCategory', '2.5.4.17': 'postalCode',
    '2.5.4.42': 'givenName', '2.5.4.43': 'initials', '2.5.4.44': 'generationQualifier',
    '2.5.4.46': 'dnQualifier', '2.5.4.65': 'pseudonym', '2.5.4.97': 'organizationIdentifier',
    '0.9.2342.19200300.100.1.1': 'userId', '0.9.2342.19200300.100.1.25': 'domainComponent',
    '1.2.840.113549.1.9.1': 'emailAddress',
    '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionLocality',
    '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionStateOrProvince',
    '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionCountry',

    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption',
    '1.2.840.113549.1.1.8': 'id-mgf1',
    '1.2.840.10045.2.1': 'id-ecPublicKey',
    '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
    '1.2.840.10045.4.3.1': 'ecdsa-with-SHA224',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    '1.2.840.10040.4.1': 'id-dsa',
    '1.2.840.10040.4.3': 'dsa-with-SHA1',
    '2.16.840.1.101.3.4.3.2': 'dsa-with-SHA256',
    '1.3.101.110': 'X25519', '1.3.101.111': 'X448', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
    '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512', '2.16.840.1.101.3.4.2.4': 'sha224',

    '2.5.29.9': 'subjectDirectoryAttributes', '2.5.29.14': 'subjectKeyIdentifier', '2.5.29.15': 'keyUsage',
    '2.5.29.16': 'privateKeyUsagePeriod', '2.5.29.17': 'subjectAltName', '2.5.29.18': 'issuerAltName',
    '2.5.29.19': 'basicConstraints', '2.5.29.30': 'nameConstraints', '2.5.29.31': 'cRLDistributionPoints',
    '2.5.29.32': 'certificatePolicies', '2.5.29.33': 'policyMappings', '2.5.29.35': 'authorityKeyIdentifier',
    '2.5.29.36': 'policyConstraints', '2.5.29.37': 'extKeyUsage', '2.5.29.46': 'freshestCRL',
    '2.5.29.54': 'inhibitAnyPolicy',
    '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess', '1.3.6.1.5.5.7.1.11': 'subjectInfoAccess',
    '1.3.6.1.5.5.7.1.24': 'TLS Feature', '1.3.6.1.5.5.7.48.1.5': 'OCSP No Check',
    '1.3.6.1.4.1.11129.2.4.2': 'Signed Certificate Timestamp list',
    '1.3.6.1.4.1.11129.2.4.3': 'CT Precertificate Poison',
    '2.16.840.1.113730.1.1': 'Netscape Cert Type', '2.16.840.1.113730.1.13': 'Netscape Comment',

    '1.3.6.1.5.5.7.3.1': 'TLS server authentication', '1.3.6.1.5.5.7.3.2': 'TLS client authentication',
    '1.3.6.1.5.5.7.3.3': 'Code signing', '1.3.6.1.5.5.7.3.4': 'Email protection',
    '1.3.6.1.5.5.7.3.5': 'IPsec end system', '1.3.6.1.5.5.7.3.6': 'IPsec tunnel',
    '1.3.6.1.5.5.7.3.7': 'IPsec user', '1.3.6.1.5.5.7.3.8': 'Time stamping',
    '1.3.6.1.5.5.7.3.9': 'OCSP signing', '2.5.29.37.0': 'Any extended key usage',
    '1.3.6.1.4.1.311.10.3.4': 'Microsoft Encrypting File System',
    '1.3.6.1.4.1.311.20.2.2': 'Microsoft Smart Card Logon',
    '1.3.6.1.4.1.311.20.2.3': 'Microsoft User Principal Name',
    '1.3.6.1.5.5.7.8.9': 'SmtpUTF8Mailbox',

    '1.3.6.1.5.5.7.48.1': 'OCSP', '1.3.6.1.5.5.7.48.2': 'CA Issuers',
    '1.3.6.1.5.5.7.48.3': 'Time Stamping', '1.3.6.1.5.5.7.48.5': 'CA Repository',
    '1.3.6.1.5.5.7.2.1': 'CPS', '1.3.6.1.5.5.7.2.2': 'User Notice',
    '2.5.29.32.0': 'anyPolicy', '2.23.140.1.1': 'CA/B Forum extended validation',
    '2.23.140.1.2.1': 'CA/B Forum domain validated', '2.23.140.1.2.2': 'CA/B Forum organization validated',
    '2.23.140.1.2.3': 'CA/B Forum individual validated'
  };

  var RDN_SHORT = {
    commonName: 'CN', countryName: 'C', localityName: 'L', stateOrProvinceName: 'ST', streetAddress: 'STREET',
    organizationName: 'O', organizationalUnitName: 'OU', domainComponent: 'DC', userId: 'UID',
    emailAddress: 'emailAddress', serialNumber: 'serialNumber', surname: 'SN', givenName: 'GN',
    organizationIdentifier: 'organizationIdentifier', title: 'title', businessCategory: 'businessCategory',
    postalCode: 'postalCode', dnQualifier: 'dnQualifier', pseudonym: 'pseudonym'
  };

  var CURVES = {
    '1.2.840.10045.3.1.1': { name: 'P-192 (prime192v1 / secp192r1)', bits: 192 },
    '1.3.132.0.33': { name: 'P-224 (secp224r1)', bits: 224 },
    '1.2.840.10045.3.1.7': { name: 'P-256 (prime256v1 / secp256r1)', bits: 256 },
    '1.3.132.0.34': { name: 'P-384 (secp384r1)', bits: 384 },
    '1.3.132.0.35': { name: 'P-521 (secp521r1)', bits: 521 },
    '1.3.132.0.10': { name: 'secp256k1', bits: 256 },
    '1.3.36.3.3.2.8.1.1.7': { name: 'brainpoolP256r1', bits: 256 },
    '1.3.36.3.3.2.8.1.1.11': { name: 'brainpoolP384r1', bits: 384 },
    '1.3.36.3.3.2.8.1.1.13': { name: 'brainpoolP512r1', bits: 512 }
  };

  var SIGNATURE_SHAPES = {
    '1.2.840.113549.1.1.4': { hash: 'MD5', keyType: 'RSA' },
    '1.2.840.113549.1.1.5': { hash: 'SHA-1', keyType: 'RSA' },
    '1.2.840.113549.1.1.11': { hash: 'SHA-256', keyType: 'RSA' },
    '1.2.840.113549.1.1.12': { hash: 'SHA-384', keyType: 'RSA' },
    '1.2.840.113549.1.1.13': { hash: 'SHA-512', keyType: 'RSA' },
    '1.2.840.113549.1.1.14': { hash: 'SHA-224', keyType: 'RSA' },
    '1.2.840.113549.1.1.10': { hash: 'declared in parameters', keyType: 'RSA-PSS' },
    '1.2.840.10045.4.1': { hash: 'SHA-1', keyType: 'ECDSA' },
    '1.2.840.10045.4.3.1': { hash: 'SHA-224', keyType: 'ECDSA' },
    '1.2.840.10045.4.3.2': { hash: 'SHA-256', keyType: 'ECDSA' },
    '1.2.840.10045.4.3.3': { hash: 'SHA-384', keyType: 'ECDSA' },
    '1.2.840.10045.4.3.4': { hash: 'SHA-512', keyType: 'ECDSA' },
    '1.2.840.10040.4.3': { hash: 'SHA-1', keyType: 'DSA' },
    '2.16.840.1.101.3.4.3.2': { hash: 'SHA-256', keyType: 'DSA' },
    '1.3.101.112': { hash: 'SHA-512 (internal)', keyType: 'Ed25519' },
    '1.3.101.113': { hash: 'SHAKE256 (internal)', keyType: 'Ed448' }
  };

  var KEY_USAGE_BITS = [
    'digitalSignature', 'nonRepudiation (contentCommitment)', 'keyEncipherment', 'dataEncipherment',
    'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'
  ];
  var NS_CERT_TYPE_BITS = [
    'SSL client', 'SSL server', 'S/MIME', 'Object signing', 'reserved', 'SSL CA', 'S/MIME CA', 'Object signing CA'
  ];

  function oidName(oid) {
    return OID_NAMES[oid] || '';
  }

  function labelOid(oid) {
    var name = oidName(oid);
    return name ? name + ' (' + oid + ')' : oid;
  }

  /* ------------------------------------------------------------- structures */

  function parseAlgorithmIdentifier(node) {
    var parts = children(expect(node, TAG.SEQUENCE, 'an algorithm identifier'));
    if (!parts.length) fail('An algorithm identifier is empty.');
    var oid = parseOid(expect(parts[0], TAG.OID, 'an algorithm OID'));
    var result = { oid: oid, name: oidName(oid) || 'unrecognized algorithm', label: labelOid(oid), parameters: null, parameterNode: parts[1] || null };
    if (parts[1] && isUniversal(parts[1], TAG.NULL)) result.parameters = 'NULL';
    else if (parts[1] && isUniversal(parts[1], TAG.OID)) {
      var paramOid = parseOid(parts[1]);
      result.parameterOid = paramOid;
      result.parameters = labelOid(paramOid);
    } else if (parts[1]) result.parameters = parts[1].length + '-byte structured parameters';
    return result;
  }

  function describeSignatureAlgorithm(node) {
    var algorithm = parseAlgorithmIdentifier(node), shape = SIGNATURE_SHAPES[algorithm.oid];
    algorithm.hash = shape ? shape.hash : 'unrecognized';
    algorithm.keyType = shape ? shape.keyType : 'unrecognized';
    if (algorithm.oid === '1.2.840.113549.1.1.10' && algorithm.parameterNode && algorithm.parameterNode.constructed) {
      var pss = readPssParameters(algorithm.parameterNode);
      algorithm.hash = pss.hash;
      algorithm.parameters = 'hash ' + pss.hash + ' · MGF ' + pss.mgf + ' · salt ' + pss.saltLength + ' bytes';
    }
    return algorithm;
  }

  function readPssParameters(node) {
    var result = { hash: 'SHA-1 (default)', mgf: 'MGF1 with SHA-1 (default)', saltLength: 20 };
    try {
      children(node).forEach(function (field) {
        if (!isContext(field, 0) && !isContext(field, 1) && !isContext(field, 2)) return;
        var inner = children(field)[0];
        if (!inner) return;
        if (isContext(field, 0)) result.hash = parseAlgorithmIdentifier(inner).name;
        if (isContext(field, 1)) {
          var mgf = parseAlgorithmIdentifier(inner);
          result.mgf = mgf.name + (mgf.parameters ? ' with ' + mgf.parameters : '');
        }
        if (isContext(field, 2)) result.saltLength = Number(integerToDecimal(integerBytes(inner)));
      });
    } catch (error) {
      result.hash = 'unreadable PSS parameters';
    }
    return result;
  }

  function escapeRdnValue(value) {
    return value.replace(/([,+"\\<>;])/g, '\\$1').replace(/^([ #])/, '\\$1').replace(/ $/, '\\ ');
  }

  function parseName(node) {
    var rdns = [], parts = [];
    children(expect(node, TAG.SEQUENCE, 'a distinguished name')).forEach(function (rdnNode) {
      children(expect(rdnNode, TAG.SET, 'a relative distinguished name')).forEach(function (attribute) {
        var pair = children(expect(attribute, TAG.SEQUENCE, 'a name attribute'));
        if (pair.length < 2) fail('A name attribute is missing its value.');
        var oid = parseOid(expect(pair[0], TAG.OID, 'a name attribute type'));
        var name = oidName(oid);
        var short = RDN_SHORT[name] || name || oid;
        var value = isUniversal(pair[1], TAG.OID) ? parseOid(pair[1])
          : pair[1].constructed ? '(structured value, ' + pair[1].length + ' bytes)'
            : decodeString(pair[1]);
        rdns.push({
          oid: oid,
          type: name || 'unrecognized attribute',
          short: short,
          value: value,
          encoding: STRING_TYPE_NAMES[pair[1].number] || ('tag ' + pair[1].number),
          multiValued: false
        });
        parts.push(short + '=' + escapeRdnValue(value));
      });
    });
    return { rdns: rdns, text: parts.join(', '), empty: rdns.length === 0 };
  }

  function parseTime(node) {
    var text = sanitizeText(decodeLatin1(content(node))), match, year;
    if (isUniversal(node, TAG.UTC_TIME)) {
      match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$/.exec(text);
      if (!match) fail('A UTCTime value is malformed: ' + text);
      year = Number(match[1]);
      year += year < 50 ? 2000 : 1900;
    } else if (isUniversal(node, TAG.GENERALIZED_TIME)) {
      match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?(Z|[+-]\d{4})?$/.exec(text);
      if (!match) fail('A GeneralizedTime value is malformed: ' + text);
      year = Number(match[1]);
    } else fail('A validity field uses an unsupported time type.');
    var epoch = Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] || 0));
    var zone = match[7] || 'Z';
    if (zone !== 'Z') {
      var sign = zone.charAt(0) === '-' ? 1 : -1;
      epoch += sign * ((Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3, 5))) * 60000);
    }
    if (!isFinite(epoch)) fail('A validity timestamp could not be converted.');
    return {
      raw: text,
      kind: isUniversal(node, TAG.UTC_TIME) ? 'UTCTime' : 'GeneralizedTime',
      epoch: epoch,
      iso: new Date(epoch).toISOString().replace('.000Z', 'Z')
    };
  }

  function formatIp(bytes) {
    var i, parts = [];
    if (bytes.length === 4 || bytes.length === 8) {
      for (i = 0; i < 4; i++) parts.push(bytes[i]);
      var address = parts.join('.');
      if (bytes.length === 8) {
        var mask = [];
        for (i = 4; i < 8; i++) mask.push(bytes[i]);
        return address + '/' + mask.join('.');
      }
      return address;
    }
    if (bytes.length === 16 || bytes.length === 32) {
      var groups = [];
      for (i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
      var text = compressIpv6(groups);
      if (bytes.length === 32) {
        var maskGroups = [];
        for (i = 16; i < 32; i += 2) maskGroups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
        return text + '/' + compressIpv6(maskGroups);
      }
      return text;
    }
    return bytesToHex(bytes, ':') + ' (' + bytes.length + '-byte address)';
  }

  function compressIpv6(groups) {
    var bestStart = -1, bestLength = 0, start = -1, i;
    for (i = 0; i <= groups.length; i++) {
      if (i < groups.length && groups[i] === '0') {
        if (start === -1) start = i;
      } else if (start !== -1) {
        if (i - start > bestLength) { bestLength = i - start; bestStart = start; }
        start = -1;
      }
    }
    if (bestLength < 2) return groups.join(':');
    return groups.slice(0, bestStart).join(':') + '::' + groups.slice(bestStart + bestLength).join(':');
  }

  function parseGeneralName(node) {
    try {
      if (isContext(node, 0)) {
        var otherParts = children(node);
        var typeOid = otherParts.length ? parseOid(expect(otherParts[0], TAG.OID, 'an otherName type')) : '';
        var valueText = '';
        if (otherParts[1]) {
          var wrapped = otherParts[1].constructed ? children(otherParts[1])[0] : otherParts[1];
          valueText = wrapped && !wrapped.constructed ? decodeString(wrapped) : '(' + otherParts[1].length + ' bytes)';
        }
        return { type: 'otherName', label: 'otherName · ' + labelOid(typeOid), value: valueText };
      }
      if (isContext(node, 1)) return { type: 'rfc822Name', label: 'email', value: sanitizeText(decodeUtf8(content(node))) };
      if (isContext(node, 2)) return { type: 'dNSName', label: 'DNS', value: sanitizeText(decodeUtf8(content(node))) };
      if (isContext(node, 3)) return { type: 'x400Address', label: 'X.400 address', value: '(' + node.length + ' bytes)' };
      if (isContext(node, 4)) {
        var inner = children(node)[0];
        return { type: 'directoryName', label: 'directory name', value: inner ? parseName(inner).text : '' };
      }
      if (isContext(node, 5)) return { type: 'ediPartyName', label: 'EDI party name', value: '(' + node.length + ' bytes)' };
      if (isContext(node, 6)) return { type: 'uniformResourceIdentifier', label: 'URI', value: sanitizeText(decodeUtf8(content(node))) };
      if (isContext(node, 7)) return { type: 'iPAddress', label: 'IP', value: formatIp(content(node)) };
      if (isContext(node, 8)) return { type: 'registeredID', label: 'registered ID', value: labelOid(parseOid(node)) };
    } catch (error) {
      return { type: 'unreadable', label: 'unreadable name', value: error.message };
    }
    return { type: 'unknown', label: 'unknown name type ' + node.number, value: '(' + node.length + ' bytes)' };
  }

  function parseGeneralNames(node) {
    return children(node).slice(0, LIMITS.maxListItems).map(parseGeneralName);
  }

  /* --------------------------------------------------------------- key info */

  // Shared RSA (modulus, exponent) detail extraction used by both
  // SubjectPublicKeyInfo-wrapped keys and bare PKCS#1 RSAPublicKey sequences.
  function fillRsaKeyDetails(info, rsaNodes, context) {
    if (rsaNodes.length < 2) fail('The RSA public key in ' + context + ' is missing its modulus or exponent.');
    var modulus = integerBytes(expect(rsaNodes[0], TAG.INTEGER, 'the RSA modulus'));
    var exponent = integerBytes(expect(rsaNodes[1], TAG.INTEGER, 'the RSA exponent'));
    var modulusBits = integerBitLength(modulus);
    info.type = 'RSA';
    info.bits = modulusBits;
    info.typeLabel = 'RSA ' + modulusBits + '-bit';
    info.rsa = {
      modulusBits: modulusBits,
      modulusBytes: modulus[0] === 0 ? modulus.length - 1 : modulus.length,
      exponent: integerToDecimal(exponent),
      exponentHex: '0x' + bytesToHex(exponent, '').replace(/^0+(?=.)/, ''),
      modulusHexHead: bytesToHex(modulus.subarray(modulus[0] === 0 ? 1 : 0, (modulus[0] === 0 ? 1 : 0) + 8), ':'),
      modulusHexTail: bytesToHex(modulus.subarray(Math.max(0, modulus.length - 8)), ':')
    };
    info.details.push({ label: 'Modulus', value: modulusBits + ' bits (' + info.rsa.modulusBytes + ' bytes)' });
    info.details.push({ label: 'Public exponent', value: info.rsa.exponent + ' (' + info.rsa.exponentHex + ')' });
    info.details.push({ label: 'Modulus start', value: info.rsa.modulusHexHead + ' …' });
    info.details.push({ label: 'Modulus end', value: '… ' + info.rsa.modulusHexTail });
  }

  function parsePublicKeyInfo(spkiNode) {
    var parts = children(expect(spkiNode, TAG.SEQUENCE, 'a SubjectPublicKeyInfo'));
    if (parts.length < 2) fail('SubjectPublicKeyInfo is missing the algorithm or key.');
    var algorithm = parseAlgorithmIdentifier(parts[0]);
    var keyBits = bitString(expect(parts[1], TAG.BIT_STRING, 'a public key BIT STRING'));
    var spkiBytes = raw(spkiNode);
    var info = {
      algorithm: algorithm,
      type: 'unrecognized',
      typeLabel: algorithm.name,
      bits: null,
      keyBytes: keyBits.bytes.length,
      details: [],
      fingerprints: digestSet(spkiBytes),
      fingerprintScope: 'SubjectPublicKeyInfo',
      visual: visualDigest(spkiBytes),
      spkiBytes: spkiBytes.length,
      unusedBits: keyBits.unusedBits
    };

    if (algorithm.oid === '1.2.840.113549.1.1.1' || algorithm.oid === '1.2.840.113549.1.1.10') {
      info.type = 'RSA';
      var rsa = children(readNode(keyBits.bytes, 0, keyBits.bytes.length, spkiNode.depth + 1));
      fillRsaKeyDetails(info, rsa, 'the RSA public key');
    } else if (algorithm.oid === '1.2.840.10045.2.1') {
      info.type = 'EC';
      var curveOid = algorithm.parameterOid || '';
      var curve = CURVES[curveOid];
      var point = keyBits.bytes;
      var format = point.length && point[0] === 4 ? 'uncompressed' : point.length && (point[0] === 2 || point[0] === 3) ? 'compressed' : 'unrecognized point format';
      var derivedBits = format === 'uncompressed' ? ((point.length - 1) / 2) * 8 : (point.length - 1) * 8;
      info.bits = curve ? curve.bits : derivedBits;
      info.ec = {
        curveOid: curveOid,
        curveName: curve ? curve.name : (curveOid ? 'unrecognized named curve ' + curveOid : 'explicit or absent curve parameters'),
        pointFormat: format,
        pointBytes: point.length,
        derivedFieldBits: derivedBits
      };
      info.typeLabel = 'EC ' + (curve ? curve.name.split(' ')[0] : info.bits + '-bit');
      info.details.push({ label: 'Curve', value: info.ec.curveName });
      info.details.push({ label: 'Field size', value: info.bits + ' bits' });
      info.details.push({ label: 'Point', value: point.length + ' bytes, ' + format });
      if (format === 'uncompressed' && point.length > 1) {
        var half = (point.length - 1) / 2;
        info.details.push({ label: 'X start', value: bytesToHex(point.subarray(1, 1 + Math.min(8, half)), ':') + ' …' });
        info.details.push({ label: 'Y start', value: bytesToHex(point.subarray(1 + half, 1 + half + Math.min(8, half)), ':') + ' …' });
      }
    } else if (algorithm.oid === '1.2.840.10040.4.1') {
      info.type = 'DSA';
      var dsaParams = algorithm.parameterNode && algorithm.parameterNode.constructed ? children(algorithm.parameterNode) : [];
      if (dsaParams.length >= 2) {
        info.bits = integerBitLength(integerBytes(dsaParams[0]));
        info.dsa = { pBits: info.bits, qBits: integerBitLength(integerBytes(dsaParams[1])) };
        info.details.push({ label: 'Prime p', value: info.dsa.pBits + ' bits' });
        info.details.push({ label: 'Subprime q', value: info.dsa.qBits + ' bits' });
      }
      info.typeLabel = 'DSA' + (info.bits ? ' ' + info.bits + '-bit' : '');
    } else if (algorithm.oid === '1.3.101.112' || algorithm.oid === '1.3.101.113' || algorithm.oid === '1.3.101.110' || algorithm.oid === '1.3.101.111') {
      info.type = algorithm.name;
      info.bits = keyBits.bytes.length * 8;
      info.typeLabel = algorithm.name;
      info.details.push({ label: 'Key', value: keyBits.bytes.length + ' bytes (' + info.bits + ' bits)' });
    } else {
      info.details.push({ label: 'Algorithm', value: algorithm.label });
      info.details.push({ label: 'Key material', value: keyBits.bytes.length + ' bytes' });
    }

    info.details.push({ label: 'SPKI SHA-256', value: info.fingerprints.sha256 });
    info.details.push({ label: 'SPKI SHA-256 (base64)', value: info.fingerprints.sha256Base64 });
    return info;
  }

  /* ------------------------------------------------------------ extensions */

  function detailsForBasicConstraints(node, summary) {
    var parts = node.constructed ? children(node) : [];
    var ca = false, pathLen = null;
    parts.forEach(function (part) {
      if (isUniversal(part, TAG.BOOLEAN)) ca = content(part)[0] !== 0;
      else if (isUniversal(part, TAG.INTEGER)) pathLen = integerToDecimal(integerBytes(part));
    });
    summary.basicConstraints = { ca: ca, pathLen: pathLen };
    var details = [{ label: 'Certificate authority', value: ca ? 'yes' : 'no' }];
    if (pathLen !== null) details.push({ label: 'Path length constraint', value: pathLen });
    return details;
  }

  function detailsForKeyUsage(node, summary) {
    var flags = bitStringFlags(node), names = [];
    flags.forEach(function (bit, index) {
      if (bit && KEY_USAGE_BITS[index]) names.push(KEY_USAGE_BITS[index]);
      else if (bit) names.push('bit ' + index);
    });
    summary.keyUsage = names;
    return names.length ? names.map(function (name) { return { label: '', value: name }; }) : [{ label: '', value: 'no usage bits set' }];
  }

  function detailsForExtKeyUsage(node, summary) {
    var usages = children(node).slice(0, LIMITS.maxListItems).map(function (child) {
      var oid = parseOid(expect(child, TAG.OID, 'an extended key usage OID'));
      return { oid: oid, name: oidName(oid) || 'unrecognized purpose', label: labelOid(oid) };
    });
    summary.extKeyUsage = usages;
    return usages.map(function (usage) { return { label: '', value: usage.label }; });
  }

  function detailsForAltName(node, summary, key) {
    var names = parseGeneralNames(node);
    summary[key] = names;
    return names.map(function (name) { return { label: name.label, value: name.value }; });
  }

  function detailsForAuthorityKeyId(node, summary) {
    var details = [], keyId = '';
    children(node).forEach(function (field) {
      if (isContext(field, 0)) {
        keyId = bytesToHex(content(field), ':');
        details.push({ label: 'Key identifier', value: keyId });
      } else if (isContext(field, 1)) {
        parseGeneralNames(field).forEach(function (name) {
          details.push({ label: 'Issuer ' + name.label, value: name.value });
        });
      } else if (isContext(field, 2)) {
        details.push({ label: 'Issuer serial', value: bytesToHex(content(field), ':') });
      }
    });
    summary.authorityKeyId = keyId;
    return details.length ? details : [{ label: '', value: 'present but empty' }];
  }

  function detailsForCrlDistributionPoints(node, summary) {
    var details = [], points = [];
    children(node).slice(0, LIMITS.maxListItems).forEach(function (point) {
      children(point).forEach(function (field) {
        if (isContext(field, 0)) {
          children(field).forEach(function (fullName) {
            if (!isContext(fullName, 0)) return;
            parseGeneralNames(fullName).forEach(function (name) {
              points.push(name.value);
              details.push({ label: name.label, value: name.value });
            });
          });
        } else if (isContext(field, 1)) {
          details.push({ label: 'Reasons', value: bitStringFlags(field).join('') });
        } else if (isContext(field, 2)) {
          parseGeneralNames(field).forEach(function (name) {
            details.push({ label: 'CRL issuer ' + name.label, value: name.value });
          });
        }
      });
    });
    summary.crlDistributionPoints = points;
    return details;
  }

  function detailsForInfoAccess(node, summary, key) {
    var details = [], entries = [];
    children(node).slice(0, LIMITS.maxListItems).forEach(function (description) {
      var parts = children(description);
      if (parts.length < 2) return;
      var method = parseOid(expect(parts[0], TAG.OID, 'an access method OID'));
      var location = parseGeneralName(parts[1]);
      var name = oidName(method) || method;
      entries.push({ method: name, value: location.value });
      details.push({ label: name + ' · ' + location.label, value: location.value });
    });
    summary[key] = entries;
    return details;
  }

  function detailsForCertificatePolicies(node, summary) {
    var details = [], policies = [];
    children(node).slice(0, LIMITS.maxListItems).forEach(function (policy) {
      var parts = children(policy);
      if (!parts.length) return;
      var oid = parseOid(expect(parts[0], TAG.OID, 'a policy OID'));
      policies.push(oid);
      details.push({ label: 'Policy', value: labelOid(oid) });
      if (!parts[1]) return;
      children(parts[1]).slice(0, LIMITS.maxListItems).forEach(function (qualifier) {
        var qualifierParts = children(qualifier);
        if (qualifierParts.length < 2) return;
        var qualifierOid = parseOid(expect(qualifierParts[0], TAG.OID, 'a policy qualifier OID'));
        if (qualifierOid === '1.3.6.1.5.5.7.2.1') {
          details.push({ label: 'CPS', value: sanitizeText(decodeUtf8(content(qualifierParts[1]))) });
        } else {
          details.push({ label: oidName(qualifierOid) || qualifierOid, value: '(' + qualifierParts[1].length + ' bytes)' });
        }
      });
    });
    summary.certificatePolicies = policies;
    return details;
  }

  function detailsForNameConstraints(node) {
    var details = [];
    children(node).forEach(function (field) {
      var kind = isContext(field, 0) ? 'Permitted' : isContext(field, 1) ? 'Excluded' : 'Subtree';
      children(field).slice(0, LIMITS.maxListItems).forEach(function (subtree) {
        var base = children(subtree)[0];
        if (!base) return;
        var name = parseGeneralName(base);
        details.push({ label: kind + ' ' + name.label, value: name.value });
      });
    });
    return details;
  }

  // RFC 6962 SCT lists are TLS-encoded inside an OCTET STRING.
  function detailsForSctList(bytes) {
    var details = [];
    try {
      var node = readNode(bytes, 0, bytes.length, 0);
      var data = content(expect(node, TAG.OCTET_STRING, 'an SCT list'));
      if (data.length < 2) return [{ label: '', value: 'empty list' }];
      var total = (data[0] << 8) | data[1], pos = 2, end = Math.min(data.length, 2 + total), index = 0;
      while (pos + 2 <= end && index < 32) {
        var length = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        if (pos + length > end || length < 43) break;
        var version = data[pos];
        var logId = bytesToHex(data.subarray(pos + 1, pos + 33), '');
        var timestamp = 0;
        for (var i = 0; i < 8; i++) timestamp = timestamp * 256 + data[pos + 33 + i];
        details.push({
          label: 'SCT ' + (++index),
          value: 'v' + (version + 1) + ' · log ' + logId.toLowerCase().slice(0, 32) + '… · ' +
            (isFinite(timestamp) ? new Date(timestamp).toISOString().replace('.000Z', 'Z') : 'unreadable timestamp')
        });
        pos += length;
      }
      if (!details.length) details.push({ label: '', value: 'list present but no complete entry could be read' });
    } catch (error) {
      details.push({ label: '', value: 'could not be decoded: ' + error.message });
    }
    return details;
  }

  function parseExtension(extensionNode, summary) {
    var parts = children(expect(extensionNode, TAG.SEQUENCE, 'an extension'));
    if (parts.length < 2) fail('An extension is missing its value.');
    var oid = parseOid(expect(parts[0], TAG.OID, 'an extension OID'));
    var critical = false, valueNode = parts[1];
    if (isUniversal(parts[1], TAG.BOOLEAN)) {
      critical = content(parts[1])[0] !== 0;
      valueNode = parts[2];
    }
    if (!valueNode) fail('Extension ' + oid + ' has no value.');
    var payload = content(expect(valueNode, TAG.OCTET_STRING, 'an extension value'));
    var extension = {
      oid: oid,
      name: oidName(oid) || 'unrecognized extension',
      recognized: Boolean(oidName(oid)),
      critical: critical,
      byteLength: payload.length,
      details: []
    };

    try {
      if (oid === '1.3.6.1.4.1.11129.2.4.2') {
        extension.details = detailsForSctList(payload);
      } else if (oid === '2.5.29.14') {
        var ski = content(expect(readNode(payload, 0, payload.length, 0), TAG.OCTET_STRING, 'a subject key identifier'));
        summary.subjectKeyId = bytesToHex(ski, ':');
        extension.details = [{ label: 'Key identifier', value: summary.subjectKeyId }];
      } else if (oid === '2.16.840.1.113730.1.13') {
        extension.details = [{ label: '', value: decodeString(readNode(payload, 0, payload.length, 0)) }];
      } else if (oid === '1.3.6.1.5.5.7.48.1.5') {
        extension.details = [{ label: '', value: 'present (NULL)' }];
      } else {
        var inner = readNode(payload, 0, payload.length, 0);
        if (oid === '2.5.29.19') extension.details = detailsForBasicConstraints(inner, summary);
        else if (oid === '2.5.29.15') extension.details = detailsForKeyUsage(inner, summary);
        else if (oid === '2.5.29.37') extension.details = detailsForExtKeyUsage(inner, summary);
        else if (oid === '2.5.29.17') extension.details = detailsForAltName(inner, summary, 'subjectAltNames');
        else if (oid === '2.5.29.18') extension.details = detailsForAltName(inner, summary, 'issuerAltNames');
        else if (oid === '2.5.29.35') extension.details = detailsForAuthorityKeyId(inner, summary);
        else if (oid === '2.5.29.31' || oid === '2.5.29.46') extension.details = detailsForCrlDistributionPoints(inner, summary);
        else if (oid === '1.3.6.1.5.5.7.1.1') extension.details = detailsForInfoAccess(inner, summary, 'authorityInfoAccess');
        else if (oid === '1.3.6.1.5.5.7.1.11') extension.details = detailsForInfoAccess(inner, summary, 'subjectInfoAccess');
        else if (oid === '2.5.29.32') extension.details = detailsForCertificatePolicies(inner, summary);
        else if (oid === '2.5.29.30') extension.details = detailsForNameConstraints(inner);
        else if (oid === '2.16.840.1.113730.1.1') {
          extension.details = bitStringFlags(inner).map(function (bit, index) {
            return bit ? { label: '', value: NS_CERT_TYPE_BITS[index] || ('bit ' + index) } : null;
          }).filter(Boolean);
        } else if (oid === '1.3.6.1.5.5.7.1.24') {
          extension.details = children(inner).map(function (feature) {
            var value = integerToDecimal(integerBytes(feature));
            return { label: 'Feature', value: value === '5' ? '5 (status_request · OCSP must-staple)' : value };
          });
        } else if (oid === '2.5.29.54' || oid === '2.5.29.36') {
          extension.details = [{ label: '', value: inner.constructed ? children(inner).length + ' field(s)' : integerToDecimal(integerBytes(inner)) }];
        } else if (isUniversal(inner, TAG.OID)) {
          extension.details = [{ label: '', value: labelOid(parseOid(inner)) }];
        } else if (!inner.constructed && (inner.number === TAG.UTF8_STRING || inner.number === TAG.IA5_STRING || inner.number === TAG.PRINTABLE_STRING)) {
          extension.details = [{ label: '', value: decodeString(inner) }];
        } else {
          extension.details = [{ label: 'Raw value', value: bytesToHex(payload.subarray(0, 32), ':') + (payload.length > 32 ? ' … (' + payload.length + ' bytes)' : '') }];
        }
      }
    } catch (error) {
      extension.error = error.message;
      extension.details = [
        { label: 'Decode error', value: error.message },
        { label: 'Raw value', value: bytesToHex(payload.subarray(0, 32), ':') + (payload.length > 32 ? ' … (' + payload.length + ' bytes)' : '') }
      ];
    }
    return extension;
  }

  /* ----------------------------------------------------------- certificate */

  var DAY_MS = 86400000;

  function parseCertificate(bytes, options) {
    var now = options && options.now !== undefined ? Number(options.now) : Date.now();
    var certificateNode = readNode(bytes, 0, bytes.length, 0);
    expect(certificateNode, TAG.SEQUENCE, 'a Certificate SEQUENCE');
    if (certificateNode.contentEnd !== bytes.length) {
      fail('Trailing data follows the certificate (' + (bytes.length - certificateNode.contentEnd) + ' extra bytes).');
    }
    var top = children(certificateNode);
    if (top.length !== 3) fail('A Certificate must hold exactly three elements; found ' + top.length + '.');
    var tbs = expect(top[0], TAG.SEQUENCE, 'a TBSCertificate');
    var signatureAlgorithm = describeSignatureAlgorithm(top[1]);
    var signatureBits = bitString(expect(top[2], TAG.BIT_STRING, 'a signature BIT STRING'));

    var fields = children(tbs), index = 0, version = 1, versionExplicit = false;
    if (fields.length && isContext(fields[0], 0)) {
      versionExplicit = true;
      var versionNode = children(fields[0])[0];
      version = Number(integerToDecimal(integerBytes(expect(versionNode, TAG.INTEGER, 'the version')))) + 1;
      index++;
    }
    if (fields.length < index + 6) fail('The TBSCertificate is missing required fields.');
    var serialBytes = integerBytes(expect(fields[index++], TAG.INTEGER, 'the serial number'));
    var innerSignature = describeSignatureAlgorithm(fields[index++]);
    var issuer = parseName(fields[index++]);
    var validityFields = children(expect(fields[index++], TAG.SEQUENCE, 'the validity period'));
    if (validityFields.length < 2) fail('The validity period is missing a boundary.');
    var notBefore = parseTime(validityFields[0]);
    var notAfter = parseTime(validityFields[1]);
    var subject = parseName(fields[index++]);
    var publicKey = parsePublicKeyInfo(fields[index++]);

    var uniqueIds = { issuer: false, subject: false };
    var summary = {
      basicConstraints: null, keyUsage: null, extKeyUsage: null, subjectAltNames: null,
      issuerAltNames: null, subjectKeyId: '', authorityKeyId: '', authorityInfoAccess: null,
      subjectInfoAccess: null, crlDistributionPoints: null, certificatePolicies: null
    };
    var extensions = [], extensionErrors = [];
    while (index < fields.length) {
      var field = fields[index++];
      if (isContext(field, 1)) { uniqueIds.issuer = true; continue; }
      if (isContext(field, 2)) { uniqueIds.subject = true; continue; }
      if (!isContext(field, 3)) continue;
      var list = children(field)[0];
      if (!list) continue;
      children(expect(list, TAG.SEQUENCE, 'the extension list')).slice(0, LIMITS.maxListItems).forEach(function (extensionNode) {
        try {
          extensions.push(parseExtension(extensionNode, summary));
        } catch (error) {
          extensionErrors.push(error.message);
        }
      });
    }

    var status = now < notBefore.epoch ? 'not-yet-valid' : now > notAfter.epoch ? 'expired' : 'valid';
    var validity = {
      notBefore: notBefore,
      notAfter: notAfter,
      status: status,
      statusLabel: status === 'valid' ? 'Within validity window' : status === 'expired' ? 'Expired' : 'Not yet valid',
      evaluatedAt: new Date(now).toISOString().replace('.000Z', 'Z'),
      evaluatedAgainst: 'the local device clock',
      lifetimeDays: Math.round((notAfter.epoch - notBefore.epoch) / DAY_MS),
      daysRemaining: Math.floor((notAfter.epoch - now) / DAY_MS),
      daysSinceStart: Math.floor((now - notBefore.epoch) / DAY_MS),
      inverted: notAfter.epoch < notBefore.epoch
    };

    var certificate = {
      kind: 'certificate',
      label: 'Certificate',
      version: { number: version, encoded: version - 1, explicit: versionExplicit, label: 'v' + version },
      serialNumber: {
        hex: bytesToHex(serialBytes, ':'),
        decimal: integerToDecimal(serialBytes),
        bits: integerBitLength(serialBytes),
        negative: (serialBytes[0] & 0x80) !== 0,
        bytes: serialBytes.length
      },
      issuer: issuer,
      subject: subject,
      validity: validity,
      publicKey: publicKey,
      signatureAlgorithm: signatureAlgorithm,
      tbsSignatureAlgorithm: innerSignature,
      signature: {
        bits: signatureBits.bytes.length * 8,
        bytes: signatureBits.bytes.length,
        preview: bytesToHex(signatureBits.bytes.subarray(0, 16), ':') + (signatureBits.bytes.length > 16 ? ' …' : '')
      },
      extensions: extensions,
      extensionErrors: extensionErrors,
      extensionSummary: summary,
      uniqueIds: uniqueIds,
      selfIssued: issuer.text === subject.text && issuer.text !== '',
      byteLength: bytes.length,
      fingerprints: digestSet(bytes),
      visual: visualDigest(bytes),
      observations: []
    };
    certificate.observations = certificateObservations(certificate);
    return certificate;
  }

  // Neutral, factual notes. Nothing here is a trust, safety, or validity decision.
  function certificateObservations(certificate) {
    var notes = [], summary = certificate.extensionSummary, validity = certificate.validity;
    if (validity.inverted) notes.push({ tone: 'alert', text: 'notAfter is earlier than notBefore.' });
    if (validity.status === 'expired') {
      notes.push({ tone: 'alert', text: 'The validity window ended ' + Math.abs(validity.daysRemaining) + ' day(s) ago by the local clock.' });
    } else if (validity.status === 'not-yet-valid') {
      notes.push({ tone: 'alert', text: 'The validity window has not started yet by the local clock.' });
    } else {
      notes.push({ tone: 'plain', text: validity.daysRemaining + ' day(s) remain in the validity window by the local clock.' });
    }
    notes.push({ tone: 'plain', text: 'The validity window spans ' + validity.lifetimeDays + ' day(s).' });
    if (certificate.selfIssued) notes.push({ tone: 'note', text: 'Subject and issuer names are identical (self-issued). Chain trust is not evaluated here.' });
    if (summary.basicConstraints && summary.basicConstraints.ca) {
      notes.push({ tone: 'note', text: 'basicConstraints marks this as a CA certificate' + (summary.basicConstraints.pathLen !== null ? ' with pathlen ' + summary.basicConstraints.pathLen : '') + '.' });
    } else if (summary.basicConstraints) {
      notes.push({ tone: 'plain', text: 'basicConstraints marks this as an end-entity certificate.' });
    } else {
      notes.push({ tone: 'note', text: 'No basicConstraints extension is present.' });
    }
    if (certificate.version.number !== 3) notes.push({ tone: 'note', text: 'The certificate is encoded as v' + certificate.version.number + '; extensions require v3.' });
    if (/SHA-1|MD5/.test(certificate.signatureAlgorithm.hash)) {
      notes.push({ tone: 'alert', text: 'The signature uses ' + certificate.signatureAlgorithm.hash + ', which major browsers and CAs no longer accept for public trust.' });
    }
    if (certificate.publicKey.type === 'RSA' && certificate.publicKey.bits < 2048) {
      notes.push({ tone: 'alert', text: 'The RSA modulus is ' + certificate.publicKey.bits + ' bits, below the 2048-bit minimum used by public CAs.' });
    }
    if (certificate.signatureAlgorithm.oid !== certificate.tbsSignatureAlgorithm.oid) {
      notes.push({ tone: 'alert', text: 'The outer signature algorithm does not match the algorithm inside the signed body.' });
    }
    var sans = summary.subjectAltNames || [];
    if (!sans.length) {
      notes.push({ tone: 'note', text: 'No subjectAltName extension is present. Modern TLS clients ignore commonName for host matching.' });
    } else {
      var wildcards = sans.filter(function (name) { return name.type === 'dNSName' && name.value.indexOf('*') === 0; });
      notes.push({ tone: 'plain', text: sans.length + ' subject alternative name(s) are present' + (wildcards.length ? ', including ' + wildcards.length + ' wildcard entry/entries' : '') + '.' });
    }
    if (certificate.serialNumber.negative) notes.push({ tone: 'alert', text: 'The serial number is encoded as a negative INTEGER.' });
    if (certificate.extensionErrors.length) {
      notes.push({ tone: 'alert', text: certificate.extensionErrors.length + ' extension(s) could not be decoded and were skipped.' });
    }
    return notes;
  }

  function parsePublicKeyDocument(bytes) {
    var node = readNode(bytes, 0, bytes.length, 0);
    if (node.contentEnd !== bytes.length) fail('Trailing data follows the public key.');

    // A bare PKCS#1 RSAPublicKey is a SEQUENCE of exactly two INTEGERs
    // (modulus, exponent). Detect that shape before attempting SPKI so raw
    // Base64 and `BEGIN RSA PUBLIC KEY` documents parse as standalone RSA
    // public keys rather than erroring as "not SubjectPublicKeyInfo".
    var pkcs1 = null;
    try {
      var seqParts = children(node);
      if (seqParts.length === 2 && isUniversal(seqParts[0], TAG.INTEGER) && isUniversal(seqParts[1], TAG.INTEGER)) {
        pkcs1 = seqParts;
      }
    } catch (error) {
      // Not a readable two-INTEGER sequence; fall through to the SPKI attempt.
    }

    if (pkcs1) {
      var pkcs1Bytes = raw(node);
      var pkcs1Info = {
        algorithm: { oid: '1.2.840.113549.1.1.1', name: 'RSA (PKCS#1)', parameterOid: null, parameters: null },
        type: 'RSA',
        typeLabel: 'RSA',
        bits: null,
        keyBytes: pkcs1Bytes.length,
        details: [],
        fingerprints: digestSet(pkcs1Bytes),
        // The digest covers the RSAPublicKey SEQUENCE, not a SubjectPublicKeyInfo,
        // so it must never be presented as an SPKI pin for the same key.
        fingerprintScope: 'PKCS#1 RSAPublicKey',
        visual: visualDigest(pkcs1Bytes),
        spkiBytes: null,
        unusedBits: 0
      };
      fillRsaKeyDetails(pkcs1Info, pkcs1, 'the PKCS#1 key');
      pkcs1Info.details.unshift({ label: 'Encoding', value: 'PKCS#1 RSAPublicKey (modulus, exponent)' });
      pkcs1Info.details.push({ label: 'PKCS#1 SHA-256', value: pkcs1Info.fingerprints.sha256 });
      return {
        kind: 'publicKey',
        label: 'Public key (PKCS#1 RSAPublicKey)',
        publicKey: pkcs1Info,
        byteLength: bytes.length,
        fingerprints: pkcs1Info.fingerprints,
        visual: pkcs1Info.visual,
        observations: publicKeyObservations(pkcs1Info)
      };
    }

    var info = parsePublicKeyInfo(node);
    return {
      kind: 'publicKey',
      label: 'Public key (SubjectPublicKeyInfo)',
      publicKey: info,
      byteLength: bytes.length,
      fingerprints: info.fingerprints,
      visual: info.visual,
      observations: publicKeyObservations(info)
    };
  }

  function publicKeyObservations(info) {
    var notes = [{ tone: 'plain', text: 'This is a standalone public key. There is no subject, issuer, validity window, or extension data to report.' }];
    if (info.fingerprintScope === 'PKCS#1 RSAPublicKey') {
      notes.push({ tone: 'note', text: 'The fingerprints cover the PKCS#1 RSAPublicKey structure. They are not the SubjectPublicKeyInfo digest used for key pinning, so they will not match an SPKI pin for the same key.' });
    }
    if (info.type === 'RSA' && info.bits < 2048) {
      notes.push({ tone: 'alert', text: 'The RSA modulus is ' + info.bits + ' bits, below the 2048-bit minimum used by public CAs.' });
    }
    if (info.type === 'RSA' && info.rsa && info.rsa.exponent !== '65537') {
      notes.push({ tone: 'note', text: 'The public exponent is ' + info.rsa.exponent + ' rather than the usual 65537.' });
    }
    if (info.type === 'EC' && info.ec && !CURVES[info.ec.curveOid]) {
      notes.push({ tone: 'note', text: 'The curve is not in this tool\u2019s named-curve table.' });
    }
    return notes;
  }

  /* -------------------------------------------------------------- detection */

  var PRIVATE_LABEL = /PRIVATE KEY|KEY PAIR/i;
  var PEM_BLOCK = /-----BEGIN ([A-Za-z0-9 ._-]{0,64})-----([\s\S]*?)-----END \1-----/g;

  var PRIVATE_KEY_MESSAGE = 'This looks like private key material. It was not decoded, parsed, or displayed. Remove the private key and supply only the certificate or the public key.';

  function looksLikePrivateKeyDer(bytes) {
    try {
      var node = readNode(bytes, 0, bytes.length, 0);
      if (!isUniversal(node, TAG.SEQUENCE)) return false;
      var parts = children(node);
      if (parts.length >= 9 && parts.every(function (part) { return isUniversal(part, TAG.INTEGER); })) return true;
      if (parts.length >= 3 && isUniversal(parts[0], TAG.INTEGER) && isUniversal(parts[1], TAG.SEQUENCE) && isUniversal(parts[2], TAG.OCTET_STRING)) return true;
      if (parts.length >= 2 && isUniversal(parts[0], TAG.INTEGER) && isUniversal(parts[1], TAG.OCTET_STRING)) return true;
      if (parts.length === 2 && isUniversal(parts[0], TAG.SEQUENCE) && isUniversal(parts[1], TAG.OCTET_STRING)) {
        var algorithm = children(parts[0])[0];
        if (algorithm && isUniversal(algorithm, TAG.OID) && parseOid(algorithm).indexOf('1.2.840.113549.1.5.') === 0) return true;
      }
    } catch (error) {
      return false;
    }
    return false;
  }

  function classifyLabel(label) {
    var upper = label.toUpperCase();
    if (PRIVATE_LABEL.test(upper) || upper.indexOf('OPENSSH') === 0) return 'private-key';
    if (upper === 'CERTIFICATE' || upper === 'X509 CERTIFICATE' || upper === 'TRUSTED CERTIFICATE') return 'certificate';
    if (upper === 'PUBLIC KEY' || upper === 'RSA PUBLIC KEY') return 'public-key';
    if (upper.indexOf('CERTIFICATE REQUEST') >= 0) return 'csr';
    if (upper.indexOf('PGP') >= 0) return 'pgp';
    if (upper === 'X509 CRL') return 'crl';
    return 'unknown';
  }

  function bytesLookTextual(bytes) {
    var limit = Math.min(bytes.length, 4096), printable = 0;
    for (var i = 0; i < limit; i++) {
      var b = bytes[i];
      if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
      else if (b === 0) return false;
    }
    return limit > 0 && printable / limit > 0.9;
  }

  /* ------------------------------------------------------------------- API */

  function inspect(input, options) {
    var settings = options || {};
    var report = {
      source: { name: sanitizeText(settings.name || 'pasted text'), format: 'unrecognized', byteLength: 0, blockCount: 0 },
      documents: [],
      problems: [],
      containsPrivateKey: false,
      ok: false,
      limitations: LIMITATIONS
    };

    var bytes, text;
    try {
      if (typeof input === 'string') {
        text = input;
        bytes = null;
      } else {
        bytes = toBytes(input);
        if (bytes.length > LIMITS.maxInputBytes) fail('The input is larger than the ' + Math.round(LIMITS.maxInputBytes / 1048576) + ' MiB safety limit.');
        report.source.byteLength = bytes.length;
        text = bytesLookTextual(bytes) ? decodeUtf8(bytes) : null;
      }
    } catch (error) {
      report.problems.push({ kind: 'input', label: report.source.name, message: error.message });
      return report;
    }

    if (typeof text === 'string' && text.length > LIMITS.maxInputBytes) {
      report.problems.push({ kind: 'input', label: report.source.name, message: 'The pasted text is larger than the safety limit.' });
      return report;
    }
    if (typeof text === 'string' && bytes === null) report.source.byteLength = text.length;

    var handled = false;
    if (typeof text === 'string' && text.indexOf('-----BEGIN ') >= 0) {
      handled = true;
      report.source.format = 'PEM';
      readPemBlocks(text, report, settings);
    }

    // Base64 is checked before DER so that a dropped file holding unarmoured
    // Base64 is read the same way pasted Base64 is. Real DER is binary, so it
    // never decodes to text and never reaches this branch.
    if (!handled && typeof text === 'string' && /^[A-Za-z0-9+/=\s]+$/.test(text.trim()) && text.trim().length > 32) {
      report.source.format = 'Base64 (no PEM header)';
      report.source.blockCount = 1;
      try {
        addBinaryDocument(base64ToBytes(text), report, settings, 'Base64 input');
      } catch (error) {
        report.problems.push({ kind: 'parse-error', label: 'Base64 input', message: error.message });
      }
      handled = true;
    }

    if (!handled && bytes && bytes.length) {
      report.source.format = 'DER';
      report.source.blockCount = 1;
      addBinaryDocument(bytes, report, settings, 'DER input');
      handled = true;
    }

    if (!handled) {
      report.problems.push({
        kind: 'unrecognized',
        label: report.source.name,
        message: 'No PEM block, DER certificate, or Base64 body was found. Supply a .pem, .crt, .cer, or .der certificate, or a PEM public key.'
      });
    }

    report.ok = report.documents.length > 0;
    return report;
  }

  function readPemBlocks(text, report, settings) {
    PEM_BLOCK.lastIndex = 0;
    var match, count = 0;
    while ((match = PEM_BLOCK.exec(text)) !== null) {
      if (++count > LIMITS.maxBlocks) {
        report.problems.push({ kind: 'limit', label: 'input', message: 'Only the first ' + LIMITS.maxBlocks + ' PEM blocks were read.' });
        break;
      }
      var label = sanitizeText(match[1] || '(unlabelled)');
      var kind = classifyLabel(match[1] || '');
      if (kind === 'private-key') {
        report.containsPrivateKey = true;
        report.problems.push({ kind: 'private-key', label: label, message: PRIVATE_KEY_MESSAGE });
        continue;
      }
      if (kind === 'pgp') {
        report.problems.push({ kind: 'unsupported', label: label, message: 'OpenPGP data is not an X.509 certificate and is not parsed here.' });
        continue;
      }
      if (kind === 'csr') {
        report.problems.push({ kind: 'unsupported', label: label, message: 'Certificate signing requests are not parsed. Supply the issued certificate instead.' });
        continue;
      }
      if (kind === 'crl') {
        report.problems.push({ kind: 'unsupported', label: label, message: 'Certificate revocation lists are not parsed.' });
        continue;
      }
      var body = String(match[2]).split(/\r?\n/).filter(function (line) {
        return line.trim() !== '' && line.indexOf(':') === -1;
      }).join('');
      if (/Proc-Type:\s*4,ENCRYPTED/i.test(match[2])) {
        report.containsPrivateKey = true;
        report.problems.push({ kind: 'private-key', label: label, message: PRIVATE_KEY_MESSAGE });
        continue;
      }
      var decoded;
      try {
        decoded = base64ToBytes(body);
        if (decoded.length > LIMITS.maxDerBytes) fail('The decoded block is larger than the ' + LIMITS.maxDerBytes + '-byte safety limit.');
      } catch (error) {
        report.problems.push({ kind: 'parse-error', label: label, message: error.message });
        continue;
      }
      addBinaryDocument(decoded, report, settings, label, kind);
    }
    report.source.blockCount = count;
    if (!count) {
      report.problems.push({ kind: 'unrecognized', label: report.source.name, message: 'A BEGIN line was found but no complete, matching PEM block could be read.' });
    }
  }

  function addBinaryDocument(bytes, report, settings, label, kindHint) {
    if (!bytes || !bytes.length) {
      report.problems.push({ kind: 'parse-error', label: label, message: 'The block decoded to zero bytes.' });
      return;
    }
    if (bytes.length > LIMITS.maxDerBytes) {
      report.problems.push({ kind: 'limit', label: label, message: 'The block is larger than the ' + LIMITS.maxDerBytes + '-byte safety limit.' });
      return;
    }
    if (looksLikePrivateKeyDer(bytes)) {
      report.containsPrivateKey = true;
      report.problems.push({ kind: 'private-key', label: label, message: PRIVATE_KEY_MESSAGE });
      return;
    }
    var certificateError = null;
    if (kindHint !== 'public-key') {
      try {
        var certificate = parseCertificate(bytes, settings);
        certificate.sourceLabel = label;
        certificate.index = report.documents.length + 1;
        report.documents.push(certificate);
        return;
      } catch (error) {
        certificateError = error;
      }
    }
    try {
      var key = parsePublicKeyDocument(bytes);
      key.sourceLabel = label;
      key.index = report.documents.length + 1;
      report.documents.push(key);
      return;
    } catch (keyError) {
      report.problems.push({
        kind: 'parse-error',
        label: label,
        message: certificateError
          ? 'Not a readable X.509 certificate (' + certificateError.message + ') and not a readable public key as SubjectPublicKeyInfo or PKCS#1 RSAPublicKey (' + keyError.message + ').'
          : keyError.message
      });
    }
  }

  var LIMITATIONS = [
    'Structure only. The signature on the certificate is never verified, so a self-made certificate parses exactly like an issued one.',
    'No chain building or trust evaluation. Issuer names are read as text; no root or intermediate store is consulted.',
    'No revocation checking. CRL and OCSP locations are displayed as data; nothing is fetched or queried.',
    'No hostname matching. Subject alternative names are listed, not compared against any host you intend to reach.',
    'The visual digest is a comparison aid derived from the SHA-256 fingerprint. It is not a security control.',
    'Validity status is computed against this device\u2019s clock, which may be wrong.',
    'Everything runs in this page. No file bytes, fingerprints, or field values leave the browser.'
  ];

  return {
    inspect: inspect,
    parseCertificate: parseCertificate,
    parsePublicKeyDocument: parsePublicKeyDocument,
    sanitizeText: sanitizeText,
    sha256: sha256,
    sha1: sha1,
    visualDigest: visualDigest,
    base64ToBytes: base64ToBytes,
    bytesToHex: bytesToHex,
    LIMITS: LIMITS,
    LIMITATIONS: LIMITATIONS,
    CertError: CertError
  };
});
