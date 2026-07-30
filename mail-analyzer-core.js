(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.MailAnalyzer = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var DEFAULTS = {
    maxInputCharacters: 20 * 1024 * 1024,
    maxPhysicalLines: 100000,
    maxHeaders: 2000,
    maxHops: 500,
    maxMimeParts: 1000,
    maxMimeDepth: 30
  };
  var SINGLETON = ['date', 'from', 'sender', 'reply-to', 'to', 'cc', 'bcc', 'message-id', 'in-reply-to', 'references', 'subject', 'mime-version', 'content-type', 'content-transfer-encoding'];
  var MIN_DKIM_B_PREFIX_LENGTH = 8;
  var STATIC_TWO_LABEL_PUBLIC_SUFFIXES = ['co.uk','org.uk','ac.uk','com.au','net.au','org.au','co.nz','co.jp','com.br','com.mx','co.in'];

  function evidenceText(line, context, title) {
    var parts = [];
    if (line) parts.push('line=' + line);
    Object.keys(context || {}).forEach(function (key) {
      var value = context[key];
      if (value === '' || value === null || value === undefined) return;
      if (typeof value === 'object') {
        try { value = JSON.stringify(value); } catch (e) { value = String(value); }
      }
      parts.push(key + '=' + value);
    });
    return parts.length ? parts.join(' · ') : 'message=' + title;
  }

  function finding(severity, code, title, detail, line, context) {
    var evidenceContext = context || {};
    return { severity: severity, code: code, title: title, detail: detail, evidence: evidenceText(line || null, evidenceContext, title), line: line || null, context: evidenceContext };
  }

  function bytesFromBase64(value) {
    var clean = String(value).replace(/\s/g, '');
    if (typeof Buffer !== 'undefined') return Array.prototype.slice.call(Buffer.from(clean, 'base64'));
    var bin = atob(clean), out = [];
    for (var i = 0; i < bin.length; i++) out.push(bin.charCodeAt(i));
    return out;
  }

  function decodeBytes(bytes, charset) {
    var label = String(charset || 'utf-8').toLowerCase();
    try { return new TextDecoder(label, { fatal: false }).decode(new Uint8Array(bytes)); }
    catch (e) {
      try { return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes)); }
      catch (e2) { return bytes.map(function (b) { return String.fromCharCode(b); }).join(''); }
    }
  }

  function decodeHeaderValue(value) {
    var input = String(value == null ? '' : value);
    var re = /=\?([^?\s]+)\?([bqBQ])\?([^?]*)\?=/g;
    var out = '', last = 0, match, previousWasEncoded = false;
    while ((match = re.exec(input))) {
      var gap = input.slice(last, match.index);
      if (!(previousWasEncoded && /^\s*$/.test(gap))) out += gap;
      try {
        var bytes;
        if (match[2].toUpperCase() === 'B') bytes = bytesFromBase64(match[3]);
        else {
          var q = match[3].replace(/_/g, ' '), arr = [];
          for (var i = 0; i < q.length; i++) {
            if (q.charAt(i) === '=' && /^[0-9a-f]{2}$/i.test(q.slice(i + 1, i + 3))) {
              arr.push(parseInt(q.slice(i + 1, i + 3), 16)); i += 2;
            } else arr.push(q.charCodeAt(i) & 255);
          }
          bytes = arr;
        }
        out += decodeBytes(bytes, match[1]);
      } catch (e) { out += match[0]; }
      previousWasEncoded = true;
      last = re.lastIndex;
    }
    return out + input.slice(last);
  }

  function splitMessage(raw, allowEmptyHeaderSection) {
    var normalized = String(raw == null ? '' : raw).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    if (allowEmptyHeaderSection && normalized.charAt(0) === '\n') return { headerText: '', body: normalized.slice(1), hasSeparator: true };
    var at = normalized.indexOf('\n\n');
    if (at < 0) return { headerText: normalized, body: '', hasSeparator: false };
    return { headerText: normalized.slice(0, at), body: normalized.slice(at + 2), hasSeparator: true };
  }

  function utf8Length(value) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(String(value)).length;
    if (typeof Buffer !== 'undefined') return Buffer.byteLength(String(value), 'utf8');
    return unescape(encodeURIComponent(String(value))).length;
  }

  function countLineEndings(value) {
    var counts = { crlf: 0, bareLf: 0, bareCr: 0 };
    for (var i = 0; i < value.length; i++) {
      if (value.charAt(i) === '\r') {
        if (value.charAt(i + 1) === '\n') { counts.crlf++; i++; }
        else counts.bareCr++;
      } else if (value.charAt(i) === '\n') counts.bareLf++;
    }
    return counts;
  }

  function parseHeaders(text, findings, lineOffset, options, state) {
    var lines = String(text || '').split('\n'), headers = [], current = null;
    var offset = lineOffset || 0, limit = options ? options.maxHeaders : DEFAULTS.maxHeaders;
    for (var index = 0; index < lines.length; index++) {
      var line = lines[index], lineNo = offset + index + 1;
      if (/^[ \t]/.test(line) && current) {
        if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(line)) findings.push(finding('error', 'header-control-character', 'Control character in header section', 'Header fields cannot contain NUL or other raw control characters apart from horizontal tab used for folding.', lineNo));
        current.value += ' ' + line.trim();
        continue;
      }
      if (headers.length >= limit) {
        findings.push(finding('error', 'header-limit', 'Header parsing limit reached', 'Parsing stopped at the configured header-field limit to protect this browser tab.', lineNo, { limit: limit }));
        if (state) state.truncated = true;
        break;
      }
      if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(line)) findings.push(finding('error', 'header-control-character', 'Control character in header section', 'Header fields cannot contain NUL or other raw control characters apart from horizontal tab used for folding.', lineNo));
      if (/^[ \t]/.test(line)) {
        findings.push(finding('error', 'header-orphan-continuation', 'Orphaned folded header line', 'A continuation line appears before any header field.', lineNo));
        current = null;
        continue;
      }
      var colon = line.indexOf(':');
      if (colon <= 0) {
        if (line) findings.push(finding('error', 'header-missing-colon', 'Malformed header line', 'Header fields require a field name followed by a colon.', lineNo));
        current = null;
        continue;
      }
      var name = line.slice(0, colon);
      if (!/^[!-9;-~]+$/.test(name)) findings.push(finding('error', 'invalid-header-name', 'Invalid header field name', 'The field name contains whitespace or a non-printable character.', lineNo, { header: name }));
      current = { name: name, lower: name.toLowerCase(), value: line.slice(colon + 1).trim(), line: lineNo };
      headers.push(current);
    }
    return headers;
  }

  function headerMap(headers) {
    var map = {};
    headers.forEach(function (h) { (map[h.lower] || (map[h.lower] = [])).push(h.value); });
    return map;
  }

  function parseParams(value) {
    var s = String(value || ''), pieces = [], cur = '', quoted = false, escaped = false;
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      if (escaped) { cur += ch; escaped = false; continue; }
      if (ch === '\\' && quoted) { cur += ch; escaped = true; continue; }
      if (ch === '"') { cur += ch; quoted = !quoted; continue; }
      if (ch === ';' && !quoted) { pieces.push(cur); cur = ''; } else cur += ch;
    }
    pieces.push(cur);
    var type = (pieces.shift() || '').trim().toLowerCase(), params = {};
    pieces.forEach(function (piece) {
      var eq = piece.indexOf('='); if (eq < 1) return;
      var key = piece.slice(0, eq).trim().toLowerCase(), val = piece.slice(eq + 1).trim();
      if (val.charAt(0) === '"' && val.charAt(val.length - 1) === '"') val = val.slice(1, -1).replace(/\\([\\"])/g, '$1');
      params[key] = val;
    });
    return { type: type || 'text/plain', params: params, unterminatedQuote: quoted };
  }

  function validateTransfer(body, encoding, findings, partPath, line) {
    var enc = String(encoding || '7bit').trim().toLowerCase();
    if (enc === 'base64') {
      var source = String(body), clean = source.replace(/[ \t\r\n]/g, ''), invalid = false;
      if (/[^A-Za-z0-9+/= \t\r\n]/.test(source) || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0 || /=/.test(clean.slice(0, -2))) invalid = true;
      if (!invalid && clean) {
        var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        if (/==$/.test(clean) && (alphabet.indexOf(clean.charAt(clean.length - 3)) & 15) !== 0) invalid = true;
        else if (/[^=]=$/.test(clean) && (alphabet.indexOf(clean.charAt(clean.length - 2)) & 3) !== 0) invalid = true;
      }
      if (invalid) findings.push(finding('error', 'invalid-base64', 'Invalid Base64 body', 'This MIME part contains invalid transport whitespace, alphabet characters, padding, length, or non-zero padding bits.', line, { part: partPath }));
    } else if (enc === 'quoted-printable') {
      var lines = String(body).split('\n'), bad = false, trailing = false;
      lines.forEach(function (ln, index) {
        if (/[ \t]$/.test(ln)) trailing = true;
        for (var i = 0; i < ln.length; i++) {
          if (ln.charAt(i) !== '=') continue;
          if (i === ln.length - 1) {
            if (index === lines.length - 1 || (index === lines.length - 2 && lines[lines.length - 1] === '')) bad = true;
          }
          else if (!/^[0-9a-f]{2}$/i.test(ln.slice(i + 1, i + 3))) bad = true;
        }
      });
      if (bad) findings.push(finding('warning', 'invalid-quoted-printable', 'Suspicious quoted-printable escape', 'An equals sign is not followed by two hexadecimal digits, or a soft break appears without a following physical line.', line, { part: partPath }));
      if (trailing) findings.push(finding('warning', 'quoted-printable-trailing-whitespace', 'Quoted-printable line has trailing literal whitespace', 'Spaces and tabs at the end of an encoded line must be encoded because transport can remove them.', line, { part: partPath }));
    } else if (!/^(7bit|8bit|binary)$/.test(enc)) {
      findings.push(finding('warning', 'unknown-transfer-encoding', 'Unknown transfer encoding', 'The declared Content-Transfer-Encoding is not one of the standard MIME encodings.', line, { part: partPath, encoding: enc }));
    }
  }

  function parseEntity(headerText, body, findings, state, depth, path, lineOffset, suppliedHeaders) {
    if (depth > state.options.maxMimeDepth) {
      if (!state.depthLimited) findings.push(finding('error', 'mime-depth-limit', 'MIME nesting limit reached', 'Deeper parts were not parsed to protect this browser tab.', null, { part: path, limit: state.options.maxMimeDepth }));
      state.depthLimited = true; state.truncated = true;
      return null;
    }
    if (state.totalParts >= state.options.maxMimeParts) {
      if (!state.partsLimited) findings.push(finding('error', 'mime-part-limit', 'MIME part limit reached', 'Additional parts were not parsed to protect this browser tab.', null, { part: path, limit: state.options.maxMimeParts }));
      state.partsLimited = true; state.truncated = true;
      return null;
    }
    state.totalParts++;
    state.maxDepth = Math.max(state.maxDepth, depth);
    var headers = suppliedHeaders || parseHeaders(headerText, findings, lineOffset, state.options, state), map = headerMap(headers);
    var ct = parseParams((map['content-type'] || ['text/plain'])[0]);
    var disposition = parseParams((map['content-disposition'] || [''])[0]);
    var node = { path: path, contentType: ct.type, charset: ct.params.charset || '', transferEncoding: (map['content-transfer-encoding'] || ['7bit'])[0].toLowerCase(), size: body.length, disposition: disposition.type === 'text/plain' && !map['content-disposition'] ? '' : disposition.type, contentTypeName: ct.params.name || '', dispositionFilename: disposition.params.filename || '', filename: disposition.params.filename || ct.params.name || '', children: [] };
    node.isAttachment = node.disposition === 'attachment' || !!node.filename;
    if (node.contentTypeName && node.dispositionFilename && node.contentTypeName !== node.dispositionFilename) findings.push(finding('warning', 'mime-filename-disagreement', 'MIME attachment filenames disagree', 'Part ' + path + ' has Content-Type name=' + node.contentTypeName + ' but Content-Disposition filename=' + node.dispositionFilename + '. Readers may display different names.', headers.length ? headers[0].line : null, { part: path, contentTypeName: node.contentTypeName, dispositionFilename: node.dispositionFilename, fields: ['Content-Type', 'Content-Disposition'] }));
    if (ct.unterminatedQuote) findings.push(finding('error', 'mime-parameter-quote-unclosed', 'Unclosed MIME parameter quote', 'A Content-Type parameter starts a quoted string but does not close it.', headers.length ? headers[0].line : null, { part: path }));

    if (ct.type.indexOf('multipart/') === 0) {
      var boundary = ct.params.boundary;
      if (/^(base64|quoted-printable)$/i.test(node.transferEncoding)) findings.push(finding('error', 'multipart-transfer-encoding', 'Multipart container has an invalid transfer encoding', 'Multipart containers must remain directly parseable and cannot be wrapped in Base64 or quoted-printable.', null, { part: path, encoding: node.transferEncoding }));
      if (!boundary) {
        findings.push(finding('error', 'mime-boundary-missing', 'Multipart boundary is missing', 'A multipart Content-Type requires a boundary parameter.', null, { part: path }));
        return node;
      }
      if (boundary.length > 70) findings.push(finding('warning', 'mime-boundary-long', 'MIME boundary is unusually long', 'RFC 2046 limits boundary values to 70 characters.', null, { part: path, length: boundary.length }));
      if (state.boundaries.indexOf(boundary) >= 0) findings.push(finding('error', 'mime-boundary-reused', 'Nested MIME boundary is reused', 'A nested multipart uses the same boundary as an ancestor, making the part tree ambiguous to streaming parsers.', null, { part: path, boundary: boundary }));
      var lines = String(body).split('\n'), open = '--' + boundary, close = open + '--', segments = [], active = null, sawOpen = false, sawClose = false, epilogueDelimiter = false;
      for (var li = 0; li < lines.length; li++) {
        var ln = lines[li], marker = ln.replace(/[ \t]+$/, '');
        if (sawClose) {
          if (marker === open || marker === close) epilogueDelimiter = true;
          continue;
        }
        if (marker === open) {
          if (active !== null) {
            if (active.length) segments.push(active.join('\n') + '\n');
            else findings.push(finding('warning', 'mime-empty-part', 'Empty MIME part delimiter', 'Two boundary delimiters appear with no part headers or body between them.', null, { part: path }));
          }
          active = []; sawOpen = true;
        } else if (marker === close) {
          if (active !== null) {
            if (active.length) segments.push(active.join('\n') + '\n');
            else findings.push(finding('warning', 'mime-empty-part', 'Empty MIME part delimiter', 'An opening boundary is immediately followed by the closing boundary.', null, { part: path }));
          }
          active = null; sawClose = true;
        } else if (active !== null) active.push(ln);
      }
      if (active !== null) {
        if (active.length) segments.push(active.join('\n'));
        else findings.push(finding('warning', 'mime-empty-part', 'Empty MIME part delimiter', 'The final opening boundary has no part content.', null, { part: path }));
      }
      if (epilogueDelimiter) findings.push(finding('warning', 'mime-delimiter-in-epilogue', 'Boundary delimiter appears in MIME epilogue', 'Delimiter-looking lines after the first closing boundary are ignored and may indicate malformed message construction.', null, { part: path }));
      if (!sawOpen) findings.push(finding('error', 'mime-boundary-not-found', 'MIME boundary not found', 'The declared boundary never appears in the body.', null, { part: path, boundary: boundary }));
      else if (!sawClose) findings.push(finding('error', 'mime-boundary-unclosed', 'MIME boundary is not closed', 'The final closing delimiter with two trailing hyphens is missing.', null, { part: path, boundary: boundary }));
      state.boundaries.push(boundary);
      for (var si = 0; si < segments.length; si++) {
        if (state.totalParts >= state.options.maxMimeParts) {
          if (!state.partsLimited) findings.push(finding('error', 'mime-part-limit', 'MIME part limit reached', 'Additional parts were not parsed to protect this browser tab.', null, { part: path, limit: state.options.maxMimeParts }));
          state.partsLimited = true; state.truncated = true;
          break;
        }
        var split = splitMessage(segments[si], true);
        if (!split.hasSeparator) findings.push(finding('error', 'mime-part-header-separator-missing', 'MIME part has no header/body separator', 'Each MIME body part must separate its part headers from content with a blank line.', null, { part: path + '.' + (si + 1) }));
        var child = parseEntity(split.headerText, split.body, findings, state, depth + 1, path + '.' + (si + 1), 0);
        if (child) node.children.push(child);
        if (state.depthLimited) break;
      }
      state.boundaries.pop();
      if (ct.type === 'multipart/alternative') {
        var seenTypes = {}, duplicates = [];
        node.children.forEach(function (childNode) {
          if (seenTypes[childNode.contentType] && duplicates.indexOf(childNode.contentType) < 0) duplicates.push(childNode.contentType);
          seenTypes[childNode.contentType] = true;
        });
        if (duplicates.length) findings.push(finding('warning', 'alternative-duplicate-type', 'Multipart alternative repeats a media type', 'Alternative parts normally represent distinct versions of the same content. Repeated media types can look suspicious to gateways.', null, { part: path, types: duplicates }));
      }
    } else {
      state.leafParts++;
      validateTransfer(body, node.transferEncoding, findings, path, null);
    }
    return node;
  }

  function mimeHasAttachment(node) {
    if (!node) return false;
    if (node.isAttachment) return true;
    return (node.children || []).some(mimeHasAttachment);
  }

  function token(value, name) {
    var re = new RegExp('(?:^|\\s)' + name + '\\s+([^\\s;(]+)', 'i'), m = re.exec(value);
    return m ? m[1] : '';
  }

  function stripComments(value) {
    var out = '', depth = 0, quoted = false, escaped = false;
    value = String(value || '');
    for (var i = 0; i < value.length; i++) {
      var ch = value.charAt(i);
      if (escaped) { if (!depth) out += ch; escaped = false; continue; }
      if (ch === '\\') { if (!depth) out += ch; escaped = true; continue; }
      if (ch === '"' && !depth) { quoted = !quoted; out += ch; continue; }
      if (!quoted && ch === '(') { depth++; continue; }
      if (!quoted && ch === ')' && depth) { depth--; continue; }
      if (!depth) out += ch;
    }
    return out.replace(/[ \t]+/g, ' ').trim();
  }

  function parseRfcDate(value) {
    var text = stripComments(value);
    var re = /^(?:(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s*,\s*)?(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{2,4})\s+(\d{2}):(\d{2})(?::(\d{2}))?\s+([+-]\d{4}|UT|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT)$/i;
    var m = re.exec(text); if (!m) return null;
    var months = { jan:0,feb:1,mar:2,apr:3,may:4,jun:5,jul:6,aug:7,sep:8,oct:9,nov:10,dec:11 };
    var day = +m[2], month = months[m[3].toLowerCase()], year = +m[4], hour = +m[5], minute = +m[6], second = m[7] == null ? 0 : +m[7];
    if (m[4].length === 2) year += year < 50 ? 2000 : 1900;
    if (year < 1900 || day < 1 || hour > 23 || minute > 59 || second > 60) return null;
    var leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    var days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (day > days[month]) return null;
    if (m[1]) {
      var weekdays = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
      if (weekdays[new Date(Date.UTC(year, month, day)).getUTCDay()].toLowerCase() !== m[1].toLowerCase()) return null;
    }
    var zone = m[8].toUpperCase(), offset;
    if (/^[+-]/.test(zone)) {
      var zh = +zone.slice(1, 3), zm = +zone.slice(3, 5);
      if (zh > 23 || zm > 59) return null;
      offset = (zh * 60 + zm) * (zone.charAt(0) === '+' ? 1 : -1);
    } else {
      var named = { UT:0,GMT:0,EST:-300,EDT:-240,CST:-360,CDT:-300,MST:-420,MDT:-360,PST:-480,PDT:-420 };
      offset = named[zone];
    }
    var leapExtra = second === 60 ? 1000 : 0;
    var timestamp = Date.UTC(year, month, day, hour, minute, Math.min(second, 59)) - offset * 60000 + leapExtra;
    return { timestamp: timestamp, text: text };
  }

  function traceDate(value) {
    var cleaned = stripComments(value), separator = cleaned.lastIndexOf(';');
    return separator >= 0 ? cleaned.slice(separator + 1).trim() : '';
  }

  function normalizeTraceHost(value) {
    return String(value || '').trim().replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  }

  function usableTraceEndpoint(value) {
    var normalized = normalizeTraceHost(value);
    return /^(?:unknown|none|unspecified|not[- ]stated|\(not stated\))$/.test(normalized) ? '' : normalized;
  }

  function traceEndpointsMatch(newer, older) {
    var receiver = usableTraceEndpoint(older && older.by), candidates = [newer && newer.from, newer && newer.claimedHostname, newer && newer.rdns, newer && newer.observedAddress, newer && newer.assertedAddress].map(usableTraceEndpoint).filter(Boolean);
    return !!(receiver && candidates.indexOf(receiver) >= 0);
  }

  function isLoopbackHost(value) {
    var host = normalizeTraceHost(value);
    if (host === 'localhost' || host === '::1') return true;
    var m = /^(\d{1,3})(?:\.\d{1,3}){3}$/.exec(host);
    return !!(m && Number(m[1]) === 127);
  }

  function isIpv4(value) {
    var parts = String(value || '').split('.');
    return parts.length === 4 && parts.every(function (part) { return /^\d{1,3}$/.test(part) && Number(part) <= 255; });
  }

  function extractTraceAddresses(value) {
    var found = [], text = String(value || ''), match;
    var v4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    while ((match = v4.exec(text))) if (isIpv4(match[0]) && found.indexOf(match[0]) < 0) found.push(match[0]);
    var v6 = /\b(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}\b/ig;
    while ((match = v6.exec(text))) {
      var candidate = match[0].replace(/[;,]$/, '');
      if (candidate.indexOf(':') >= 0 && found.indexOf(candidate) < 0) found.push(candidate);
    }
    return found;
  }

  function classifySpecialAddress(value) {
    var ip = normalizeTraceHost(value);
    if (ip === '::1') return 'loopback';
    if (/^fe[89ab][0-9a-f]:/i.test(ip)) return 'link-local';
    if (/^2001:db8:/i.test(ip)) return 'RFC 3849 documentation';
    if (!isIpv4(ip)) return '';
    var p = ip.split('.').map(Number);
    if (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168)) return 'RFC 1918';
    if (p[0] === 127) return 'loopback';
    if (p[0] === 169 && p[1] === 254) return 'link-local';
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return 'CGNAT';
    if ((p[0] === 192 && p[1] === 0 && p[2] === 2) || (p[0] === 198 && p[1] === 51 && p[2] === 100) || (p[0] === 203 && p[1] === 0 && p[2] === 113)) return 'RFC 5737 documentation';
    if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return 'RFC 2544 benchmarking';
    return '';
  }

  function traceFromDetails(value, fromToken) {
    var text = String(value || ''), lower = text.toLowerCase(), start = lower.indexOf('from '), end = lower.indexOf(' by ', start + 5);
    var clause = start >= 0 ? text.slice(start + 5, end >= 0 ? end : text.length) : '';
    var asserted = /^\[([^\]]+)\]/.exec(String(fromToken || ''));
    var addresses = extractTraceAddresses(clause), assertedAddress = asserted ? asserted[1] : '';
    var observedAddress = '';
    addresses.forEach(function (address) { if (!observedAddress && normalizeTraceHost(address) !== normalizeTraceHost(assertedAddress)) observedAddress = address; });
    if (!observedAddress && !assertedAddress && addresses.length) observedAddress = addresses[0];
    var comment = /\(([^()]*?)\[([^\]]+)\][^()]*\)/.exec(clause), rdns = '';
    if (comment) rdns = comment[1].replace(/\[[^\]]+\]/g, '').trim().replace(/\.$/, '');
    if (!rdns && /\(unknown\b/i.test(clause)) rdns = 'unknown';
    var heloMatch = /(?:\bhelo\s*=\s*|\bHELO\s+)([^\s)]+)/i.exec(clause);
    var claimedHostname = assertedAddress || isIpv4(normalizeTraceHost(fromToken)) || normalizeTraceHost(fromToken).indexOf(':') >= 0 ? '' : String(fromToken || '').replace(/\.$/, '');
    return { claimedHostname: claimedHostname, assertedAddress: assertedAddress, observedAddress: observedAddress, rdns: rdns, helo: heloMatch ? heloMatch[1] : '' };
  }

  function parseHopTls(value, hop) {
    var text = String(value || ''), version = '', cipher = '', bits = '', verify = '';
    var match = /\bversion=(TLS[^\s)]+)/i.exec(text) || /\busing\s+(TLS[^\s)]+)/i.exec(text);
    if (match) version = match[1];
    match = /\bcipher(?:=|\s+)([A-Za-z0-9_-]+)/i.exec(text); if (match) cipher = match[1];
    match = /\bbits=([0-9/]+)/i.exec(text) || /\(([0-9/]+)\s+bits\)/i.exec(text); if (match) bits = match[1];
    match = /\bverify=([A-Za-z]+)/i.exec(text); if (match) verify = match[1].toUpperCase();
    if (/Google Transport Security/i.test(text)) return { status: 'tls', version: version, cipher: cipher, bits: bits, verify: verify || 'not-stated', label: 'Google Transport Security' };
    if (version || cipher || /\b(?:ESMTPSA?|SMTPS)\b/i.test(hop.with || '')) return { status: 'tls', version: version, cipher: cipher, bits: bits, verify: verify || 'not-stated', label: 'TLS' };
    if (isLoopbackHost(hop.from)) return { status: 'local', version: '', cipher: '', bits: '', verify: 'not-applicable', label: 'Local re-injection' };
    if (/^SMTP$/i.test(hop.with || '') && hop.from) return { status: 'plaintext', version: '', cipher: '', bits: '', verify: 'not-applicable', label: 'Plaintext SMTP' };
    return { status: 'not-stated', version: '', cipher: '', bits: '', verify: 'not-stated', label: 'TLS not stated' };
  }

  function parseHops(received, findings, options, state, messageContext) {
    var source = received;
    if (source.length > options.maxHops) {
      findings.push(finding('error', 'received-hop-limit', 'Received hop limit reached', 'Only the newest trace fields were parsed to protect this browser tab.', null, { count: source.length, limit: options.maxHops }));
      source = source.slice(0, options.maxHops); state.truncated = true;
    }
    var hops = source.map(function (value, index) {
      var dateText = traceDate(value), parsed = dateText ? parseRfcDate(dateText) : null, ms = parsed ? parsed.timestamp : null;
      var hop = { index: index + 1, from: token(value, 'from'), by: token(value, 'by'), with: token(value, 'with'), id: token(value, 'id'), for: token(value, 'for'), date: dateText, timestamp: ms, raw: value };
      var fromDetails = traceFromDetails(value, hop.from);
      Object.keys(fromDetails).forEach(function (key) { hop[key] = fromDetails[key]; });
      hop.origin = hop.observedAddress || hop.claimedHostname || hop.assertedAddress || hop.from;
      hop.tls = parseHopTls(value, hop);
      hop.addresses = extractTraceAddresses(value);
      var xOriginating = messageContext && messageContext.xOriginatingIp;
      hop.xOriginatingIpMatch = !!(xOriginating && hop.observedAddress && normalizeTraceHost(xOriginating) === normalizeTraceHost(hop.observedAddress));
      if (!parsed) findings.push(finding('warning', 'received-date-unparseable', 'Received timestamp could not be parsed', 'Hop ' + hop.index + ' has no valid RFC-style date after its final grammar-level semicolon.', null, { hop: hop.index, date: dateText || '(not stated)' }));
      if (!hop.by) findings.push(finding('warning', 'received-by-missing', 'Received hop has no “by” clause', 'Hop ' + hop.index + ' does not identify the receiving server.', null, { hop: hop.index, raw: value }));
      if (hop.tls.verify === 'FAIL') findings.push(finding('warning', 'tls-verification-failed', 'TLS peer verification failed at hop ' + hop.index, 'Hop ' + hop.index + ' reports version ' + (hop.tls.version || '(not stated)') + ', cipher ' + (hop.tls.cipher || '(not stated)') + ', and verify=FAIL.', null, { hop: hop.index, version: hop.tls.version, cipher: hop.tls.cipher, verify: hop.tls.verify }));
      if (hop.tls.status === 'plaintext') findings.push(finding('warning', 'plaintext-smtp', 'Plaintext SMTP reported at hop ' + hop.index, 'Hop ' + hop.index + ' says “with ' + hop.with + '” and contains no TLS version or cipher, so this trace field reports plaintext transport.', null, { hop: hop.index, protocol: hop.with, from: hop.from, by: hop.by }));
      if (hop.claimedHostname && hop.helo && normalizeTraceHost(hop.claimedHostname) !== normalizeTraceHost(hop.helo)) findings.push(finding('warning', 'helo-hostname-mismatch', 'HELO differs from claimed hostname at hop ' + hop.index, 'Hop ' + hop.index + ' claims hostname ' + hop.claimedHostname + ' but announces HELO ' + hop.helo + '.', null, { hop: hop.index, claimedHostname: hop.claimedHostname, helo: hop.helo }));
      if (hop.assertedAddress && hop.observedAddress && normalizeTraceHost(hop.assertedAddress) !== normalizeTraceHost(hop.observedAddress)) {
        var assertedClass = classifySpecialAddress(hop.assertedAddress), xNote = hop.xOriginatingIpMatch ? ' X-Originating-IP ' + xOriginating + ' matches the observed peer.' : (xOriginating ? ' X-Originating-IP ' + xOriginating + ' does not match the observed peer.' : '');
        findings.push(finding('warning', 'received-address-mismatch', 'Client-asserted and observed addresses differ at hop ' + hop.index, 'Hop ' + hop.index + ' has client-asserted literal ' + hop.assertedAddress + ' but the receiving MTA recorded peer ' + hop.observedAddress + '; rDNS is ' + (hop.rdns || '(not stated)') + '. The asserted literal is ' + (assertedClass || 'not in a classified special-use range') + '.' + xNote, null, { hop: hop.index, assertedAddress: hop.assertedAddress, observedAddress: hop.observedAddress, rdns: hop.rdns, assertedClass: assertedClass, xOriginatingIp: xOriginating || '', xOriginatingIpMatch: hop.xOriginatingIpMatch }));
      }
      return hop;
    });
    for (var i = 0; i + 1 < hops.length; i++) {
      if (hops[i].timestamp !== null && hops[i + 1].timestamp !== null && hops[i + 1].timestamp - hops[i].timestamp > 300000) {
        findings.push(finding('warning', 'received-time-inversion', 'Received timestamps run backward', 'Hop ' + (i + 2) + ' claims ' + hops[i + 1].date + ', more than five minutes later than hop ' + (i + 1) + ' at ' + hops[i].date + '. Clock skew or a forged trace field is possible.', null, { newerHop: i + 1, olderHop: i + 2, newerTime: hops[i].date, olderTime: hops[i + 1].date }));
      }
    }
    for (var hi = 0; hi + 1 < hops.length; hi++) {
      var newer = hops[hi], older = hops[hi + 1];
      if (!newer.from || !older.by) continue;
      if (traceEndpointsMatch(newer, older)) continue;
      if (isLoopbackHost(newer.from) && normalizeTraceHost(newer.by) === normalizeTraceHost(older.by)) continue;
      var inversion = findings.filter(function (item) { return item.code === 'received-time-inversion' && item.context.olderHop === older.index; })[0];
      if (inversion) {
        inversion.severity = 'error';
        inversion.context.correlatedChainBreak = true;
        inversion.detail += ' The same hop also breaks trace continuity, which favors a forged prepend over ordinary clock skew.';
      }
      findings.push(finding('error', 'received-chain-discontinuity', 'Received trace does not connect at hop ' + older.index, 'Hop ' + older.index + ' claims receiver ' + older.by + ', but the next trace field (hop ' + newer.index + ') identifies its origin as ' + newer.from + ' and was received by ' + (newer.by || '(receiver not stated)') + '. The isolated receiver does not connect to the adjacent trace.', null, { hop: older.index, olderBy: older.by, newerHop: newer.index, newerFrom: newer.from, newerBy: newer.by, correlatedTimestampInversion: !!inversion }));
    }
    for (var ri = 0; ri + 1 < hops.length; ri++) {
      var newerRecipient = hops[ri].for, olderRecipient = hops[ri + 1].for;
      if (newerRecipient && olderRecipient && newerRecipient.toLowerCase() !== olderRecipient.toLowerCase()) {
        findings.push(finding('info', 'envelope-recipient-change', 'Envelope recipient changes between hops ' + hops[ri + 1].index + ' and ' + hops[ri].index, 'Hop ' + hops[ri + 1].index + ' names ' + olderRecipient + ', while hop ' + hops[ri].index + ' names ' + newerRecipient + '. Alias expansion or forwarding commonly causes this and the trace alone does not imply interception.', null, { hops: [hops[ri + 1].index, hops[ri].index], olderRecipient: olderRecipient, newerRecipient: newerRecipient }));
      }
    }
    var specialEntries = [];
    hops.forEach(function (hopItem) {
      hopItem.addresses.forEach(function (address) {
        var category = classifySpecialAddress(address);
        if (category) specialEntries.push({ hop: hopItem.index, address: address, category: category });
      });
    });
    if (specialEntries.length) {
      var uniqueSpecial = [], seenSpecial = {};
      specialEntries.forEach(function (entry) {
        var key = entry.hop + '|' + entry.address + '|' + entry.category;
        if (!seenSpecial[key]) { seenSpecial[key] = true; uniqueSpecial.push(entry); }
      });
      findings.push(finding('info', 'special-use-addresses', 'Special-use addresses appear in the Received trace', uniqueSpecial.map(function (entry) { return 'hop ' + entry.hop + ': ' + entry.address + ' (' + entry.category + ')'; }).join('; ') + '. These ranges are classified from message bytes only; no ownership, reputation, or geolocation lookup was performed.', null, { hops: uniqueSpecial.map(function (entry) { return entry.hop; }).filter(function (hopNo, pos, all) { return all.indexOf(hopNo) === pos; }), addresses: uniqueSpecial }));
    }
    return hops;
  }

  function calculateHopTiming(hops) {
    var consecutive = [], largest = null, totalSeconds = 0;
    for (var i = 0; i + 1 < hops.length; i++) {
      if (hops[i].timestamp === null || hops[i + 1].timestamp === null) continue;
      var seconds = Math.round((hops[i].timestamp - hops[i + 1].timestamp) / 1000);
      if (seconds < 0) continue;
      var delta = { fromHop: hops[i + 1].index, toHop: hops[i].index, seconds: seconds };
      hops[i].deltaFromOlderSeconds = seconds;
      consecutive.push(delta); totalSeconds += seconds;
      if (!largest || seconds > largest.seconds) largest = delta;
    }
    return { consecutive: consecutive, totalSeconds: totalSeconds, largest: largest };
  }

  function applyTrustBoundary(hops, findings, requestedHop) {
    var trustedHop = Number(requestedHop), designated = Number.isInteger(trustedHop) && trustedHop >= 1 && trustedHop <= hops.length;
    hops.forEach(function (hop) { hop.trust = designated && hop.index <= trustedHop ? 'controlled-side' : designated ? 'untrusted' : 'undesignated'; });
    if (!designated) return { designated: false, trustedHop: null, untrustedFromHop: null };
    findings.forEach(function (item) {
      var cited = [];
      if (item.context && Number.isInteger(Number(item.context.hop))) cited.push(Number(item.context.hop));
      if (item.context && Array.isArray(item.context.hops)) cited = cited.concat(item.context.hops.map(Number));
      if (item.context && Number.isInteger(Number(item.context.olderHop))) cited.push(Number(item.context.olderHop));
      if (!cited.some(function (hopNo) { return hopNo > trustedHop; })) return;
      item.unverifiable = true;
      item.trustNote = 'Evidence at hop ' + cited.filter(function (hopNo) { return hopNo > trustedHop; }).filter(function (hopNo, pos, all) { return all.indexOf(hopNo) === pos; }).join(', ') + ' is below the designated trust boundary and is attacker-controllable, so it is unverifiable by construction.';
    });
    return { designated: true, trustedHop: trustedHop, untrustedFromHop: trustedHop + 1 };
  }

  function splitAuthClauses(value) {
    var parts = [], cur = '', depth = 0, quoted = false, escaped = false;
    value = String(value || '');
    for (var i = 0; i < value.length; i++) {
      var ch = value.charAt(i);
      if (escaped) { cur += ch; escaped = false; continue; }
      if (ch === '\\' && (quoted || depth)) { cur += ch; escaped = true; continue; }
      if (ch === '"' && !depth) { quoted = !quoted; cur += ch; continue; }
      if (!quoted && ch === '(') { depth++; cur += ch; continue; }
      if (!quoted && ch === ')' && depth) { depth--; cur += ch; continue; }
      if (ch === ';' && !quoted && !depth) { parts.push(cur.trim()); cur = ''; }
      else cur += ch;
    }
    parts.push(cur.trim());
    return parts;
  }

  function domainFromMailbox(value) {
    var text = String(value || ''), match, domain = '';
    var re = /@([A-Za-z0-9.-]+)(?=[>\s",;)]|$)/g;
    while ((match = re.exec(text))) domain = match[1];
    if (!domain && /^[A-Za-z0-9.-]+$/.test(text.trim())) domain = text.trim();
    return domain.replace(/\.$/, '').toLowerCase();
  }

  function messageIdentities(map, findings) {
    var identities = {
      returnPath: domainFromMailbox((map['return-path'] || [''])[0]),
      sender: domainFromMailbox((map.sender || [''])[0]),
      from: domainFromMailbox((map.from || [''])[0]),
      replyTo: domainFromMailbox((map['reply-to'] || [''])[0])
    };
    var present = Object.keys(identities).filter(function (key) { return identities[key]; }), unique = [];
    present.forEach(function (key) { if (unique.indexOf(identities[key]) < 0) unique.push(identities[key]); });
    if (unique.length > 1) findings.push(finding('warning', 'identity-domain-spread', 'Message identity fields use different domains', 'Return-Path: ' + (identities.returnPath || '(not stated)') + '; Sender: ' + (identities.sender || '(not stated)') + '; From: ' + (identities.from || '(not stated)') + '; Reply-To: ' + (identities.replyTo || '(not stated)') + '. This is common for mailing lists and delegated senders, but the identities should be reviewed separately.', null, identities));
    return identities;
  }

  function parseTagList(value) {
    var tags = {};
    splitAuthClauses(value).forEach(function (piece) {
      var eq = piece.indexOf('='); if (eq < 1) return;
      var key = piece.slice(0, eq).trim().toLowerCase();
      tags[key] = piece.slice(eq + 1).replace(/\s/g, '');
    });
    return tags;
  }

  function authProperties(clause) {
    var props = {}, clean = stripComments(clause), re = /([a-z][a-z0-9_.-]*)\s*=\s*(?:"([^"]*)"|([^\s;]+))/ig, match;
    while ((match = re.exec(clean))) props[match[1].toLowerCase()] = match[2] == null ? match[3] : match[2];
    return props;
  }

  function relaxedAlignmentState(a, b) {
    var left = String(a || '').toLowerCase().replace(/\.$/, ''), right = String(b || '').toLowerCase().replace(/\.$/, '');
    if (!left || !right) return null;
    if (left === right) return true;
    var aLabels = left.split('.').filter(Boolean), bLabels = right.split('.').filter(Boolean);
    if (aLabels.length < 2 || bLabels.length < 2) return null;
    if (aLabels[aLabels.length - 1] !== bLabels[bLabels.length - 1]) return false;
    var aLastTwo = aLabels.slice(-2).join('.'), bLastTwo = bLabels.slice(-2).join('.');
    if (aLastTwo !== bLastTwo) return false;
    if (STATIC_TWO_LABEL_PUBLIC_SUFFIXES.indexOf(aLastTwo) >= 0) {
      if (aLabels.length < 3 || bLabels.length < 3) return null;
      if (aLabels.slice(-3).join('.') !== bLabels.slice(-3).join('.')) return false;
    }
    return null;
  }

  function parseReceivedSpf(headers) {
    return headers.filter(function (header) { return header.lower === 'received-spf'; }).map(function (header) {
      var resultMatch = /^\s*([a-z][a-z0-9_-]*)/i.exec(header.value), evaluatorMatch = /^\s*[a-z][a-z0-9_-]*\s+\(([^:()]+):/i.exec(header.value);
      var clientMatch = /\bclient-ip=([^;\s]+)/i.exec(header.value), domainMatch = /\bdomain of\s+"?([^\s")]+)/i.exec(header.value);
      var domainValue = domainMatch ? domainMatch[1] : '';
      return { result: resultMatch ? resultMatch[1].toLowerCase() : 'unknown', evaluator: evaluatorMatch ? evaluatorMatch[1].trim() : '(not stated)', domain: domainFromMailbox(domainValue), clientIp: clientMatch ? clientMatch[1].replace(/[;>]$/, '') : '', field: 'Received-SPF', line: header.line, raw: header.value };
    });
  }

  function dkimRecordSignatureCandidates(record, signatures) {
    if (record.headerB) {
      if (record.headerB.length < MIN_DKIM_B_PREFIX_LENGTH) return [];
      return signatures.filter(function (signature) { return !!signature.b && signature.b.indexOf(record.headerB) === 0; });
    }
    if (!record.headerDomain) return [];
    return signatures.filter(function (signature) { return signature.domain === record.headerDomain; });
  }

  function authentication(headers, map, findings, identities) {
    var observed = { dkim: [], spf: [], dmarc: [], arc: [] }, authservIds = [], records = [], sealers = {};
    (map['arc-seal'] || []).forEach(function (value) { var tags = parseTagList(value); if (tags.i) sealers[tags.i] = tags.d || ''; });
    headers.forEach(function (header, fieldOrder) {
      if (header.lower !== 'authentication-results' && header.lower !== 'arc-authentication-results') return;
      var clauses = splitAuthClauses(header.value), arcInstance = null;
      if (header.lower === 'arc-authentication-results') {
        var instance = /^i\s*=\s*(\d+)$/i.exec(clauses.shift() || ''); arcInstance = instance ? Number(instance[1]) : null;
      }
      var evaluator = (clauses.shift() || '(not stated)').replace(/\s+\d+\s*$/, '').trim();
      if (header.lower === 'authentication-results') authservIds.push(evaluator);
      clauses.forEach(function (clause) {
        var clean = stripComments(clause), methodMatch = /^([a-z][a-z0-9_-]*)\s*=\s*([a-z][a-z0-9_-]*)\b/i.exec(clean);
        if (!methodMatch) return;
        var method = methodMatch[1].toLowerCase(), result = methodMatch[2].toLowerCase(), props = authProperties(clause);
        var record = { method: method, result: result, evaluator: evaluator, source: header.lower === 'authentication-results' ? 'Authentication-Results' : 'ARC-Authentication-Results', arcInstance: arcInstance, sealer: arcInstance === null ? '' : (sealers[String(arcInstance)] || ''), fieldOrder: fieldOrder, line: header.line, properties: props };
        record.headerB = (props['header.b'] || '').replace(/\s/g, '');
        record.headerDomain = domainFromMailbox(props['header.i'] || props['header.d'] || '');
        record.mailFromDomain = domainFromMailbox(props['smtp.mailfrom'] || '');
        records.push(record);
        if (header.lower === 'authentication-results' && Object.prototype.hasOwnProperty.call(observed, method)) observed[method].push(result);
      });
    });

    var signatures = (map['dkim-signature'] || []).map(function (value) {
      var tags = parseTagList(value);
      return { domain: tags.d || '', selector: tags.s || '', b: tags.b || '', signedHeaders: tags.h || '', reports: [] };
    });
    records.filter(function (record) { return record.method === 'dkim'; }).forEach(function (record) {
      var candidates = dkimRecordSignatureCandidates(record, signatures), signature = candidates.length === 1 ? candidates[0] : null;
      if (signature) {
        record.signatureDomain = signature.domain;
        signature.reports.push({ result: record.result, evaluator: record.evaluator, source: record.source, arcInstance: record.arcInstance, sealer: record.sealer, headerB: record.headerB });
      }
    });

    var bySignature = {};
    records.filter(function (record) { return record.method === 'dkim' && record.headerB; }).forEach(function (record) { (bySignature[record.headerB] || (bySignature[record.headerB] = [])).push(record); });
    Object.keys(bySignature).forEach(function (headerB) {
      var group = bySignature[headerB], results = [];
      group.forEach(function (record) { if (results.indexOf(record.result) < 0) results.push(record.result); });
      if (results.length < 2) return;
      var reports = group.map(function (record) { return record.arcInstance === null ? record.evaluator + ' reports ' + record.result : 'ARC i=' + record.arcInstance + ' sealed by ' + (record.sealer || '(not stated)') + ' reports ' + record.result; });
      findings.push(finding('info', 'dkim-verdict-conflict', 'The same reported DKIM signature has different verdicts', 'header.b=' + headerB + ': ' + reports.join('; ') + '. The message’s own reports are consistent with signed body/content having changed between these evaluation points, as mailing-list footer insertion commonly does, but they do not establish why any verifier returned fail. Header changes, DNS/key state, verifier behavior, and malformed/truncated claims are also consistent explanations.', null, { field: 'Authentication-Results / ARC-Authentication-Results', headerB: headerB, reports: group.map(function (record) { return { result: record.result, evaluator: record.evaluator, arcInstance: record.arcInstance, sealer: record.sealer }; }) }));
    });

    var receivedSpf = parseReceivedSpf(headers), spfResults = [];
    receivedSpf.forEach(function (entry) { if (spfResults.indexOf(entry.result) < 0) spfResults.push(entry.result); });
    if (spfResults.length > 1) findings.push(finding('warning', 'received-spf-disagreement', 'Received-SPF fields report different results', receivedSpf.map(function (entry) { return entry.evaluator + ' reports ' + entry.result + ' for ' + (entry.domain || '(domain not stated)') + ' with client-ip=' + (entry.clientIp || '(not stated)'); }).join('; ') + '. These are recorded claims from separate evaluation points, not fresh SPF checks.', null, { field: 'Received-SPF', results: receivedSpf }));

    var standardRecords = records.filter(function (record) { return record.source === 'Authentication-Results'; }), fieldOrders = [];
    standardRecords.forEach(function (record) { if (fieldOrders.indexOf(record.fieldOrder) < 0) fieldOrders.push(record.fieldOrder); });
    var dmarcAlignment = [];
    fieldOrders.forEach(function (order) {
      var group = standardRecords.filter(function (record) { return record.fieldOrder === order; }), dmarc = group.filter(function (record) { return record.method === 'dmarc'; })[0];
      if (!dmarc || !identities.from) return;
      var passing = group.filter(function (record) { return (record.method === 'spf' || record.method === 'dkim') && record.result === 'pass'; });
      var spfStates = passing.filter(function (record) { return record.method === 'spf'; }).map(function (record) { return relaxedAlignmentState(identities.from, record.mailFromDomain); });
      var dkimStates = passing.filter(function (record) { return record.method === 'dkim'; }).map(function (record) { return record.signatureDomain ? relaxedAlignmentState(identities.from, record.signatureDomain) : null; });
      var alignedSpf = spfStates.indexOf(true) >= 0, alignedDkim = dkimStates.indexOf(true) >= 0, states = spfStates.concat(dkimStates);
      var spfCovered = group.some(function (record) { return record.method === 'spf'; });
      var unmatchedDkimRecords = group.filter(function (record) { return record.method === 'dkim'; }).slice();
      var dkimCovered = signatures.every(function (signature) {
        var matchIndex = unmatchedDkimRecords.map(function (record) {
          var candidates = dkimRecordSignatureCandidates(record, signatures);
          return candidates.length === 1 && candidates[0] === signature;
        }).indexOf(true);
        if (matchIndex < 0) return false;
        unmatchedDkimRecords.splice(matchIndex, 1);
        return true;
      });
      var coverageComplete = spfCovered && dkimCovered;
      var derived = alignedSpf || alignedDkim ? 'pass' : (!coverageComplete || states.indexOf(null) >= 0 ? 'indeterminate' : 'fail');
      var item = { evaluator: dmarc.evaluator, fromDomain: identities.from, derived: derived, reported: dmarc.result, relaxed: true, strictEvaluated: false, alignedSpf: alignedSpf, alignedDkim: alignedDkim, authenticationCoverageComplete: coverageComplete };
      dmarcAlignment.push(item);
      var noIdentifier = derived === 'fail' ? 'No aligned passing identifier exists' : derived === 'pass' ? 'At least one aligned passing identifier exists' : 'Authentication method coverage or organizational-domain data is insufficient to derive alignment safely';
      if (derived === 'indeterminate') findings.push(finding('info', 'dmarc-alignment-indeterminate', 'DMARC alignment is not locally derivable with certainty', dmarc.evaluator + ' reports dmarc=' + dmarc.result + ' for From domain ' + identities.from + '. ' + noIdentifier + '; strict alignment was not evaluated.', null, item));
      else if (derived === dmarc.result) findings.push(finding('info', 'dmarc-alignment-agreement', 'Derived DMARC alignment agrees with the reported result', dmarc.evaluator + ' reports dmarc=' + dmarc.result + ' for From domain ' + identities.from + '. ' + noIdentifier + ' under relaxed organizational-domain alignment; strict alignment was not evaluated.', null, item));
      else if (dmarc.result === 'pass' && derived === 'fail') findings.push(finding('error', 'dmarc-claim-contradiction', 'Reported DMARC result contradicts the message’s identity claims', dmarc.evaluator + ' reports dmarc=pass for From domain ' + identities.from + ', but the same Authentication-Results field yields derived alignment=fail. ' + noIdentifier + ' even under relaxed organizational-domain alignment; strict alignment was not evaluated. This is a contradiction within the message’s own claims, not cryptographic verification.', null, item));
      else findings.push(finding('info', 'dmarc-alignment-observation', 'Derived and reported DMARC alignment differ without a local contradiction', dmarc.evaluator + ' reports dmarc=' + dmarc.result + ', while message-local identifiers yield ' + derived + ' relaxed alignment. A reported failure can still be consistent with strict aspf/adkim policy, which was not evaluated.', null, item));
    });

    return {
      observed: observed,
      authservIds: authservIds,
      records: records,
      signatures: signatures,
      receivedSpf: receivedSpf,
      spfDetails: records.filter(function (record) { return record.method === 'spf'; }).concat(receivedSpf),
      dmarcAlignment: dmarcAlignment,
      dkimSignatures: signatures.length,
      arcSets: (map['arc-seal'] || []).length,
      arcAuthenticationResults: (map['arc-authentication-results'] || []).length,
      verified: false,
      caveat: 'These are method results reported by Authentication-Results and Received-SPF fields. ARC set presence is counted separately. This local structural analyzer does not query DNS, validate DKIM body hashes or signatures, validate ARC seals, or establish which result and trace fields are trustworthy.'
    };
  }

  function analyzeMessage(raw, suppliedOptions) {
    var options = {};
    Object.keys(DEFAULTS).forEach(function (k) { options[k] = suppliedOptions && suppliedOptions[k] != null ? Math.max(1, Number(suppliedOptions[k]) || 1) : DEFAULTS[k]; });
    raw = String(raw == null ? '' : raw);
    var originalCharacters = raw.length, findings = [], analysisState = { truncated: false };
    if (raw.length > options.maxInputCharacters) {
      findings.push(finding('error', 'input-size-limit', 'Input size limit reached', 'Only the configured prefix was analyzed to protect this browser tab.', null, { characters: raw.length, limit: options.maxInputCharacters }));
      raw = raw.slice(0, options.maxInputCharacters); analysisState.truncated = true;
    }
    var leadingBlank = /^(?:[ \t]*(?:\r\n|\r|\n))+/.exec(raw);
    if (leadingBlank) {
      var candidate = raw.slice(leadingBlank[0].length);
      if (/^[!-9;-~]+[ \t]*:/.test(candidate)) {
        var ignoredEndings = countLineEndings(leadingBlank[0]);
        findings.push(finding('info', 'leading-blank-lines-ignored', 'Leading blank lines were ignored', 'Blank lines before the first recognizable header were treated as a copy/paste artifact.', null, { count: ignoredEndings.crlf + ignoredEndings.bareLf + ignoredEndings.bareCr }));
        raw = candidate;
      }
    }
    if (!raw.trim()) findings.push(finding('error', 'empty-message', 'Message is empty', 'Paste or open a complete raw message, including headers and body.'));

    var endingCounts = countLineEndings(raw), crlf = endingCounts.crlf, bareLf = endingCounts.bareLf, bareCr = endingCounts.bareCr;
    if (bareLf || bareCr) {
      var pastedEndings = suppliedOptions && suppliedOptions.inputSource === 'paste';
      findings.push(finding('info', 'non-crlf-line-endings', pastedEndings ? 'Pasted text uses normalized line endings' : 'Non-CRLF line endings found', pastedEndings ? 'Browsers normally normalize pasted textarea content to LF. The analyzer preserved this as an informational transport note.' : 'Internet messages normally use CRLF. Copy/paste and file conversion often normalize these, so this alone does not prove the source message was malformed.', null, { crlf: crlf, bareLf: bareLf, bareCr: bareCr }));
    }
    var normalizedRaw = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    var scanAt = 0, lineCount = 1, cutAt = -1;
    while (lineCount <= options.maxPhysicalLines) {
      var nextBreak = normalizedRaw.indexOf('\n', scanAt);
      if (nextBreak < 0) break;
      lineCount++; scanAt = nextBreak + 1;
      if (lineCount > options.maxPhysicalLines) { cutAt = nextBreak; break; }
    }
    if (cutAt >= 0) {
      findings.push(finding('error', 'physical-line-limit', 'Physical line limit reached', 'Only the configured prefix of the message was analyzed to protect this browser tab.', null, { atLeast: lineCount, limit: options.maxPhysicalLines }));
      normalizedRaw = normalizedRaw.slice(0, cutAt);
      raw = normalizedRaw; analysisState.truncated = true;
    }
    var normalizedLines = normalizedRaw.split('\n');
    normalizedLines.forEach(function (line, index) {
      var octets = utf8Length(line);
      if (octets > 998) findings.push(finding('error', 'line-too-long', 'Physical line exceeds 998 octets', 'RFC 5322 places a hard limit of 998 octets before the line ending.', index + 1, { octets: octets, characters: line.length }));
    });

    var split = splitMessage(raw, false);
    if (!split.hasSeparator && raw.trim()) findings.push(finding('warning', 'header-body-separator-missing', 'No blank line separates headers from body', 'A complete message uses an empty line between the header section and body. Header-only input may be intentional.'));
    var headers = parseHeaders(split.headerText, findings, 0, options, analysisState), map = headerMap(headers);
    var identities = messageIdentities(map, findings);
    if (map['x-mailer'] && map['user-agent'] && map['x-mailer'][0].trim() !== map['user-agent'][0].trim()) findings.push(finding('info', 'client-fingerprint-conflict', 'Client fingerprint fields disagree', 'X-Mailer reports ' + map['x-mailer'][0] + ', while User-Agent reports ' + map['user-agent'][0] + '. Multiple clients or middleware can add these fields, so this is a low-severity observation.', null, { fields: ['X-Mailer', 'User-Agent'], xMailer: map['x-mailer'][0], userAgent: map['user-agent'][0] }));
    if ((map['content-type'] || map['content-transfer-encoding']) && !map['mime-version']) findings.push(finding('warning', 'mime-version-missing', 'MIME-Version is missing', 'Top-level MIME Content-Type or transfer-encoding fields normally accompany MIME-Version: 1.0. Some readers infer MIME anyway, but gateways may not.'));
    ['subject', 'from', 'to', 'cc', 'reply-to'].forEach(function (name) {
      (map[name] || []).forEach(function (value) {
        var remainder = value.replace(/=\?[^?\s]+\?[bqBQ]\?[^?]*\?=/g, '');
        if (remainder.indexOf('=?') >= 0) findings.push(finding('warning', 'invalid-encoded-word', 'Malformed encoded word', 'This display-oriented header contains an RFC 2047 encoded-word marker that is incomplete or malformed.', null, { header: name }));
      });
    });
    ['date', 'from'].forEach(function (name) {
      if (!map[name] || !map[name].length) findings.push(finding('error', 'missing-header', 'Required header is missing', 'A normal Internet message requires a ' + name.replace(/(^|-)([a-z])/g, function (_, a, b) { return a + b.toUpperCase(); }) + ' field.', null, { header: name }));
    });
    SINGLETON.forEach(function (name) {
      if (map[name] && map[name].length > 1) findings.push(finding('error', 'duplicate-singleton-header', 'Singleton header appears more than once', name + ' appears ' + map[name].length + ' times with values: ' + map[name].join(' | ') + '. Mail clients can disagree about which copy to display.', null, { header: name, count: map[name].length, values: map[name].slice() }));
    });
    if (!map['message-id']) findings.push(finding('info', 'message-id-missing', 'Message-ID is absent', 'Message-ID is strongly recommended for traceability and threading, though absence is not always a structural error.'));
    if (map.date && !parseRfcDate(map.date[0])) findings.push(finding('error', 'invalid-date', 'Date header could not be parsed', 'The Date field is not a valid RFC-style date-time with a real calendar date and timezone.', headers.filter(function (h) { return h.lower === 'date'; })[0].line));

    var mimeState = { totalParts: 0, leafParts: 0, maxDepth: 0, options: options, boundaries: [], truncated: false };
    var rootNode = parseEntity(split.headerText, split.body, findings, mimeState, 0, '1', 0, headers) || { path:'1', contentType:'unknown', charset:'', transferEncoding:'', size:0, children:[], truncated:true };
    var hasAttachment = mimeHasAttachment(rootNode), attachClaim = (map['x-ms-has-attach'] || [''])[0].trim().toLowerCase();
    if (attachClaim === 'yes' && !hasAttachment) findings.push(finding('warning', 'attachment-indicator-disagreement', 'Attachment indicator does not match the MIME tree', 'X-MS-Has-Attach: yes is present, but no attachment part or filename exists in the parsed MIME tree.', null, { field: 'X-MS-Has-Attach', claimed: 'yes', attachmentPartExists: false }));
    else if (attachClaim && attachClaim !== 'yes' && hasAttachment) findings.push(finding('warning', 'attachment-indicator-disagreement', 'Attachment indicator does not match the MIME tree', 'X-MS-Has-Attach reports ' + attachClaim + ', but at least one attachment part exists in the parsed MIME tree.', null, { field: 'X-MS-Has-Attach', claimed: attachClaim, attachmentPartExists: true }));
    var xOriginatingIp = ((map['x-originating-ip'] || [''])[0].match(/\[([^\]]+)\]/) || [null, (map['x-originating-ip'] || [''])[0]])[1] || '';
    var hops = parseHops(map.received || [], findings, options, analysisState, { xOriginatingIp: xOriginatingIp });
    if (!hops.length) findings.push(finding('info', 'received-headers-missing', 'No Received trace fields are present', 'The message contains no Received fields, so transport continuity, per-hop TLS, and trace timing cannot be assessed from message bytes.', null, { field: 'Received', count: 0 }));
    var messageDate = map.date && parseRfcDate(map.date[0]), earliestHop = null;
    hops.forEach(function (hop) { if (hop.timestamp !== null && (!earliestHop || hop.timestamp < earliestHop.timestamp)) earliestHop = hop; });
    if (messageDate && earliestHop && earliestHop.timestamp - messageDate.timestamp > 7 * 24 * 60 * 60 * 1000) findings.push(finding('warning', 'date-before-received-trace', 'Date header substantially predates the Received trace', 'Date: ' + map.date[0] + ' precedes earliest trace hop ' + earliestHop.index + ' at ' + earliestHop.date + ' by more than seven days.', null, { field: 'Date', date: map.date[0], hop: earliestHop.index, hopDate: earliestHop.date, differenceMilliseconds: earliestHop.timestamp - messageDate.timestamp }));
    var timing = calculateHopTiming(hops);
    var auth = authentication(headers, map, findings, identities);
    var trustBoundary = applyTrustBoundary(hops, findings, suppliedOptions && suppliedOptions.trustedHop);
    var severityRank = { error: 0, warning: 1, info: 2 };
    findings.sort(function (a, b) { return severityRank[a.severity] - severityRank[b.severity] || (a.line || 999999) - (b.line || 999999); });
    var count = function (sev) { return findings.filter(function (f) { return f.severity === sev; }).length; };
    return {
      summary: { errors: count('error'), warnings: count('warning'), info: count('info') },
      findings: findings,
      trustBoundary: trustBoundary,
      identities: identities,
      headers: { count: headers.length, fields: headers, subjectDecoded: decodeHeaderValue((map.subject || [''])[0]), from: decodeHeaderValue((map.from || [''])[0]), to: decodeHeaderValue((map.to || [''])[0]), date: (map.date || [''])[0], messageId: (map['message-id'] || [''])[0] },
      mime: { totalParts: mimeState.totalParts, leafParts: mimeState.leafParts, maxDepth: mimeState.maxDepth, tree: rootNode },
      hops: hops,
      timing: timing,
      authentication: auth,
      meta: { characters: originalCharacters, analyzedCharacters: raw.length, truncated: analysisState.truncated || mimeState.truncated, lineEndings: { crlf: crlf, bareLf: bareLf, bareCr: bareCr } },
      caveats: [
        'Structural checks are heuristic and cannot reproduce every MTA or gateway policy.',
        'Received fields are prepended by each handling system; entries below the first trusted boundary can be forged.',
        'Authentication-Results and ARC fields are displayed as claims unless independently verified by a trusted receiver.'
      ]
    };
  }

  return { analyzeMessage: analyzeMessage, decodeHeaderValue: decodeHeaderValue, parseParams: parseParams };
});
