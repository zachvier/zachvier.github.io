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

  function finding(severity, code, title, detail, line, context) {
    return { severity: severity, code: code, title: title, detail: detail, line: line || null, context: context || {} };
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
    var node = { path: path, contentType: ct.type, charset: ct.params.charset || '', transferEncoding: (map['content-transfer-encoding'] || ['7bit'])[0].toLowerCase(), size: body.length, children: [] };
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

  function parseHops(received, findings, options, state) {
    var source = received;
    if (source.length > options.maxHops) {
      findings.push(finding('error', 'received-hop-limit', 'Received hop limit reached', 'Only the newest trace fields were parsed to protect this browser tab.', null, { count: source.length, limit: options.maxHops }));
      source = source.slice(0, options.maxHops); state.truncated = true;
    }
    var hops = source.map(function (value, index) {
      var dateText = traceDate(value), parsed = dateText ? parseRfcDate(dateText) : null, ms = parsed ? parsed.timestamp : null;
      var hop = { index: index + 1, from: token(value, 'from'), by: token(value, 'by'), with: token(value, 'with'), id: token(value, 'id'), for: token(value, 'for'), date: dateText, timestamp: ms, raw: value };
      if (!parsed) findings.push(finding('warning', 'received-date-unparseable', 'Received timestamp could not be parsed', 'This hop has no valid RFC-style date after its final grammar-level semicolon.', null, { hop: index + 1 }));
      if (!hop.by) findings.push(finding('warning', 'received-by-missing', 'Received hop has no “by” clause', 'The trace field does not identify the receiving server.', null, { hop: index + 1 }));
      return hop;
    });
    for (var i = 0; i + 1 < hops.length; i++) {
      if (hops[i].timestamp !== null && hops[i + 1].timestamp !== null && hops[i + 1].timestamp - hops[i].timestamp > 300000) {
        findings.push(finding('warning', 'received-time-inversion', 'Received timestamps run backward', 'A lower (earlier) hop claims a time more than five minutes later than the hop above it. Clock skew or forged trace fields are possible.', null, { newerHop: i + 1, olderHop: i + 2 }));
      }
    }
    return hops;
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

  function authentication(map) {
    var observed = { dkim: [], spf: [], dmarc: [], arc: [] }, authservIds = [];
    (map['authentication-results'] || []).forEach(function (value) {
      var clauses = splitAuthClauses(value);
      if (clauses.length) authservIds.push(clauses.shift().replace(/\s+\d+\s*$/, '').trim());
      clauses.forEach(function (clause) {
        var clean = stripComments(clause), m = /^([a-z][a-z0-9_-]*)\s*=\s*([a-z][a-z0-9_-]*)\b/i.exec(clean);
        if (!m) return;
        var method = m[1].toLowerCase(), result = m[2].toLowerCase();
        if (Object.prototype.hasOwnProperty.call(observed, method)) observed[method].push(result);
      });
    });
    return {
      observed: observed,
      authservIds: authservIds,
      dkimSignatures: (map['dkim-signature'] || []).length,
      arcSets: (map['arc-seal'] || []).length,
      arcAuthenticationResults: (map['arc-authentication-results'] || []).length,
      verified: false,
      caveat: 'These are method results reported by Authentication-Results fields. ARC set presence is counted separately. This local structural analyzer does not query DNS, validate DKIM/ARC cryptography, or establish which result and trace fields are trustworthy.'
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
      findings.push(finding(pastedEndings ? 'info' : 'warning', 'non-crlf-line-endings', pastedEndings ? 'Pasted text uses normalized line endings' : 'Non-CRLF line endings found', pastedEndings ? 'Browsers normally normalize pasted textarea content to LF. The analyzer preserved this as an informational transport note.' : 'Internet messages normally use CRLF. Copy/paste and file conversion often normalize these, so this alone does not prove the source message was malformed.', null, { crlf: crlf, bareLf: bareLf, bareCr: bareCr }));
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
      if (map[name] && map[name].length > 1) findings.push(finding('error', 'duplicate-singleton-header', 'Header appears more than once', 'This field is defined as a singleton in a normal message and duplicate instances can trigger filtering or ambiguous interpretation.', null, { header: name, count: map[name].length }));
    });
    if (!map['message-id']) findings.push(finding('info', 'message-id-missing', 'Message-ID is absent', 'Message-ID is strongly recommended for traceability and threading, though absence is not always a structural error.'));
    if (map.date && !parseRfcDate(map.date[0])) findings.push(finding('error', 'invalid-date', 'Date header could not be parsed', 'The Date field is not a valid RFC-style date-time with a real calendar date and timezone.', headers.filter(function (h) { return h.lower === 'date'; })[0].line));

    var mimeState = { totalParts: 0, leafParts: 0, maxDepth: 0, options: options, boundaries: [], truncated: false };
    var rootNode = parseEntity(split.headerText, split.body, findings, mimeState, 0, '1', 0, headers) || { path:'1', contentType:'unknown', charset:'', transferEncoding:'', size:0, children:[], truncated:true };
    var hops = parseHops(map.received || [], findings, options, analysisState);
    var auth = authentication(map);
    var severityRank = { error: 0, warning: 1, info: 2 };
    findings.sort(function (a, b) { return severityRank[a.severity] - severityRank[b.severity] || (a.line || 999999) - (b.line || 999999); });
    var count = function (sev) { return findings.filter(function (f) { return f.severity === sev; }).length; };
    return {
      summary: { errors: count('error'), warnings: count('warning'), info: count('info'), verdict: count('error') ? 'problems-found' : count('warning') ? 'review' : 'clean' },
      findings: findings,
      headers: { count: headers.length, fields: headers, subjectDecoded: decodeHeaderValue((map.subject || [''])[0]), from: decodeHeaderValue((map.from || [''])[0]), to: decodeHeaderValue((map.to || [''])[0]), date: (map.date || [''])[0], messageId: (map['message-id'] || [''])[0] },
      mime: { totalParts: mimeState.totalParts, leafParts: mimeState.leafParts, maxDepth: mimeState.maxDepth, tree: rootNode },
      hops: hops,
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
