# zachvivier.com

Source for [zachvivier.com](https://zachvivier.com), a static site hosting
browser-based diagnostic tools for support and security work.

The tools process files with JavaScript running in the browser. There is no
application backend, intentional file-upload step, account, analytics,
framework, dependency installation, or build process; the files in this
repository are served directly through GitHub Pages.

## Tools

| Tool | Status | Input | Open |
| --- | --- | --- | --- |
| HAR Viewer | Available | `.har` / `.json` | [Launch](https://zachvivier.com/har-viewer.html) |
| Event Log Viewer | Available | Windows `.evtx` | [Launch](https://zachvivier.com/event-viewer.html) |
| Mail Header Analyzer | Beta | `.eml` / `.txt` / raw message text | [Launch](https://zachvivier.com/mail-analyzer.html) |
| Certificate Inspector | Available | PEM / CRT / CER / DER certificate or PEM public key | [Launch](https://zachvivier.com/cert-inspector.html) |

### HAR Viewer

**Input:** One or more HTTP Archive captures exported from browser developer
tools. Additional files can be merged into the current session.

**Capabilities:**

- Inspect recorded requests, headers, cookies, query and form parameters,
  payloads, response bodies, timings, protocol, remote address, and initiator
  stack.
- Search across URLs, headers, parameters, payloads, and response bodies,
  including `-term` exclusions.
- Filter by status class, method, host, resource type, or timeline range.
- Open a header index listing every header name and value across the filtered
  requests.
- Copy URLs or cURL commands and export filtered data as CSV, JSON, or HAR.

**Limitations:** `Mask` is off by default. While it is on, it hides values in
named credential-looking headers, cookies, query parameters, and form
parameters throughout the interface and exports. With it off, copied and
exported values are unmasked. It is not comprehensive redaction.

**Response bodies are not masked. Payloads that cannot be parsed into named
parameters are not masked either.** HAR captures routinely contain active
tokens, cookies, credentials, personal information, and proprietary data.
Review the file and every export before sharing them.

### Event Log Viewer

**Input:** One or more Windows `.evtx` files. Files can be exported from Event
Viewer using **Save All Events As…** while retaining the `.evtx` format. Windows
is not required to read them.

**Capabilities:**

- Merge several event logs into one timeline.
- Search provider, event ID, computer, channel, an event-data summary, and raw
  XML. Space-separated terms must all match.
- Filter by level, provider, event ID, or timeline range.
- Inspect event metadata, named event-data fields, and raw XML.
- Switch between local and UTC timestamps.
- Copy individual records as XML or JSON and export filtered results as CSV or
  JSON.

**Limitations:**

- **Masking is off by default and is best effort, not a guarantee.** While it is
  on, it shortens recognized account, computer, address, SID, and
  credential-bearing values across the list, detail pane, XML, copy actions,
  and exports. With it off, copied and exported values are unmasked. Some
  providers store identifying data in positional fields such as `param7`, and
  unrecognized or short values can remain in raw XML.
- **Rendered Windows descriptions are unavailable.** Windows constructs an
  event's description at display time from the provider's message DLL on the
  originating machine. That text is not stored in the `.evtx`; the viewer
  instead exposes the underlying named event-data fields.
- XML decode failures are counted as unreadable. Malformed record headers or
  chunks can cause additional records to be skipped without being counted, so
  displayed totals may be incomplete.

Review records and every export before sharing them or relying on masking.

### Mail Header Analyzer (beta)

**Input:** A complete raw message supplied as an `.eml` or text file, or pasted
from a provider's “Show original” view. Files larger than 20 MiB are rejected.
Additional safety limits can truncate analysis of very large or deeply nested
messages; the report is marked when this occurs.

**Capabilities:**

- Check header syntax, required and duplicate fields, physical line limits, and
  RFC 2047 encoded words.
- Build a MIME structure tree; inspect boundaries, nesting, part counts,
  dispositions, attachment filenames, and Base64 or quoted-printable encoding.
- Parse `Received` routes into claimed and receiver-observed endpoints, protocol,
  TLS details, timestamps, and per-hop timing.
- Identify disconnected adjacent hops, chronology inversions, plaintext SMTP,
  failed TLS verification claims, HELO or address disagreements, recipient
  changes, and special-use IP address ranges. Localhost and loopback
  reinjection are treated separately from external continuity.
- Let you designate a trusted receiver and label lower hops and related findings
  as unverifiable by construction.
- Surface SPF, DKIM, DMARC, ARC, and `Received-SPF` results recorded in message
  headers, including repeated or disagreeing claims and unmatched DKIM results.
- Compare message-local Return-Path, Sender, From, Reply-To, SPF, and DKIM
  identities. DMARC alignment is derived only when the available local evidence
  is sufficient; organizational-domain cases that require unavailable public
  suffix data remain indeterminate.
- Present severity, evidence, and context for individual observations without
  issuing an overall safe, malicious, phishing, or spoofing verdict.

This tool is **beta**. Parsing may be wrong or incomplete. Feedback is welcome
at [site@zachvivier.com](mailto:site@zachvivier.com?subject=Mail%20Header%20Analyzer%20feedback).

Authentication output contains **observed claims, not independent verification**:

- **No DNS:** SPF, DKIM, and DMARC records or policies are not fetched.
- **No cryptography:** DKIM body hashes, signatures, and ARC seals are not
  verified.
- **Trust boundary:** `Received` and authentication fields below a trusted
  receiver can be forged. The analyzer does not determine where that boundary
  is; you must designate the receiver you trust, or leave the boundary unset.

A favorable `Authentication-Results` header proves only that a system wrote
that result into the message. The analyzer does not determine whether a message
is legitimate, safe, phishing, or malware-free.

### Certificate Inspector

**Input:** PEM certificates, SubjectPublicKeyInfo public keys, and PKCS#1 RSA
public keys, plus DER certificates and unarmoured Base64, whether pasted or
dropped as a file. Common `.crt`, `.cer`, `.pem`, and `.der` files are
supported. Private-key material is detected and rejected rather than displayed
or parsed.

**Capabilities:**

- Read X.509 subject, issuer, serial number, version, validity, signature
  algorithm, key algorithm, certificate fingerprints, and public-key
  fingerprints.
- Decode commonly useful extensions including subject alternative names, basic
  constraints, key usage, extended key usage, and authority/subject key IDs.
- Present RSA and EC key details with a deterministic visual fingerprint derived
  from the public key's SHA-256 value.
- Label every key fingerprint with the structure it covers. Only a
  SubjectPublicKeyInfo digest is shown as a pin; a PKCS#1 RSAPublicKey digest is
  marked as not being an SPKI pin, because the two differ for the same key.

**Limitations:** This is a local structure reader, not a trust decision engine.
It does not validate a chain, check revocation, validate hostnames, retrieve
intermediates, or verify certificate signatures. A fingerprint or parsed field
does not establish that a certificate is trusted, current, or safe.

## Privacy and responsible use

The full statement is available at
[Privacy & usage](https://zachvivier.com/privacy.html).

- **Local processing:** Files are processed by code running on your device. The
  tools do not intentionally upload file contents, require an account, or send
  analytics. Your browser and the hosting provider still receive ordinary page
  requests.
- **Sensitive data:** Diagnostic files can contain passwords, tokens, cookies,
  personal information, internal addresses, and proprietary data. Masking and
  parsing may not identify every secret or interpret every file correctly.
  Review everything before sharing or exporting it.
- **Responsible use:** Inspect only data and systems you are authorized to
  access. Keep original files and verify important conclusions independently.
  Do not treat tool output as security, legal, or professional advice.
- **No warranty:** The site and tools are provided “as is” and without
  warranties. To the fullest extent permitted by law, the author assumes no
  responsibility or liability for data loss, exposure, inaccurate results,
  service interruption, or other consequences arising from their use.

## Repository structure

```text
README.md                This document
index.html               Homepage and tool directory
privacy.html             Privacy and responsible-use statement
har-viewer.html          Self-contained HAR Viewer
event-viewer.html        Event Log Viewer and EVTX parser
mail-analyzer.html       Mail Header Analyzer interface
mail-analyzer-core.js    Mail parsing and analysis logic
cert-inspector.html      Certificate Inspector interface
cert-inspector-core.js   X.509 and public-key parsing logic
assets/                  Site assets and shared Ghostty Site stylesheet
tests/                   Tool tests and safe fixtures
.gitattributes           Disables text conversion and diffs for .eml fixtures
CNAME                    GitHub Pages custom domain
```

## Running locally

No installation or build step is required. Serve the repository directory with
any static HTTP server:

```sh
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000/
```

## Tests

Automated tests cover the Mail Header Analyzer, Certificate Inspector, CSP and
escaping policy across the diagnostic tools, and an adversarial HAR rendering
check in a real browser. The
browser check runs when Chrome or Chromium and a Node runtime with global
WebSocket support are available; otherwise it is skipped. The HAR and EVTX
parsers do not yet have broad functional test coverage.

Run the suite from the repository root using Node's built-in test runner:

```sh
node --test
```
