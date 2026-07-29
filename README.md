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
  encoded words.
- Inspect MIME boundaries, nesting, part counts, and Base64 or
  quoted-printable encoding.
- Build a MIME structure tree.
- Parse `Received` routes, timestamps, and protocols; flag missing `by` clauses,
  unparseable timestamps, and chronology inversions greater than five minutes.
- Surface SPF, DKIM, DMARC, and ARC results recorded in
  `Authentication-Results`, and count `ARC-Seal` and
  `ARC-Authentication-Results` fields. Results inside
  `ARC-Authentication-Results` are not parsed.

This tool is **beta**. Parsing may be wrong or incomplete. Feedback is welcome
at [site@zachvivier.com](mailto:site@zachvivier.com?subject=Mail%20Header%20Analyzer%20feedback).

Authentication output contains **observed claims, not independent verification**:

- **No DNS:** SPF, DKIM, and DMARC records or policies are not fetched.
- **No cryptography:** DKIM body hashes, signatures, and ARC seals are not
  verified.
- **Trust boundary:** `Received` and authentication fields below a trusted
  receiver can be forged. The analyzer does not determine where that boundary
  is; you must identify the receiver you trust.

A favorable `Authentication-Results` header proves only that a system wrote
that result into the message. The analyzer does not determine whether a message
is legitimate, safe, phishing, or malware-free.

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
assets/                  Site assets
tests/                   Mail analyzer tests and fixtures
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

Automated tests cover the Mail Header Analyzer, CSP and escaping policy across
all three tools, and an adversarial HAR rendering check in a real browser. The
browser check runs when Chrome or Chromium and a Node runtime with global
WebSocket support are available; otherwise it is skipped. The HAR and EVTX
parsers do not yet have broad functional test coverage.

Run the suite from the repository root using Node's built-in test runner:

```sh
node --test
```
