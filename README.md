# TRACE 3.0

TRACE is a terminal-centric, evidence-first security-intelligence workstation for authorized defensive investigation. It runs as a native Android application and as a dependency-free Java PC client with a CLI and Swing GUI.

> TRACE is read-only by design. It does not exploit, brute-force credentials, flood services, bypass controls, execute files, or provide stealth/evasion features.

## Release downloads

The latest release is [TRACE 3.0.0](https://github.com/just-ulas/trace/releases/tag/v3.0.0). Download links below are added only when the corresponding build succeeds:

| Platform | Asset | Status |
| --- | --- | --- |
| Android | `TRACE-3.0.0-android.apk` | Built by Android CI |
| Linux x64 | `TRACE-3.0.0-linux-x64.tar.gz` | Built and smoke-tested in this repository |
| Windows x64 | `TRACE-3.0.0-windows-x64.zip` | Built by Windows CI when the v3 tag workflow succeeds |
| macOS ARM64 | `TRACE-3.0.0-macos-arm64.zip` | Built by macOS CI when the v3 tag workflow succeeds |
| macOS x64 | `TRACE-3.0.0-macos-x64.zip` | Built by macOS CI when the v3 tag workflow succeeds |

Every uploaded binary has a matching `.sha256` file. A platform is not described as available unless a real binary was produced and uploaded.

## What is new in 3.0

TRACE 3.0 preserves the Android scanner, terminal, history, cases, reports, risk engine, Malware Guard, WorkManager watchlist, SSRF protections, and keyless behavior from 2.0. The major change is the addition of a real PC client and a dependency-free shared core.

The shared `TRACE Core` contains URL normalization, link structure analysis, page classification, and risk vocabulary. The PC client adds a real HTTP redirect collector, DNS/TLS/HTTP evidence collection, content and phishing heuristics, static file analysis, SHA-256/MD5 hashing, local cases, comparisons, reports, watchlist commands, and a native Swing GUI. Android continues to use its richer platform implementation while consuming the same core URL policy and evidence vocabulary.

## Intelligence model

### Link Intelligence

`trace link <url>` decomposes scheme, host, port, path, query, fragment, subdomain, TLD, punycode, encoding, nested URLs, and download indicators. `trace scan` records the original URL, normalized URL, final destination, redirect chain, page type, title, forms, password-field observations, external form actions, and technology hints.

Each redirect hop records status, source and destination host, HTTPS state, cross-origin state, and a timestamp. Redirect targets are normalized and revalidated against the SSRF policy before the next request.

### Page Understanding

Static content is classified conservatively as `LOGIN`, `PAYMENT`, `SEARCH`, `STORE`, `NEWS`, `BLOG`, `DOWNLOAD`, `SOCIAL`, or `UNKNOWN`. A heuristic finding is not treated as proof of maliciousness.

### Threat and risk engine

TRACE keeps these concepts separate:

- `THREAT`: known malicious evidence only.
- `SUSPICIOUS`: heuristic or phishing indicators that require review.
- `HARDENING`: missing controls such as CSP or HSTS.
- `INFORMATIONAL`: observable facts without a risk claim.
- `UNKNOWN`: unavailable or insufficient evidence.

`UNKNOWN` is never converted into `SAFE`, and a heuristic is never silently upgraded to `THREAT`.

### Phishing analysis

The engine looks for IDN/punycode, encoded destinations, lookalike or sensitive paths, redirect complexity, password forms, cross-origin form actions, iframes, mixed content, suspicious parameters, and download anomalies.

### Malware Guard

Files are inspected locally and never executed or uploaded. The Android and PC clients support static hashing and format indicators for APK/ZIP/JAR, DEX markers, PDF, HTML/JavaScript, EXE/ELF-style metadata, embedded URLs, suspicious strings, extension mismatch, and APK archive components. Results remain evidence-based and can be `UNKNOWN` when a parser or source is unavailable.

## Android

Install `TRACE-3.0.0-android.apk` from the v3.0.0 release. The Android client provides the terminal-first UI, scanner screen, dashboard, history/cases, reports, local settings, keyless intelligence, and WorkManager watchlist refresh.

Build locally:

```bash
export ANDROID_HOME=/path/to/android-sdk
./gradlew testDebugUnitTest lintDebug assembleDebug
```

The output is `app/build/outputs/apk/debug/app-debug.apk`.

## PC CLI

The Linux package contains a real executable launcher and a Java runtime-compatible JAR. Java 17 or newer is required when running from source or the JAR.

```bash
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 scan https://example.com
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 link 'https://example.com/a?next=https%3A%2F%2Fgithub.com%2F'
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 deep example.com
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 file sample.apk
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 apk sample.apk
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 hash <hash>
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 case CASE-00001
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 history
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 compare CASE-00001 CASE-00002
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 report CASE-00001
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 watch example.com
TRACE-3.0.0-linux-x64/TRACE-3.0.0-linux-x64 gui
```

Local PC cases and reports are stored under `~/.trace/cases`. Network failures are reported as `UNKNOWN / UNAVAILABLE`; saved cases, hashes, static file analysis, reports, and comparisons remain available offline.

## PC GUI

`trace gui` opens a native Swing workstation with terminal-centric output and dedicated sections for Dashboard, Scanner, Link Intelligence, Cases, History, Watchlist, Files, Reports, Evidence, and Settings. The GUI is intentionally dependency-free and remains usable without a backend.

## Watchlist and comparison

Android uses WorkManager for periodic refresh. The PC CLI stores local watch targets and supports the same watchlist commands; native background scheduling is kept conservative in the portable client so an offline machine does not fabricate alerts. Case comparison exposes `NEW`, `REMOVED`, `CHANGED`, and `UNCHANGED` evidence categories for DNS, IP, TLS, certificates, redirects, headers, content, forms, technology, and risk.

## Reports

Reports are available as JSON evidence bundles on Android and as local HTML reports on both clients. The report structure includes Executive Summary, What Is This Link?, Original URL, Final Destination, URL Structure, DNS, IP, TLS, HTTP, Redirects, Content, Forms, Technology, Security Hardening, Phishing, Threat Intelligence, Malware, Evidence, Timeline, Changes, and Limitations.

## Privacy and security model

No VirusTotal, Google Safe Browsing, or URLhaus API key is required. There is no API-key settings screen. Public or keyless sources are optional; unavailable sources remain `UNAVAILABLE` or `UNKNOWN`.

SSRF controls block localhost, loopback, private networks, link-local addresses, multicast/any-local addresses, internal and special-use domains, and unsafe URL schemes. Redirect destinations are revalidated. Response bodies are bounded. Files are statically inspected only.

Use TRACE only against systems you are authorized to inspect.

## Architecture

```text
TRACE Core (dependency-free Java)
  ├── URL policy and normalization
  ├── link structure and page classification
  └── risk vocabulary

Android client
  ├── TraceScanner + DNS/TLS/HTTP/content/reputation modules
  ├── RiskEngine / MalwareGuard / EvidenceGraph
  ├── CaseStore / reports / WorkManager watchlist
  └── terminal-first native UI

PC client
  ├── TracePc CLI and Swing GUI
  ├── HTTP redirect and evidence collector
  ├── static file/hash Malware Guard
  └── ~/.trace local cases and reports
```

## Build matrix and limitations

The repository has Android CI plus a PC matrix for Windows x64, Linux x64, macOS ARM64, and macOS x64. The Linux package is built and smoke-tested in the current environment. Windows and macOS native packages are produced only by their respective GitHub-hosted runners; if a runner or native packager fails, that platform is omitted from the release rather than represented by a placeholder.

This sandbox cannot emulate Android UI instrumentation or validate Windows/macOS binaries locally. The CI workflow is the source of truth for those platform builds.

## Release history

Existing releases and tags are preserved. TRACE 3.0 is published as a new `v3.0.0` release; previous v1.x and v2.x artifacts are not rewritten or deleted.

## License

TRACE is released under the MIT License. See [LICENSE](LICENSE).
