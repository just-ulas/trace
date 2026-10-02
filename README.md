# TRACE 3.1

TRACE is a terminal-centric, evidence-first security-intelligence workstation for authorized defensive investigation. It runs as a native Android application and as a dependency-free Java PC client with a CLI and Swing GUI.

> TRACE is read-only by design. It does not exploit, brute-force credentials, flood services, bypass controls, execute files, or provide stealth/evasion features.

## Release downloads

The latest release is [TRACE 3.1.0](https://github.com/just-ulas/trace/releases/tag/v3.1.0). Download links below are added only when the corresponding build succeeds:

| Platform | Asset | Status |
| --- | --- | --- |
| Android | `TRACE-3.1.0-android.apk` | Built by Android CI |
| Linux x64 | `TRACE-3.1.0-linux-x64.tar.gz` | Built and smoke-tested in this repository |
| Windows x64 | `TRACE-3.1.0-windows-x64.zip` | Portable Java package with Windows launcher |
| macOS ARM64 | `TRACE-3.1.0-macos-arm64.zip` | Portable Java package with macOS launcher |
| macOS x64 | `TRACE-3.1.0-macos-x64.zip` | Portable Java package with macOS launcher |

Every uploaded binary has a matching `.sha256` file. A platform is not described as available unless a real binary was produced and uploaded.

## What is new in 3.1

TRACE 3.1 preserves the Android scanner, terminal, history, cases, reports, risk engine, Malware Guard, WorkManager watchlist, SSRF protections, and keyless behavior from 2.0. The major change is the addition of a real PC client and a dependency-free shared core.

The shared `TRACE Core` contains URL normalization, link structure analysis, page classification, and risk vocabulary. The PC client adds a real HTTP redirect collector, DNS/TLS/HTTP evidence collection, content and phishing heuristics, static file analysis, SHA-256/MD5 hashing, local cases, comparisons, reports, watchlist commands, and a native Swing GUI. Android continues to use its richer platform implementation while consuming the same core URL policy and evidence vocabulary.


## TRACE 3.1 user experience

TRACE now opens on a simple **Target → Analyze** flow. The result begins with a presentation-layer **GENERAL RESULT**: `RELIABLE / GÜVENİLİR GÖRÜNÜYOR`, `SUSPICIOUS / ŞÜPHELİ`, `THREAT / TEHDİT BULGUSU`, or `UNVERIFIED / GÜVENİLİRLİK DOĞRULANAMADI`. `UNKNOWN` and unavailable sources are never presented as safe. Every result includes **WHY?**, **WHAT SHOULD I DO?**, confidence, evidence count, and the explicit warning that an assessment is not a security guarantee.

### Beginner, Standard, and Developer modes

- **Beginner:** verdict, explanation, recommended action, target, and a technical-details button.
- **Standard:** verdict plus important findings and destination details.
- **Developer:** complete JSON, headers, TLS/DNS/HTTP evidence, redirect chain, source diagnostics, timing, case ID, risk calculation, and evidence graph data.

Mode is persisted locally in Android Settings or with `trace config mode beginner|standard|developer` on PC.

### Ten languages

Android resource localization and the shared PC translation model cover Turkish, English, German, Spanish, French, Italian, Portuguese, Russian, Arabic, and Chinese. The command syntax remains stable across languages. Change language in Android Settings or with `trace lang tr` / `trace config language tr`.

### Link explain and safe code output

`trace link <url>` now combines URL structure with a safe fetch-based explanation. `trace explain <url>` describes likely login, payment, download, external-domain, nested-destination, redirect, and final-destination observations. Uncertain claims are kept as likely/possible/unknown.

`trace code <language> <url>` produces observation-only cURL, Python, JavaScript, TypeScript, Java, Kotlin, Go, Rust, PowerShell, or Bash examples. Snippets are redacted and never include tokens, cookies, passwords, or authorization values. Android case details provide **COPY JSON**, **COPY EVIDENCE**, **COPY CURL**, **SHARE CASE**, and local report export actions.

### Real settings and local case annotations

Settings cover language, mode, timeout/body limits, watch interval, local-only privacy, optional intelligence, and developer detail visibility. PC cases support local timing, tags, notes, and favorites; Android cases remain app-private and shareable only when the user invokes Android Share.

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

Install `TRACE-3.1.0-android.apk` from the v3.1.0 release. The Android client provides the terminal-first UI, scanner screen, dashboard, history/cases, reports, local settings, keyless intelligence, and WorkManager watchlist refresh.

Build locally:

```bash
export ANDROID_HOME=/path/to/android-sdk
./gradlew testDebugUnitTest lintDebug assembleDebug
```

The output is `app/build/outputs/apk/debug/app-debug.apk`.

## PC CLI

The Linux package contains a real executable launcher and a Java runtime-compatible JAR. Java 17 or newer is required when running from source or the JAR.

```bash
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 scan https://example.com
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 link 'https://example.com/a?next=https%3A%2F%2Fgithub.com%2F'
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 deep example.com
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 file sample.apk
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 apk sample.apk
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 hash <hash>
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 case CASE-00001
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 history
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 compare CASE-00001 CASE-00002
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 report CASE-00001
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 watch example.com
TRACE-3.1.0-linux-x64/TRACE-3.1.0-linux-x64 gui
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

The repository has Android CI plus a PC matrix for Windows x64, Linux x64, macOS ARM64, and macOS x64. Linux is distributed as a native app-image tarball. Windows and macOS are distributed as real portable Java ZIP packages with platform launchers; they do not pretend to be native `.exe` or `.app` binaries. A package is omitted rather than represented by a placeholder if its build does not produce the expected archive.

This sandbox cannot emulate Android UI instrumentation or validate Windows/macOS binaries locally. The CI workflow is the source of truth for those platform builds.

## Release history

Existing releases and tags are preserved. TRACE 3.1 is published as a new `v3.1.0` release; previous `v1.0.0`, `v2.0.0`, and `v3.0.0` artifacts are not rewritten or deleted.

## License

TRACE is released under the MIT License. See [LICENSE](LICENSE).
