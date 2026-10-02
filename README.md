# TRACE

TRACE 2.0 is a local-first Android security-intelligence workstation for authorized defensive investigation. Its **TRACE Intelligence Engine** collects DNS, IP, TLS, HTTP, redirect, header, technology, static content, threat-indicator, risk, evidence-graph, case, and report data directly from the Android device's network connection.

> TRACE is read-only by design. It does not exploit, brute-force, attack credentials, flood services, bypass controls, or provide stealth/evasion features.

## Features

- Terminal commands that invoke real scanner functions
- HTTP/HTTPS URL normalization and status inspection
- Redirect chain collection with re-validation at every hop
- DNS-over-HTTPS lookups for A, AAAA, MX, NS, TXT, and CNAME records
- TLS certificate subject, issuer, validity, SAN count, and cipher details
- Security-header inspection
- Technology hints from response headers and HTML fingerprints
- Modular VirusTotal, URLhaus, and Google Safe Browsing provider support
- Keyless operation: there is no API-key screen and no provider account requirement
- Local case history with `CASE-00001` identifiers
- JSON evidence and self-contained HTML report export
- Explainable risk engine with severity, confidence, evidence, source, reason, and timestamp
- Static phishing heuristics and local Malware Guard for files and APK metadata
- Evidence graph, scan comparison, local watchlist, and WorkManager refresh
- Offline access to saved cases, reports, hashes, heuristics, and cached source state
- Dark, minimal, monospace UI with no backend/server requirement

## Screenshots

### Terminal UI preview

![TRACE terminal UI preview](docs/screenshots/terminal.svg)

The APK renders this same terminal-first visual language natively on Android.

## Installation

Download the APK from the [latest GitHub release](https://github.com/just-ulas/trace/releases/latest), enable installation from the browser or file manager when Android requests it, and install. No server, VPS, Docker, PostgreSQL, Redis, or nginx setup is required.

## Android APK

The repository includes a reproducible Gradle project. GitHub Actions builds the debug APK on pushes and pull requests and attaches a tagged APK to GitHub Releases. The current release is [TRACE v2.0.0](https://github.com/just-ulas/trace/releases/tag/v2.0.0).

Local build:

```bash
./gradlew testDebugUnitTest assembleDebug
```

Output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

## Usage

Open TRACE and use the **TERMINAL** section:

```text
$ trace scan example.com

[+] TARGET        example.com
[+] DNS           OK
[+] TLS           VALID
[+] HTTP          200
[+] REDIRECTS     0
[+] TECHNOLOGY    nginx
[+] REPUTATION    3 provider modules
[+] CASE          CASE-00001
```

All network work is asynchronous so the interface remains responsive. The **SCAN** tab provides the same full scan as a form, while **HISTORY** and **CASES** reopen locally stored evidence.

## TRACE 2.0 terminal commands

| Command | Purpose |
| --- | --- |
| `trace scan <target>` | Full scan and save a local case |
| `trace quick <target>` | Fast safe analysis |
| `trace deep <target>` | Full intelligence pipeline |
| `trace dns <domain>` | A / AAAA / MX / NS / TXT / CNAME records |
| `trace tls <domain>` | Certificate and cipher information |
| `trace headers <url>` | Response and security headers |
| `trace redirects <url>` | Safe redirect chain |
| `trace tech <url>` | Web server, framework, CMS, and CDN hints |
| `trace domain <domain>` | Keyless public RDAP domain data |
| `trace ip <host>` | IP family, reverse DNS, and scope |
| `trace file <path>` | Local static file/APK analysis |
| `trace hash <path-or-hash>` | Local hashes and case history lookup |
| `trace reputation <domain>` | Provider module results |
| `trace risk <target>` | Explainable risk assessment |
| `trace compare <caseA> <caseB>` | Compare two local scans |
| `trace history` | Local case list |
| `trace case <id>` | Reopen a case |
| `trace watch <target>` | Add a local watch target |
| `trace unwatch <target>` | Remove a watch target |
| `trace watches` | List watch targets |
| `trace export <id>` | Write JSON and HTML reports |
| `trace clear` | Clear the terminal view |
| `trace help` | Show command help |

## Keyless intelligence sources

Provider integrations are modular and optional. TRACE never asks the user to create an account or enter an API key:

- **URLhaus** is queried without a key.
- Public DNS-over-HTTPS, RDAP, and URLhaus-compatible keyless requests are used where appropriate.
- If a source is unavailable, rate-limited, stale, or unsupported, TRACE records that state as evidence and continues the pipeline.
- A missing source never becomes a fabricated safe or malicious verdict.

TRACE's local heuristics and static analysis remain available without network access.

## Security

TRACE applies the following URL safety controls before every request:

- Only HTTP and HTTPS schemes are accepted.
- User-info URLs are rejected.
- `localhost`, `.local`, `.internal`, `.intranet`, `.lan`, and `home.arpa` names are blocked.
- Loopback, private, link-local, multicast, any-local, IPv4 special-range, and IPv6 ULA addresses are blocked.
- Every redirect target is normalized and validated again.
- Redirect chains stop after eight hops.
- Response bodies are capped at 256 KiB.
- Network operations have connect/read timeouts.
- APKs and files are never executed, uploaded, or passed to a sandbox bypass.

TRACE is intended for targets the operator is authorized to inspect.

## Architecture

```text
Android Activity
  ├── Terminal / Scan / History / Cases / Reports / Settings UI
  ├── TraceScanner
  │     ├── URL + SSRF validation
  │     ├── HTTP/redirect collector
  │     ├── DNS-over-HTTPS collector
  │     ├── TLS certificate collector
  │     ├── Technology detector
  │     └── Reputation provider modules
  ├── RiskEngine / ContentAnalyzer / MalwareGuard
  ├── WatchWorker (WorkManager) + WatchlistStore
  └── CaseStore (SharedPreferences + app-private Documents export)
```

The base application has no continuously running backend and no required cloud service. Android's app storage provides persistence after restart; all analysis traffic originates from the device.

## Reports

Each export creates:

```text
case.json       case metadata plus results
evidence.json   scanner evidence bundle
report.html     standalone dark HTML report
```

Exports are written to the app-specific Documents directory, which does not require broad storage permission.

## License

TRACE is released under the MIT License. See [LICENSE](LICENSE).
