# Changelog

## [3.1.0] - 2026-10-02

### Added

- Two-layer result presentation: GENERAL RESULT, WHY, recommended action, confidence, evidence counts, and technical details. UNKNOWN and unavailable evidence never become SAFE.
- Beginner, Standard, and Developer modes with persisted local settings.
- Shared TRACE 3.1 presentation layer for verdict mapping, source diagnostics, stage timing, link explanation, ten-language translation keys, and safe code snippets.
- `trace explain`, `trace verdict`, `trace sources`, `trace timing`, `trace code`, `trace tags`, `trace note`, `trace favorite`, `trace config`, and `trace lang` commands. Existing commands remain compatible.
- Safe cURL/Python/JavaScript/TypeScript/Java/Kotlin/Go/Rust/PowerShell/Bash integration examples with token, cookie, password, and authorization redaction.
- Android Target → Analyze start screen, localized result summary, technical-details reveal, copy JSON/evidence/cURL, share case, and expanded local Settings.
- Android resource localization and shared PC translations for Turkish, English, German, Spanish, French, Italian, Portuguese, Russian, Arabic, and Chinese.
- Real PC GUI content for Dashboard, Link Intelligence, and Settings rather than empty tab placeholders.
- Persistent local PC case timing, tags, notes, and favorites.

### Security and privacy

- The evidence-first `THREAT`, `SUSPICIOUS`, `HARDENING`, `INFORMATIONAL`, and `UNKNOWN` risk vocabulary is preserved.
- Link explanation remains read-only and safe; no exploit, credential, brute-force, upload, or evasion behavior was added.
- Code output is observation-only and redacts sensitive query/header values.

### Debugging hardening

- Removed legacy API-key provider execution from Android scanning; reputation now reports explicit local, cached, and unavailable source states.
- Preserved raw encoded query strings so nested destinations and encoded parameters are not silently decoded during normalization.
- Separated `HARDENING` from `RELIABLE` in the presentation verdict layer.
- Fixed Android risk severity/confidence mapping, PC timing persistence, metadata validation, and TRACE 3.1 User-Agent labeling.
- Added regression coverage for raw query preservation, nested URL detection, unavailable-source handling, hardening presentation, and redaction.

### Language and site-understanding fixes

- Language changes now rebuild the Android shell immediately instead of only changing a hidden preference.
- Android and PC verdict labels/actions follow the selected language; mixed Turkish/English verdict output is removed.
- Page classification now prioritizes visible text, headings, real forms, URL path and page structure while ignoring script/style noise.
- Scan summaries now show detected site type and page scope (links, forms, headings).
- Added regression tests for login/store classification, encoded destinations, localized verdicts and conservative unknown handling.

### Validation

- PC core regression tests: PASS, including ten-language coverage, unknown/suspicious verdicts, link explain, and redaction.
- Android unit tests: 10 tests, 0 failures.
- Android lint: 0 issues.
- Android debug APK: versionName 3.1.0, signed and verified.

[3.0.0] - 2026-10-02

### What's new

TRACE is now an Android plus PC security-intelligence workstation. Existing Android scanning, terminal, history, cases, reports, risk engine, Malware Guard, watchlist, SSRF validation, and keyless privacy behavior remain available.

A dependency-free shared `TRACE Core` now provides URL normalization, link structure analysis, page classification, and risk vocabulary. The PC client adds a real Java CLI, native Swing GUI, redirect-aware HTTP evidence collection, page classification, phishing heuristics, static file/APK/ZIP/JAR analysis, SHA-256/MD5 hashing, local cases, reports, comparisons, and watch commands.

### Security engine

Risk concepts are kept separate: `THREAT`, `SUSPICIOUS`, `HARDENING`, `INFORMATIONAL`, and `UNKNOWN`. Missing security headers are hardening observations; known malicious evidence is required for a threat claim; unavailable sources remain unavailable.

### Link intelligence

Added URL component decomposition, nested URL and encoding indicators, punycode/download indicators, original-to-final destination tracking, redirect hop evidence, page type classification, title and form observations, and timestamped redirect timeline data.

### Platforms

Android 3.0.0 is built by Gradle/Android CI. Linux x64 is built and smoke-tested as a native app-image tarball. Windows x64, macOS ARM64, and macOS x64 are distributed as real portable Java ZIP packages with platform launchers; no fake native binaries or placeholder files are created.

### Privacy and limitations

No API-key settings screen is required. Files are never executed or uploaded. Windows/macOS archives are portable Java packages rather than native `.exe`/`.app` binaries. Unknown is not safe, and heuristic suspiciousness is not malware.

### Checksums

Every real binary attached to the `TRACE 3.0.0` release has a matching `.sha256` asset. Release notes list only assets produced by successful builds.

## [2.0.0] - 2026-10-02

### Added

- TRACE Intelligence Engine pipeline with URL, DNS, IP, TLS, HTTP, content, threat, risk, graph, case, and report stages.
- Explainable `RiskEngine` findings with severity, confidence, source, reason, evidence, and timestamp.
- Static phishing heuristics for IDN/path anomalies, password forms, cross-origin actions, iframes, mixed content, encoding, and obfuscation indicators.
- `TRACE Malware Guard` for local SHA-256/SHA-1/MD5, MIME, markers, suspicious strings, extension mismatch, and APK metadata/permissions/components.
- Keyless public RDAP domain intelligence and local feed status cache.
- Expanded DNS record coverage: SOA, CAA, PTR, SPF, DMARC, and explicit DNSSEC `NOT AVAILABLE` state.
- IP intelligence with IPv4/IPv6 family, reverse DNS, and public/private scope.
- Evidence graph and local scan comparison.
- `quick`, `deep`, `domain`, `ip`, `file`, `hash`, `risk`, `compare`, `watch`, `unwatch`, and `watches` terminal commands.
- Local watchlist refresh through Android WorkManager.
- Settings without API-key fields; privacy and local-only controls are documented in-app.
- Additional risk, content, graph, URL policy, and persistence tests.

### Safety

- No exploit, brute-force, credential attack, DDoS, stealth, evasion, file execution, or sandbox bypass behavior.
- Files are statically inspected on-device and never uploaded.
- Unknown, unavailable, stale, and suspicious states are kept distinct from safe or malicious verdicts.
