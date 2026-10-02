# Changelog

## [3.0.0] - 2026-10-02

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
