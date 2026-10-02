# Changelog

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
