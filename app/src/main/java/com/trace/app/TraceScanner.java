package com.trace.app;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.IDN;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

/**
 * TRACE's read-only reconnaissance engine. Every URL and redirect is revalidated
 * against public-address rules before a connection is opened.
 */
public final class TraceScanner {
    private static final int CONNECT_TIMEOUT_MS = 7000;
    private static final int READ_TIMEOUT_MS = 9000;
    private static final int MAX_REDIRECTS = 8;
    private static final int MAX_BODY_BYTES = 262144;
    private final SharedPreferences settings;

    public TraceScanner(Context context) {
        settings = context.getSharedPreferences("trace_settings", Context.MODE_PRIVATE);
    }

    public JSONObject scan(String target) throws Exception {
        String url = normalizeUrl(target);
        FetchResult fetch = fetch(url);
        JSONObject result = new JSONObject();
        result.put("target", target);
        result.put("normalizedUrl", url);
        result.put("scannedAt", System.currentTimeMillis());
        result.put("dns", dns(new URL(url).getHost()));
        result.put("http", fetch.toJson());
        result.put("redirects", fetch.redirects);
        result.put("tls", tls(url));
        result.put("technology", technology(fetch.headers, fetch.body));
        result.put("securityHeaders", securityHeaders(fetch.headers));
        result.put("reputation", reputation(new URL(url).getHost()));
        result.put("content", ContentAnalyzer.analyze(url, fetch.body));
        result.put("ip", ipIntelligence(new URL(url).getHost()));
        result.put("domain", domainIntelligence(new URL(url).getHost()));
        result.put("risk", RiskEngine.evaluate(result));
        result.put("evidenceGraph", IntelligenceUtils.graph(result));
        return result;
    }

    public JSONObject quick(String target) throws Exception { return scan(target); }
    public JSONObject deep(String target) throws Exception { return scan(target); }

    public JSONObject ip(String rawHost) throws Exception {
        String host = normalizeDomain(rawHost); validatePublicHost(host); return ipIntelligence(host);
    }

    public JSONObject domain(String rawDomain) throws Exception {
        String domain = normalizeDomain(rawDomain); validatePublicHost(domain); return domainIntelligence(domain);
    }

    public JSONObject dns(String rawDomain) throws Exception {
        String domain = normalizeDomain(rawDomain);
        validatePublicHost(domain);
        JSONObject result = new JSONObject();
        result.put("domain", domain);
        JSONObject records = new JSONObject();
        for (String type : new String[]{"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "PTR"}) {
            records.put(type, doh(domain, type));
        }
        JSONObject flags = new JSONObject();
        flags.put("SPF", records.optJSONArray("TXT") != null && records.optJSONArray("TXT").toString().toLowerCase(Locale.US).contains("v=spf1"));
        flags.put("DMARC", doh("_dmarc." + domain, "TXT").length() > 0);
        flags.put("DNSSEC", "NOT AVAILABLE");
        result.put("checks", flags);
        result.put("records", records);
        return result;
    }

    public JSONObject headers(String target) throws Exception {
        FetchResult fetch = fetch(normalizeUrl(target));
        JSONObject result = fetch.toJson();
        result.put("securityHeaders", securityHeaders(fetch.headers));
        return result;
    }

    public JSONObject redirects(String target) throws Exception {
        FetchResult fetch = fetch(normalizeUrl(target));
        JSONObject result = new JSONObject();
        result.put("requestedUrl", target);
        result.put("finalUrl", fetch.finalUrl);
        result.put("count", fetch.redirects.length());
        result.put("chain", fetch.redirects);
        result.put("status", fetch.statusCode);
        return result;
    }

    public JSONObject tech(String target) throws Exception {
        FetchResult fetch = fetch(normalizeUrl(target));
        return technology(fetch.headers, fetch.body);
    }

    public JSONObject tls(String target) throws Exception {
        String url = normalizeUrl(target);
        requireHttpUrl(url);
        JSONObject result = new JSONObject();
        if (!url.startsWith("https://")) {
            result.put("status", "not_applicable");
            result.put("message", "TLS is only available for HTTPS targets.");
            return result;
        }
        HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
        configure(connection);
        connection.setInstanceFollowRedirects(false);
        try {
            int code = connection.getResponseCode();
            result.put("status", "valid");
            result.put("httpStatus", code);
            result.put("cipherSuite", connection.getCipherSuite());
            Certificate[] certificates = connection.getServerCertificates();
            if (certificates.length > 0 && certificates[0] instanceof X509Certificate) {
                X509Certificate certificate = (X509Certificate) certificates[0];
                result.put("subject", certificate.getSubjectX500Principal().getName());
                result.put("issuer", certificate.getIssuerX500Principal().getName());
                result.put("validFrom", certificate.getNotBefore().toString());
                result.put("validUntil", certificate.getNotAfter().toString());
                result.put("serial", certificate.getSerialNumber().toString(16));
                result.put("san", certificate.getSubjectAlternativeNames() == null ? 0 : certificate.getSubjectAlternativeNames().size());
            }
        } finally {
            connection.disconnect();
        }
        return result;
    }

    public JSONObject reputation(String rawDomain) throws Exception {
        String domain = normalizeDomain(rawDomain);
        validatePublicHost(domain);
        JSONArray providers = new JSONArray();
        providers.put(virusTotal(domain));
        providers.put(urlhaus(domain));
        providers.put(googleSafeBrowsing(domain));
        JSONObject result = new JSONObject();
        result.put("domain", domain);
        result.put("providers", providers);
        return result;
    }

    public static String normalizeUrl(String input) throws Exception {
        if (input == null || input.trim().isEmpty()) throw new IllegalArgumentException("Target is empty");
        String raw = input.trim();
        if (!raw.matches("^[A-Za-z][A-Za-z0-9+.-]*://.*$")) raw = "https://" + raw;
        URI uri = new URI(raw);
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.US);
        if (!("http".equals(scheme) || "https".equals(scheme))) throw new IllegalArgumentException("Only HTTP and HTTPS are supported");
        if (uri.getUserInfo() != null) throw new IllegalArgumentException("User-info URLs are not allowed");
        if (uri.getHost() == null || uri.getHost().isEmpty()) throw new IllegalArgumentException("URL host is missing");
        if (uri.getPort() > 65535) throw new IllegalArgumentException("Invalid port");
        URI clean = new URI(scheme, null, uri.getHost(), uri.getPort(),
                uri.getPath() == null || uri.getPath().isEmpty() ? "/" : uri.getPath(), uri.getQuery(), null);
        return clean.toString();
    }

    public static String normalizeDomain(String input) {
        if (input == null || input.trim().isEmpty()) throw new IllegalArgumentException("Domain is empty");
        String value = input.trim().toLowerCase(Locale.US);
        if (value.startsWith("http://") || value.startsWith("https://")) {
            try { value = new URL(value).getHost(); } catch (Exception e) { throw new IllegalArgumentException("Invalid domain"); }
        }
        while (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        if (value.isEmpty() || value.contains("/") || value.contains(" ")) throw new IllegalArgumentException("Invalid domain");
        return value;
    }

    private FetchResult fetch(String initial) throws Exception {
        String current = normalizeUrl(initial);
        JSONArray redirects = new JSONArray();
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            requireHttpUrl(current);
            HttpURLConnection connection = (HttpURLConnection) new URL(current).openConnection();
            configure(connection);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("GET");
            int status;
            Map<String, String> headers;
            String body;
            try {
                status = connection.getResponseCode();
                headers = flattenHeaders(connection.getHeaderFields());
                String location = connection.getHeaderField("Location");
                if (status >= 300 && status < 400 && location != null && hop < MAX_REDIRECTS) {
                    String next = normalizeUrl(new URL(new URL(current), location).toString());
                    requireHttpUrl(next);
                    JSONObject step = new JSONObject();
                    step.put("from", current);
                    step.put("to", next);
                    step.put("status", status);
                    redirects.put(step);
                    connection.disconnect();
                    current = next;
                    continue;
                }
                body = readLimited(status >= 400 ? connection.getErrorStream() : connection.getInputStream(), MAX_BODY_BYTES);
            } finally {
                connection.disconnect();
            }
            return new FetchResult(initial, current, status, headers, body, redirects);
        }
        throw new IllegalStateException("Too many redirects; scan stopped safely");
    }

    private JSONArray doh(String domain, String type) throws Exception {
        String endpoint = "https://dns.google/resolve?name=" + URLEncoder.encode(domain, "UTF-8") + "&type=" + type;
        HttpURLConnection connection = (HttpURLConnection) new URL(endpoint).openConnection();
        configure(connection);
        connection.setRequestProperty("Accept", "application/dns-json");
        try {
            int status = connection.getResponseCode();
            String body = readLimited(status >= 400 ? connection.getErrorStream() : connection.getInputStream(), 65536);
            if (status < 200 || status >= 300) throw new IllegalStateException("DNS provider returned HTTP " + status);
            JSONObject root = new JSONObject(body);
            JSONArray answer = root.optJSONArray("Answer");
            JSONArray values = new JSONArray();
            if (answer != null) {
                for (int i = 0; i < answer.length(); i++) {
                    JSONObject record = answer.optJSONObject(i);
                    if (record != null) values.put(record.optString("data", ""));
                }
            }
            return values;
        } finally {
            connection.disconnect();
        }
    }

    private JSONObject technology(Map<String, String> headers, String body) {
        String content = body == null ? "" : body.toLowerCase(Locale.US);
        JSONObject result = new JSONObject();
        JSONArray technologies = new JSONArray();
        String server = header(headers, "server");
        String powered = header(headers, "x-powered-by");
        if (!server.isEmpty()) technologies.put(server);
        if (!powered.isEmpty()) technologies.put(powered);
        addIf(content.contains("wp-content") || content.contains("wordpress"), technologies, "WordPress");
        addIf(content.contains("drupal-settings-json") || content.contains("/sites/default/"), technologies, "Drupal");
        addIf(content.contains("_next/static") || content.contains("next.js"), technologies, "Next.js");
        addIf(content.contains("react") || content.contains("data-reactroot"), technologies, "React");
        addIf(content.contains("vue") || content.contains("data-v-") , technologies, "Vue.js");
        addIf(content.contains("ng-version") || content.contains("angular"), technologies, "Angular");
        addIf(content.contains("jquery"), technologies, "jQuery");
        addIf(content.contains("bootstrap"), technologies, "Bootstrap");
        addIf(!header(headers, "cf-ray").isEmpty() || server.toLowerCase(Locale.US).contains("cloudflare"), technologies, "Cloudflare");
        addIf(!header(headers, "x-cache").isEmpty() || !header(headers, "via").isEmpty(), technologies, "HTTP cache/CDN");
        try {
            result.put("technologies", technologies);
            result.put("server", server);
            result.put("poweredBy", powered);
        } catch (Exception ignored) { }
        return result;
    }

    private JSONObject securityHeaders(Map<String, String> headers) {
        JSONObject result = new JSONObject();
        String[] names = {"strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"};
        for (String name : names) {
            String value = header(headers, name);
            try { result.put(name, value.isEmpty() ? "missing" : value); } catch (Exception ignored) { }
        }
        return result;
    }

    private JSONObject virusTotal(String domain) {
        String key = settings.getString("provider_virustotal", "").trim();
        if (key.isEmpty()) return providerState("VirusTotal", "not_configured", "Add an API key in Settings");
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL("https://www.virustotal.com/api/v3/domains/" + URLEncoder.encode(domain, "UTF-8")).openConnection();
            configure(connection);
            connection.setRequestProperty("x-apikey", key);
            int status = connection.getResponseCode();
            String body = readLimited(status >= 400 ? connection.getErrorStream() : connection.getInputStream(), 65536);
            connection.disconnect();
            JSONObject root = new JSONObject(body);
            JSONObject data = root.optJSONObject("data");
            JSONObject attributes = data == null ? null : data.optJSONObject("attributes");
            JSONObject stats = attributes == null ? null : attributes.optJSONObject("last_analysis_stats");
            JSONObject out = providerState("VirusTotal", status >= 200 && status < 300 ? "ok" : "error", "");
            if (stats != null) out.put("lastAnalysisStats", stats);
            return out;
        } catch (Exception e) { return providerState("VirusTotal", "error", safeMessage(e)); }
    }

    private JSONObject urlhaus(String domain) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL("https://urlhaus-api.abuse.ch/v1/host/").openConnection();
            configure(connection);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            try (OutputStream output = connection.getOutputStream()) {
                output.write(("host=" + URLEncoder.encode(domain, "UTF-8")).getBytes(StandardCharsets.UTF_8));
            }
            int status = connection.getResponseCode();
            String body = readLimited(status >= 400 ? connection.getErrorStream() : connection.getInputStream(), 65536);
            connection.disconnect();
            JSONObject root = new JSONObject(body);
            JSONObject out = providerState("URLhaus", status >= 200 && status < 300 ? "ok" : "error", root.optString("query_status", ""));
            out.put("urls", root.optInt("urls", 0));
            return out;
        } catch (Exception e) { return providerState("URLhaus", "error", safeMessage(e)); }
    }

    private JSONObject googleSafeBrowsing(String domain) {
        String key = settings.getString("provider_google", "").trim();
        if (key.isEmpty()) return providerState("Google Safe Browsing", "not_configured", "Add an API key in Settings");
        try {
            URL url = new URL("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + URLEncoder.encode(key, "UTF-8"));
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            configure(connection);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            JSONObject payload = new JSONObject();
            JSONObject client = new JSONObject(); client.put("clientId", "trace"); client.put("clientVersion", "1.0.0");
            payload.put("client", client);
            JSONObject info = new JSONObject();
            info.put("threatTypes", new JSONArray(Arrays.asList("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")));
            info.put("platformTypes", new JSONArray(Arrays.asList("ANY_PLATFORM")));
            info.put("threatEntryTypes", new JSONArray(Arrays.asList("URL")));
            info.put("threatEntries", new JSONArray().put(new JSONObject().put("url", "https://" + domain + "/")));
            payload.put("threatInfo", info);
            try (OutputStream output = connection.getOutputStream()) { output.write(payload.toString().getBytes(StandardCharsets.UTF_8)); }
            int status = connection.getResponseCode();
            String body = readLimited(status >= 400 ? connection.getErrorStream() : connection.getInputStream(), 65536);
            connection.disconnect();
            JSONObject out = providerState("Google Safe Browsing", status >= 200 && status < 300 ? "ok" : "error", "");
            out.put("matches", body.isEmpty() ? 0 : new JSONObject(body).optJSONArray("matches") == null ? 0 : new JSONObject(body).optJSONArray("matches").length());
            return out;
        } catch (Exception e) { return providerState("Google Safe Browsing", "error", safeMessage(e)); }
    }

    private JSONObject ipIntelligence(String host) throws Exception {
        JSONObject out = new JSONObject(); JSONArray addresses = new JSONArray();
        for (InetAddress address : InetAddress.getAllByName(host)) {
            JSONObject item = new JSONObject();
            item.put("address", address.getHostAddress());
            item.put("reverseDns", address.getCanonicalHostName());
            item.put("family", address.getAddress().length == 16 ? "IPv6" : "IPv4");
            item.put("scope", isBlocked(address) ? "BLOCKED" : "PUBLIC");
            addresses.put(item);
        }
        out.put("host", host); out.put("addresses", addresses); out.put("asn", "UNKNOWN"); out.put("organization", "UNKNOWN");
        return out;
    }

    private JSONObject domainIntelligence(String domain) {
        JSONObject out = new JSONObject();
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL("https://rdap.org/domain/" + URLEncoder.encode(domain, "UTF-8")).openConnection();
            configure(connection); int status = connection.getResponseCode();
            String body = readLimited(status >= 400 ? connection.getErrorStream() : connection.getInputStream(), 131072);
            connection.disconnect();
            out.put("domain", domain); out.put("source", "RDAP"); out.put("status", status >= 200 && status < 300 ? "AVAILABLE" : "UNAVAILABLE");
            if (!body.isEmpty() && status >= 200 && status < 300) {
                JSONObject root = new JSONObject(body); out.put("registrar", root.optJSONArray("entities") == null ? "UNKNOWN" : "SEE_ENTITIES");
                out.put("events", root.optJSONArray("events") == null ? new JSONArray() : root.optJSONArray("events"));
                out.put("nameservers", root.optJSONArray("nameservers") == null ? new JSONArray() : root.optJSONArray("nameservers"));
            }
        } catch (Exception e) { try { out.put("domain", domain); out.put("status", "UNAVAILABLE"); out.put("reason", safeMessage(e)); } catch (Exception ignored) {} }
        return out;
    }

    private static JSONObject providerState(String provider, String status, String detail) {
        JSONObject out = new JSONObject();
        try { out.put("provider", provider); out.put("status", status); if (!detail.isEmpty()) out.put("detail", detail); } catch (Exception ignored) { }
        return out;
    }

    private static void configure(URLConnection connection) {
        connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
        connection.setReadTimeout(READ_TIMEOUT_MS);
        connection.setRequestProperty("User-Agent", "TRACE/1.0 (local security research)");
        connection.setRequestProperty("Accept", "text/html,application/json;q=0.9,*/*;q=0.1");
    }

    private static String readLimited(InputStream input, int maxBytes) throws Exception {
        if (input == null) return "";
        try (InputStream stream = input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int count;
            while (total < maxBytes && (count = stream.read(buffer, 0, Math.min(buffer.length, maxBytes - total))) != -1) {
                output.write(buffer, 0, count);
                total += count;
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static Map<String, String> flattenHeaders(Map<String, List<String>> raw) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : raw.entrySet()) {
            if (entry.getKey() == null) continue;
            out.put(entry.getKey().toLowerCase(Locale.US), String.join(", ", entry.getValue()));
        }
        return out;
    }

    private static String header(Map<String, String> headers, String name) {
        String value = headers.get(name.toLowerCase(Locale.US));
        return value == null ? "" : value;
    }

    private static void addIf(boolean condition, JSONArray list, String value) { if (condition && !contains(list, value)) list.put(value); }
    private static boolean contains(JSONArray array, String value) { for (int i = 0; i < array.length(); i++) if (value.equals(array.optString(i))) return true; return false; }

    private static void requireHttpUrl(String url) throws Exception {
        URI uri = new URI(url);
        if (!("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) throw new IllegalArgumentException("Only HTTP and HTTPS are supported");
        validatePublicHost(uri.getHost());
    }

    static void validatePublicHost(String host) throws Exception {
        if (host == null || host.isEmpty()) throw new IllegalArgumentException("Host is missing");
        String ascii = IDN.toASCII(host).toLowerCase(Locale.US);
        if (ascii.equals("localhost") || ascii.endsWith(".localhost") || ascii.endsWith(".local") || ascii.endsWith(".internal") || ascii.endsWith(".intranet") || ascii.endsWith(".lan") || ascii.endsWith(".home.arpa")) {
            throw new SecurityException("Internal hostnames are blocked");
        }
        InetAddress[] addresses = InetAddress.getAllByName(ascii);
        if (addresses.length == 0) throw new SecurityException("Host did not resolve");
        for (InetAddress address : addresses) {
            if (isBlocked(address)) throw new SecurityException("Private, loopback, link-local, or internal address is blocked");
        }
    }

    private static boolean isBlocked(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress() || address.isMulticastAddress()) return true;
        if (bytes.length == 16 && (bytes[0] & 0xff) >= 0xfc && (bytes[0] & 0xff) <= 0xfd) return true;
        if (bytes.length == 4) {
            int a = bytes[0] & 0xff, b = bytes[1] & 0xff;
            return a == 0 || a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168);
        }
        return false;
    }

    private static String safeMessage(Exception e) { return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(); }

    private static final class FetchResult {
        final String requestedUrl, finalUrl, body;
        final int statusCode;
        final Map<String, String> headers;
        final JSONArray redirects;
        FetchResult(String requestedUrl, String finalUrl, int statusCode, Map<String, String> headers, String body, JSONArray redirects) {
            this.requestedUrl = requestedUrl; this.finalUrl = finalUrl; this.statusCode = statusCode; this.headers = headers; this.body = body; this.redirects = redirects;
        }
        JSONObject toJson() {
            JSONObject out = new JSONObject();
            try { out.put("requestedUrl", requestedUrl); out.put("finalUrl", finalUrl); out.put("statusCode", statusCode); out.put("headers", new JSONObject(headers)); } catch (Exception ignored) { }
            return out;
        }
    }
}
