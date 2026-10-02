package com.trace.core;

import java.net.IDN;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Shared, dependency-free intelligence primitives used by Android and PC clients. */
public final class TraceCore {
    private static final Pattern INTERNAL = Pattern.compile("(^localhost$|\\.local$|\\.internal$|\\.intranet$|\\.lan$|home\\.arpa$)", Pattern.CASE_INSENSITIVE);
    private TraceCore() {}

    public static URI normalizeUrl(String input) {
        if (input == null || input.trim().isEmpty()) throw new IllegalArgumentException("Target is empty");
        String raw = input.trim();
        if (!raw.matches("^[A-Za-z][A-Za-z0-9+.-]*://.*$")) raw = "https://" + raw;
        try {
            URI uri = URI.create(raw);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!(scheme.equals("http") || scheme.equals("https"))) throw new IllegalArgumentException("Only HTTP and HTTPS are supported");
            if (uri.getUserInfo() != null || uri.getHost() == null || uri.getHost().isBlank()) throw new IllegalArgumentException("Unsafe or invalid URL");
            if (uri.getPort() > 65535) throw new IllegalArgumentException("Invalid port");
            String host = uri.getHost().toLowerCase(Locale.ROOT);
            if (INTERNAL.matcher(host).find()) throw new IllegalArgumentException("Internal host is blocked");
            return new URI(scheme, null, host, uri.getPort(), uri.getPath() == null || uri.getPath().isBlank() ? "/" : uri.getPath(), uri.getQuery(), null);
        } catch (IllegalArgumentException e) { throw e; } catch (Exception e) { throw new IllegalArgumentException("Invalid URL", e); }
    }

    public static Map<String, String> linkStructure(URI uri) {
        Map<String, String> out = new LinkedHashMap<>();
        String host = uri.getHost() == null ? "" : uri.getHost();
        out.put("scheme", String.valueOf(uri.getScheme())); out.put("host", host);
        out.put("port", String.valueOf(uri.getPort() < 0 ? ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80) : uri.getPort()));
        out.put("path", uri.getPath() == null ? "/" : uri.getPath()); out.put("query", uri.getQuery() == null ? "" : uri.getQuery());
        out.put("fragment", uri.getFragment() == null ? "" : uri.getFragment());
        String[] labels = host.split("\\."); out.put("subdomain", labels.length > 2 ? String.join(".", java.util.Arrays.copyOf(labels, labels.length - 2)) : "");
        out.put("tld", labels.length == 0 ? "" : labels[labels.length - 1]); out.put("punycode", host.contains("xn--") ? "true" : "false");
        out.put("encoded", (uri.toString().contains("%") || uri.toString().contains("%2f")) ? "true" : "false");
        out.put("nestedUrls", uri.toString().matches(".*https?%3A.*|.*https?://.*https?://.*") ? "true" : "false");
        out.put("downloadIndicator", uri.getPath() != null && uri.getPath().matches("(?i).*\\.(apk|exe|msi|dmg|zip|jar|pdf|docx?)($|[?]).*") ? "true" : "false");
        return out;
    }

    public static String classifyPage(String title, String body, URI uri) {
        String text = ((title == null ? "" : title) + " " + (body == null ? "" : body)).toLowerCase(Locale.ROOT);
        if (text.matches(".*(sign[ -]?in|log[ -]?in|password|username).*")) return "LOGIN";
        if (text.matches(".*(checkout|payment|credit card|billing).*")) return "PAYMENT";
        if (text.matches(".*(search|query|find results).*")) return "SEARCH";
        if (text.matches(".*(download|installer|apk|\\.exe|\\.dmg).*")) return "DOWNLOAD";
        if (text.matches(".*(news|breaking|press release).*")) return "NEWS";
        if (text.matches(".*(blog|article|author).*")) return "BLOG";
        if (text.matches(".*(shop|store|cart|product).*")) return "STORE";
        if (text.matches(".*(facebook|instagram|social|follow us).*")) return "SOCIAL";
        return "UNKNOWN";
    }

    public static String riskLevel(int score, boolean knownThreat, boolean unknown) {
        if (knownThreat) return "THREAT";
        if (unknown) return "UNKNOWN";
        if (score >= 35) return "SUSPICIOUS";
        if (score > 0) return "HARDENING";
        return "INFORMATIONAL";
    }
}
