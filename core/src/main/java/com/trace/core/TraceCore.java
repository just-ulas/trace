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
            String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
            StringBuilder canonical = new StringBuilder(scheme).append("://").append(host);
            if (uri.getPort() >= 0) canonical.append(':').append(uri.getPort());
            canonical.append(path);
            if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) canonical.append('?').append(uri.getRawQuery());
            return URI.create(canonical.toString());
        } catch (IllegalArgumentException e) { throw e; } catch (Exception e) { throw new IllegalArgumentException("Invalid URL", e); }
    }

    public static Map<String, String> linkStructure(URI uri) {
        Map<String, String> out = new LinkedHashMap<>();
        String host = uri.getHost() == null ? "" : uri.getHost();
        out.put("scheme", String.valueOf(uri.getScheme())); out.put("host", host);
        out.put("port", String.valueOf(uri.getPort() < 0 ? ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80) : uri.getPort()));
        out.put("path", uri.getRawPath() == null ? "/" : uri.getRawPath()); out.put("query", uri.getRawQuery() == null ? "" : uri.getRawQuery());
        out.put("fragment", uri.getFragment() == null ? "" : uri.getFragment());
        String[] labels = host.split("\\."); out.put("subdomain", labels.length > 2 ? String.join(".", java.util.Arrays.copyOf(labels, labels.length - 2)) : "");
        out.put("tld", labels.length == 0 ? "" : labels[labels.length - 1]); out.put("punycode", host.contains("xn--") ? "true" : "false");
        String raw = uri.toString();
        out.put("encoded", raw.matches("(?i).*%[0-9a-f]{2}.*") ? "true" : "false");
        out.put("nestedUrls", raw.matches("(?i).*https?%3a.*|.*https?://.*https?://.*") ? "true" : "false");
        out.put("downloadIndicator", uri.getPath() != null && uri.getPath().matches("(?i).*\\.(apk|exe|msi|dmg|zip|jar|pdf|docx?)($|[?]).*") ? "true" : "false");
        return out;
    }

    public static String classifyPage(String title, String body, URI uri) {
        String html = body == null ? "" : body;
        String visible = html.replaceAll("(?is)<(script|style|noscript|svg)[^>]*>.*?</\\1>", " ")
                .replaceAll("(?is)<[^>]+>", " ").replaceAll("&(?:nbsp|amp|quot|lt|gt);", " ")
                .replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
        String heading = html.replaceAll("(?is)<h[1-3][^>]*>(.*?)</h[1-3]>", " $1 ").toLowerCase(Locale.ROOT);
        String titleText = (title == null ? "" : title).toLowerCase(Locale.ROOT);
        String path = uri == null || uri.getPath() == null ? "" : uri.getPath().toLowerCase(Locale.ROOT);
        boolean passwordInput = html.matches("(?is).*<input[^>]+type\\s*=\\s*[\\\"']?password.*");
        boolean form = html.matches("(?is).*<form\\b.*");
        if (passwordInput && (containsAny(visible + " " + heading + " " + titleText, "sign in", "signin", "log in", "login", "account", "password", "username") || path.matches(".*(login|signin|account|auth|verify).*"))) return "LOGIN";
        if (form && containsAny(visible + " " + heading + " " + titleText, "checkout", "payment", "credit card", "billing", "order", "cart")) return "PAYMENT";
        if (html.matches("(?is).*<input[^>]+type\\s*=\\s*[\\\"']?(search|text).*|.*role\\s*=\\s*[\\\"']search.*") && containsAny(visible + " " + heading + " " + titleText, "search", "results", "find")) return "SEARCH";
        if (path.matches(".*\\.(apk|exe|msi|dmg|zip|jar|pdf|docx?)(\\?.*)?$") || html.matches("(?is).*\\b(download|installer)\\b.*")) return "DOWNLOAD";
        if (containsAny(heading + " " + titleText, "news", "breaking", "press release") || html.matches("(?is).*<article\\b.*")) return "NEWS";
        if (html.matches("(?is).*<article\\b.*") || containsAny(heading + " " + titleText, "blog", "article", "author", "read more")) return "BLOG";
        if (containsAny(visible + " " + heading + " " + titleText, "shop", "store", "cart", "product", "add to cart")) return "STORE";
        if (containsAny(visible + " " + heading + " " + titleText, "facebook", "instagram", "social", "follow us")) return "SOCIAL";
        return "UNKNOWN";
    }

    private static boolean containsAny(String text, String... terms) {
        for (String term : terms) if (text.contains(term)) return true;
        return false;
    }

    public static String riskLevel(int score, boolean knownThreat, boolean unknown) {
        if (knownThreat) return "THREAT";
        if (unknown) return "UNKNOWN";
        if (score >= 35) return "SUSPICIOUS";
        if (score > 0) return "HARDENING";
        return "INFORMATIONAL";
    }
}
