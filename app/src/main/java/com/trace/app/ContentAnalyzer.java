package com.trace.app;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Conservative static HTML inspection. Scripts are never executed. */
public final class ContentAnalyzer {
    private ContentAnalyzer() {}

    public static JSONObject analyze(String url, String body) {
        String html = body == null ? "" : body;
        String lower = html.toLowerCase(Locale.US);
        JSONObject out = new JSONObject();
        JSONArray forms = new JSONArray();
        JSONArray scripts = new JSONArray();
        JSONArray externalResources = new JSONArray();
        try {
            URI origin = new URI(url);
            String host = origin.getHost() == null ? "" : origin.getHost().toLowerCase(Locale.US);
            String title = match(html, "(?is)<title[^>]*>(.*?)</title>");
            out.put("title", strip(title));
            String visible = html.replaceAll("(?is)<(script|style|noscript|svg)[^>]*>.*?</\\1>", " ").replaceAll("(?is)<[^>]+>", " ").replaceAll("\\s+", " ").trim();
            out.put("visibleTextChars", Math.min(visible.length(), 200000));
            out.put("headingCount", countMatches(html, "(?is)<h[1-6]\\b"));
            out.put("linkCount", countMatches(html, "(?is)<a\\b"));
            out.put("imageCount", countMatches(html, "(?is)<img\\b"));
            out.put("hasPasswordField", lower.matches("(?s).*<input[^>]+type\\s*=\\s*[\\\"']?password.*"));
            out.put("hasIframe", lower.contains("<iframe"));
            out.put("hasSuspiciousPath", origin.getPath() != null && origin.getPath().toLowerCase(Locale.US).matches(".*(login|verify|secure|account|update|wallet|signin|password|confirm).*"));
            out.put("excessiveUrlEncoding", count(lower, "%25") + count(lower, "%2f") + count(lower, "%3d") >= 5);
            out.put("mixedContent", "https".equalsIgnoreCase(origin.getScheme()) && lower.matches("(?s).*https?://[^\\\"' ]+.*") && lower.contains("http://"));
            Matcher formMatcher = Pattern.compile("(?is)<form\\b([^>]*)>(.*?)</form>").matcher(html);
            boolean crossOrigin = false;
            while (formMatcher.find() && forms.length() < 40) {
                String attrs = formMatcher.group(1);
                String action = attr(attrs, "action");
                boolean password = formMatcher.group(2).toLowerCase(Locale.US).contains("type=\"password\"") || formMatcher.group(2).toLowerCase(Locale.US).contains("type='password'");
                boolean foreign = false;
                try { if (!action.isEmpty()) { URI form = origin.resolve(action); foreign = form.getHost() != null && !form.getHost().equalsIgnoreCase(host); } } catch (Exception ignored) { }
                crossOrigin |= foreign && password;
                JSONObject f = new JSONObject(); f.put("action", action); f.put("passwordField", password); f.put("crossOrigin", foreign); forms.put(f);
            }
            Matcher scriptMatcher = Pattern.compile("(?is)<script\\b([^>]*)>").matcher(html);
            while (scriptMatcher.find() && scripts.length() < 80) scripts.put(attr(scriptMatcher.group(1), "src"));
            Matcher resourceMatcher = Pattern.compile("(?is)(?:src|href)\\s*=\\s*[\\\"']([^\\\"']+)").matcher(html);
            while (resourceMatcher.find() && externalResources.length() < 100) externalResources.put(resourceMatcher.group(1));
            out.put("forms", forms); out.put("scripts", scripts); out.put("externalResources", externalResources);
            out.put("crossOriginFormAction", crossOrigin);
            out.put("obfuscationIndicators", count(lower, "eval(") + count(lower, "atob(") + count(lower, "fromcharcode") + count(lower, "document.write"));
            out.put("downloadLinks", lower.contains("download") || lower.matches("(?s).*\\.(apk|exe|zip|js)(\\?|[\\\"']).*"));
        } catch (Exception ignored) { }
        return out;
    }

    private static String match(String input, String regex) { Matcher m = Pattern.compile(regex).matcher(input); return m.find() ? m.group(1) : ""; }
    private static String attr(String attrs, String name) { Matcher m = Pattern.compile("(?i)\\b" + name + "\\s*=\\s*[\\\"']([^\\\"']*)").matcher(attrs); return m.find() ? m.group(1) : ""; }
    private static String strip(String value) { return value == null ? "" : value.replaceAll("<[^>]+>", "").replaceAll("\\s+", " ").trim(); }
    private static int count(String text, String token) { int n=0, p=0; while ((p=text.indexOf(token,p)) >= 0) { n++; p += token.length(); } return n; }
    private static int countMatches(String text, String regex) { Matcher m = Pattern.compile(regex).matcher(text); int n=0; while (m.find()) n++; return n; }
}
