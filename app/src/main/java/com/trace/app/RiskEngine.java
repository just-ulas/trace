package com.trace.app;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Locale;

/** Deterministic, explainable risk scoring; it never claims certainty. */
public final class RiskEngine {
    private RiskEngine() {}

    public static JSONObject evaluate(JSONObject evidence) {
        JSONArray findings = new JSONArray();
        int score = 0;
        score += addMissingHeaders(evidence, findings);
        score += addRedirectFinding(evidence, findings);
        score += addPhishingFindings(evidence, findings);
        score += addTlsFinding(evidence, findings);
        score += addContentFindings(evidence, findings);
        String severity = score >= 70 ? "HIGH" : score >= 35 ? "MEDIUM" : score > 0 ? "LOW" : "INFO";
        String confidence = findings.length() >= 3 ? "HIGH" : findings.length() > 0 ? "MEDIUM" : "LOW";
        JSONObject result = new JSONObject();
        try {
            result.put("severity", severity);
            result.put("confidence", confidence);
            result.put("score", score);
            result.put("findings", findings);
            result.put("disclaimer", "Heuristic assessment; UNKNOWN is not SAFE and SUSPICIOUS is not MALWARE.");
        } catch (Exception ignored) { }
        return result;
    }

    private static int addMissingHeaders(JSONObject evidence, JSONArray findings) {
        JSONObject headers = evidence.optJSONObject("securityHeaders");
        if (headers == null) return 0;
        int score = 0;
        String[] names = {"content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options"};
        for (String name : names) {
            if ("missing".equalsIgnoreCase(headers.optString(name, "missing"))) {
                add(findings, "LOW", "MEDIUM", "HTTP", name, "Security header is missing", "The response does not advertise this browser security control.");
                score += "content-security-policy".equals(name) ? 12 : 6;
            }
        }
        return score;
    }

    private static int addRedirectFinding(JSONObject evidence, JSONArray findings) {
        int count = evidence.optJSONArray("redirects") == null ? 0 : evidence.optJSONArray("redirects").length();
        if (count < 3) return 0;
        add(findings, count >= 6 ? "MEDIUM" : "LOW", "MEDIUM", "HTTP", "redirects", "Redirect chain contains " + count + " hops", "Long chains make destination verification harder.");
        return count >= 6 ? 20 : 8;
    }

    private static int addPhishingFindings(JSONObject evidence, JSONArray findings) {
        JSONObject content = evidence.optJSONObject("content");
        if (content == null) return 0;
        int score = 0;
        if (content.optBoolean("hasPasswordField")) {
            add(findings, "INFO", "MEDIUM", "CONTENT", "password-field", "Page contains a password field", "Credential collection is observable; this is not proof of phishing.");
        }
        if (content.optBoolean("crossOriginFormAction")) {
            add(findings, "HIGH", "HIGH", "CONTENT", "cross-origin-form", "Form posts to another origin", "Cross-origin credential submission deserves review."); score += 35;
        }
        if (content.optBoolean("hasSuspiciousPath")) {
            add(findings, "MEDIUM", "MEDIUM", "CONTENT", "suspicious-path", "URL path matches a suspicious pattern", "A path heuristic matched; manual verification is required."); score += 18;
        }
        if (content.optBoolean("hasIframe")) {
            add(findings, "LOW", "LOW", "CONTENT", "iframe", "Embedded iframe detected", "Iframes are common but can obscure content provenance."); score += 3;
        }
        return score;
    }

    private static int addTlsFinding(JSONObject evidence, JSONArray findings) {
        JSONObject tls = evidence.optJSONObject("tls");
        if (tls == null || "not_applicable".equals(tls.optString("status"))) return 0;
        String status = tls.optString("status", "unknown");
        if (!"valid".equalsIgnoreCase(status)) {
            add(findings, "MEDIUM", "HIGH", "TLS", "certificate", "TLS validation returned " + status, "Certificate evidence could not be validated.");
            return 20;
        }
        return 0;
    }

    private static int addContentFindings(JSONObject evidence, JSONArray findings) {
        JSONObject content = evidence.optJSONObject("content");
        if (content == null) return 0;
        int score = 0;
        if (content.optBoolean("excessiveUrlEncoding")) {
            add(findings, "LOW", "LOW", "CONTENT", "encoded-url", "Excessive URL encoding detected", "Encoding can be benign but is worth reviewing in context."); score += 5;
        }
        if (content.optBoolean("mixedContent")) {
            add(findings, "MEDIUM", "HIGH", "CONTENT", "mixed-content", "HTTPS page references HTTP resources", "Mixed content can weaken transport security."); score += 15;
        }
        return score;
    }

    private static void add(JSONArray findings, String severity, String confidence, String source, String code, String reason, String evidence) {
        JSONObject finding = new JSONObject();
        try {
            finding.put("severity", severity);
            finding.put("confidence", confidence);
            finding.put("source", source);
            finding.put("indicator", code);
            finding.put("reason", reason);
            finding.put("evidence", evidence);
            finding.put("timestamp", System.currentTimeMillis());
            findings.put(finding);
        } catch (Exception ignored) { }
    }
}
