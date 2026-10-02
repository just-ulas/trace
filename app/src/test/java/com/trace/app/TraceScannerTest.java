package com.trace.app;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TraceScannerTest {
    @Test
    public void normalizesBareDomainToHttps() throws Exception {
        assertEquals("https://example.com/", TraceScanner.normalizeUrl("example.com"));
    }

    @Test
    public void preservesHttpAndPath() throws Exception {
        assertEquals("http://example.com/health?full=1", TraceScanner.normalizeUrl("http://example.com/health?full=1#fragment"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsUnsupportedScheme() throws Exception {
        TraceScanner.normalizeUrl("ftp://example.com/file");
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsUserInfo() throws Exception {
        TraceScanner.normalizeUrl("https://user:pass@example.com/");
    }

    @Test
    public void normalizesDomainInput() {
        assertEquals("example.com", TraceScanner.normalizeDomain("HTTPS://EXAMPLE.COM."));
    }

    @Test(expected = SecurityException.class)
    public void blocksLocalhost() throws Exception {
        TraceScanner.validatePublicHost("localhost");
    }

    @Test(expected = SecurityException.class)
    public void blocksPrivateIpv4() throws Exception {
        TraceScanner.validatePublicHost("192.168.1.1");
    }

    @Test
    public void contentAnalyzerFindsCrossOriginPasswordForm() {
        org.json.JSONObject content = ContentAnalyzer.analyze("https://example.com/login", "<title>Login</title><form action='https://other.test/collect'><input type='password'></form>");
        assertEquals(true, content.optBoolean("hasPasswordField"));
        assertEquals(true, content.optBoolean("crossOriginFormAction"));
    }

    @Test
    public void riskEngineExplainsMissingHeaders() throws Exception {
        org.json.JSONObject evidence = new org.json.JSONObject();
        evidence.put("securityHeaders", new org.json.JSONObject().put("content-security-policy", "missing"));
        org.json.JSONObject risk = RiskEngine.evaluate(evidence);
        assertEquals("LOW", risk.optString("severity"));
        assertTrue(risk.optJSONArray("findings").length() >= 1);
    }

    @Test
    public void graphContainsTargetAndRiskNodes() throws Exception {
        org.json.JSONObject evidence = new org.json.JSONObject().put("target", "example.com").put("risk", new org.json.JSONObject().put("severity", "INFO"));
        org.json.JSONObject graph = IntelligenceUtils.graph(evidence);
        assertEquals(2, graph.optJSONArray("nodes").length());
    }
}
