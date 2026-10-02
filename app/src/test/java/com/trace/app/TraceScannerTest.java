package com.trace.app;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

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
}
