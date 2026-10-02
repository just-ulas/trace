package com.trace.pc;

import com.trace.core.TraceCore;
import java.net.URI;

public final class TraceCoreTest {
    public static void main(String[] args) {
        if (!TraceCore.normalizeUrl("example.com").toString().equals("https://example.com/")) throw new AssertionError("normalization");
        if (!TraceCore.linkStructure(URI.create("https://xn--example-9za.com/a?next=https%3A%2F%2Fgithub.com")).get("punycode").equals("true")) throw new AssertionError("punycode");
        if (!TraceCore.classifyPage("Example Domain", "Welcome to this page", URI.create("https://example.com")).equals("UNKNOWN")) throw new AssertionError("conservative classification");
        if (!TraceCore.riskLevel(8, false, false).equals("HARDENING")) throw new AssertionError("hardening");
        boolean blocked=false; try { TraceCore.normalizeUrl("http://localhost/"); } catch (IllegalArgumentException expected) { blocked=true; }
        if (!blocked) throw new AssertionError("SSRF policy");
        System.out.println("TRACE CORE TESTS: PASS");
    }
}
