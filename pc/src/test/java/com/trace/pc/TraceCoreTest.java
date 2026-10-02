package com.trace.pc;

import com.trace.core.Trace31;
import com.trace.core.TraceCore;
import java.net.URI;
import java.util.List;
import java.util.Map;

public final class TraceCoreTest {
    public static void main(String[] args) {
        if (!TraceCore.normalizeUrl("example.com").toString().equals("https://example.com/")) throw new AssertionError("normalization");
        if (!TraceCore.linkStructure(URI.create("https://xn--example-9za.com/a?next=https%3A%2F%2Fgithub.com")).get("punycode").equals("true")) throw new AssertionError("punycode");
        if (!TraceCore.classifyPage("Example Domain", "Welcome to this page", URI.create("https://example.com")).equals("UNKNOWN")) throw new AssertionError("conservative classification");
        if (!TraceCore.riskLevel(8, false, false).equals("HARDENING")) throw new AssertionError("hardening");
        if (!TraceCore.normalizeUrl("https://example.com/a?next=https%3A%2F%2Fgithub.com%2F").toString().contains("%3A%2F%2F")) throw new AssertionError("raw query preservation");
        if (!TraceCore.linkStructure(TraceCore.normalizeUrl("https://example.com/a?next=https%3A%2F%2Fgithub.com%2F")).get("nestedUrls").equals("true")) throw new AssertionError("nested URL detection");
        boolean blocked=false; try { TraceCore.normalizeUrl("http://localhost/"); } catch (IllegalArgumentException expected) { blocked=true; }
        if (!blocked) throw new AssertionError("SSRF policy");
        if (Trace31.languages().size() != 10) throw new AssertionError("10 languages");
        if (!Trace31.language("tr-TR").equals("tr")) throw new AssertionError("language normalization");
        if (!Trace31.verdict("UNKNOWN", 20, 0, 2, 1, List.of(), List.of()).verdict().equals(Trace31.Verdict.UNVERIFIED)) throw new AssertionError("unknown verdict");
        if (!Trace31.verdict("SUSPICIOUS", 80, 3, 0, 0, List.of("IDN"), List.of()).verdict().equals(Trace31.Verdict.SUSPICIOUS)) throw new AssertionError("suspicious verdict");
        if (!Trace31.verdict("HARDENING", 60, 2, 0, 0, List.of("HSTS"), List.of()).verdict().equals(Trace31.Verdict.HARDENING)) throw new AssertionError("hardening presentation");
        if (!Trace31.verdict("INFORMATIONAL", 50, 0, 0, 1, List.of(), List.of()).verdict().equals(Trace31.Verdict.UNVERIFIED)) throw new AssertionError("unavailable is not safe");
        if (Trace31.safeCode("python", "https://example.com/?token=SECRET", "https://example.com/", 200, Map.of()).contains("SECRET")) throw new AssertionError("redaction");
        if (Trace31.explainLink("https://a.example", "https://a.example", "https://b.example", 2, "LOGIN", true, false, false, true, 1).size() < 3) throw new AssertionError("link explain");
        System.out.println("TRACE CORE + TRACE 3.1 TESTS: PASS");
    }
}
