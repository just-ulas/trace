package com.trace.pc;

import com.trace.core.TraceCore;
import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

public final class TracePc {
    private final CaseStore cases = new CaseStore();
    private final Set<String> watchlist = new LinkedHashSet<>();
    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(java.time.Duration.ofSeconds(8)).build();

    public static void main(String[] args) throws Exception {
        TracePc app = new TracePc();
        if (args.length == 0 || args[0].equalsIgnoreCase("gui")) { SwingUtilities.invokeLater(app::gui); return; }
        System.out.println(app.command(String.join(" ", args)));
    }

    String command(String line) throws Exception {
        String[] p = line.trim().split("\\s+", 2); String cmd = p[0].toLowerCase(Locale.ROOT); String arg = p.length > 1 ? p[1].trim() : "";
        return switch (cmd) {
            case "scan", "deep" -> scan(arg, true);
            case "quick" -> scan(arg, false);
            case "link" -> link(arg);
            case "file", "apk" -> file(arg);
            case "hash" -> hash(arg);
            case "case" -> cases.read(arg);
            case "history" -> cases.history();
            case "compare" -> compare(arg);
            case "report" -> report(arg);
            case "watch" -> { watchlist.add(arg); yield "WATCHED " + arg; }
            case "unwatch" -> { watchlist.remove(arg); yield "UNWATCHED " + arg; }
            case "watches" -> String.join("\n", watchlist);
            case "help" -> help();
            default -> "Unknown command. Try: trace help";
        };
    }

    private String scan(String target, boolean deep) throws Exception {
        URI start = TraceCore.normalizeUrl(target); List<Map<String,Object>> hops = new ArrayList<>(); URI current = start; HttpResponse<String> response = null;
        for (int i=0; i<8; i++) {
            validatePublic(current.getHost());
            HttpRequest req = HttpRequest.newBuilder(current).timeout(java.time.Duration.ofSeconds(12)).header("User-Agent", "TRACE/3.0 PC Security Intelligence").GET().build();
            try { response = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)); }
            catch (Exception e) { return evidenceError(target, start, e); }
            Map<String,Object> hop = new LinkedHashMap<>(); hop.put("from", current.toString()); hop.put("status", response.statusCode()); hop.put("host", current.getHost()); hop.put("https", current.getScheme().equalsIgnoreCase("https")); hop.put("timestamp", Instant.now().toString());
            String location = response.headers().firstValue("location").orElse("");
            if (response.statusCode() >= 300 && response.statusCode() < 400 && !location.isBlank()) {
                URI next = TraceCore.normalizeUrl(current.resolve(location).toString()); validatePublic(next.getHost()); hop.put("to", next.toString()); hop.put("crossOrigin", !next.getHost().equalsIgnoreCase(current.getHost())); hops.add(hop); current = next; continue;
            }
            hops.add(hop); break;
        }
        String body = response == null ? "" : response.body(); if (body.length() > 262144) body = body.substring(0,262144);
        String title = match(body, "(?is)<title[^>]*>(.*?)</title>"); String page = TraceCore.classifyPage(title, body, current);
        int score = 0; List<String> findings = new ArrayList<>();
        if (!hasHeader(response, "content-security-policy")) { score += 4; findings.add("HARDENING: missing content-security-policy"); }
        if (!hasHeader(response, "strict-transport-security") && current.getScheme().equals("https")) { score += 4; findings.add("HARDENING: missing strict-transport-security"); }
        if (body.matches("(?is).*<input[^>]+type=[\\\"']password.*")) findings.add("INFORMATIONAL: password field detected");
        String formActions = match(body, "(?is)<form[^>]+action=[\\\"']([^\\\"']+)"); if (!formActions.isBlank() && formActions.matches("(?i)https?://.*") && !formActions.contains(current.getHost())) { score += 35; findings.add("SUSPICIOUS: cross-origin form action"); }
        if (current.getHost().contains("xn--") || current.getPath().matches("(?i).*login|verify|secure|wallet.*")) { score += 18; findings.add("SUSPICIOUS: IDN or sensitive path heuristic"); }
        boolean unknown = response == null;
        String risk = TraceCore.riskLevel(score, false, unknown);
        String id = cases.save(target, start, current, page, risk, findings, hops, body, response);
        return formatEvidence(id, target, start, current, page, risk, findings, hops, response, body, deep);
    }

    private String link(String target) throws Exception {
        URI uri = TraceCore.normalizeUrl(target); Map<String,String> structure = TraceCore.linkStructure(uri); return "WHAT IS THIS LINK?\n" + structure + "\nPAGE TYPE: UNKNOWN until fetched\nUse: trace scan " + uri;
    }

    private String file(String path) throws Exception {
        Path p = Paths.get(path); if (!Files.isRegularFile(p)) return "UNAVAILABLE: file not found";
        byte[] data = Files.readAllBytes(p); if (data.length > 8_000_000) data = Arrays.copyOf(data, 8_000_000);
        String name=p.getFileName().toString().toLowerCase(Locale.ROOT); List<String> findings=new ArrayList<>();
        if (name.endsWith(".apk") || name.endsWith(".jar") || name.endsWith(".zip")) { try (java.util.zip.ZipInputStream z=new java.util.zip.ZipInputStream(new ByteArrayInputStream(data))) { java.util.zip.ZipEntry e; while((e=z.getNextEntry())!=null) if(e.getName().matches("(?i).*classes\\.dex|AndroidManifest.xml|lib/.*|\\.so$")) findings.add("ARTIFACT: "+e.getName()); } }
        String text = new String(data, StandardCharsets.ISO_8859_1); if (text.matches("(?s).*https?://.*")) findings.add("INDICATOR: embedded URL"); if (text.matches("(?s).*Runtime\\.getRuntime|powershell|cmd\\.exe|eval\\(.*")) findings.add("SUSPICIOUS: executable/script marker");
        return "MALWARE GUARD\nPATH: "+p.toAbsolutePath()+"\nSIZE: "+Files.size(p)+"\nSHA256: "+digest(p,"SHA-256")+"\nMD5: "+digest(p,"MD5")+"\nTYPE: "+probe(name,data)+"\nFINDINGS:\n- "+String.join("\n- ", findings.isEmpty()?List.of("NONE OBSERVED (static only)"):findings)+"\nSTATUS: UNKNOWN / static analysis only";
    }

    private String hash(String value) throws Exception { Path p=Paths.get(value); if(Files.isRegularFile(p)) return file(value); return "HASH LOOKUP\n"+cases.findHash(value)+"\nSource: local evidence only; public provider not configured"; }
    private String compare(String arg) throws Exception { String[] ids=arg.split("\\s+"); if(ids.length<2)return"Usage: compare CASE-A CASE-B"; return cases.compare(ids[0],ids[1]); }
    private String report(String id) throws Exception { return cases.report(id); }

    private void gui() {
        JFrame frame=new JFrame("TRACE 3.0 — Security Intelligence Workstation"); frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); frame.setSize(1100,720); frame.setLocationByPlatform(true);
        JTextArea out=new JTextArea(); out.setFont(new Font(Font.MONOSPACED,Font.PLAIN,14)); out.setBackground(new Color(8,12,15)); out.setForeground(new Color(215,230,221)); out.setCaretColor(Color.WHITE); out.setText("TRACE 3.0 / LOCAL-FIRST SECURITY INTELLIGENCE\nType a command or use the tabs.\n");
        JTextField input=new JTextField(); JButton run=new JButton("RUN"); JPanel command=new JPanel(new BorderLayout(8,8)); command.add(input,BorderLayout.CENTER); command.add(run,BorderLayout.EAST);
        JTabbedPane tabs=new JTabbedPane(); for(String tab:new String[]{"DASHBOARD","SCANNER","LINK INTELLIGENCE","CASES","HISTORY","WATCHLIST","FILES","REPORTS","EVIDENCE","SETTINGS"}) { JPanel panel=new JPanel(new BorderLayout()); JLabel l=new JLabel(tab+"  /  TRACE 3.0"); l.setBorder(BorderFactory.createEmptyBorder(20,20,10,20)); panel.add(l,BorderLayout.NORTH); tabs.addTab(tab,panel); }
        ActionListener action=e->{try{out.append("\n$ "+input.getText()+"\n"+command(input.getText())+"\n");input.setText("");}catch(Exception ex){out.append("\nERROR: "+ex.getMessage()+"\n");}}; run.addActionListener(action); input.addActionListener(action);
        frame.add(tabs,BorderLayout.NORTH); frame.add(new JScrollPane(out),BorderLayout.CENTER); frame.add(command,BorderLayout.SOUTH); frame.setVisible(true);
    }

    private static String help(){return "TRACE 3.0 PC COMMANDS\ntrace scan <url> | trace deep <url> | trace link <url> | trace file <path> | trace apk <path>\ntrace hash <hash> | trace case CASE-00001 | trace history | trace compare CASE-A CASE-B | trace report CASE-00001 | trace watch <target> | trace watches | trace gui";}
    private static void validatePublic(String host) throws Exception { if(host==null||host.isBlank()||host.equalsIgnoreCase("localhost")||host.endsWith(".local")||host.endsWith(".internal"))throw new SecurityException("Internal host blocked"); for(InetAddress a:InetAddress.getAllByName(host)) if(a.isAnyLocalAddress()||a.isLoopbackAddress()||a.isLinkLocalAddress()||a.isSiteLocalAddress()||a.isMulticastAddress())throw new SecurityException("Private or special-use address blocked"); }
    private static boolean hasHeader(HttpResponse<?> r,String name){return r!=null&&r.headers().map().keySet().stream().anyMatch(k->k.equalsIgnoreCase(name));}
    private static String match(String s,String re){Matcher m=Pattern.compile(re).matcher(s==null?"":s);return m.find()?m.groupCount()>0?m.group(1).trim():m.group().trim():"";}
    private static String probe(String n,byte[] d){if(n.endsWith(".apk"))return"APK";if(n.endsWith(".pdf")||new String(d,0,Math.min(5,d.length),StandardCharsets.ISO_8859_1).startsWith("%PDF"))return"PDF";if(n.endsWith(".exe"))return"EXE";if(n.endsWith(".html")||n.endsWith(".js"))return"WEB";return"BINARY/UNKNOWN";}
    private static String digest(Path p,String algo)throws Exception{MessageDigest md=MessageDigest.getInstance(algo);try(InputStream in=Files.newInputStream(p)){byte[] b=new byte[8192];int n;while((n=in.read(b))>0)md.update(b,0,n);}StringBuilder s=new StringBuilder();for(byte x:md.digest())s.append(String.format("%02x",x));return s.toString();}
    private static String evidenceError(String target,URI start,Exception e){return "UNKNOWN / UNAVAILABLE\nTARGET: "+target+"\nNORMALIZED: "+start+"\nREASON: "+e.getClass().getSimpleName()+"\nNo safe verdict was inferred.";}
    private static String formatEvidence(String id,String target,URI start,URI end,String page,String risk,List<String> findings,List<Map<String,Object>> hops,HttpResponse<String> r,String body,boolean deep){return "TRACE SECURITY EVIDENCE\nCASE: "+id+"\nORIGINAL URL: "+start+"\nFINAL DESTINATION: "+end+"\nPAGE TYPE: "+page+"\nRISK: "+risk+"\nSTATUS: "+(r==null?"UNKNOWN":r.statusCode())+"\nTITLE: "+match(body,"(?is)<title[^>]*>(.*?)</title>")+"\nREDIRECT HOPS: "+hops.size()+"\nFINDINGS:\n- "+String.join("\n- ",findings.isEmpty()?List.of("NONE OBSERVED"):findings)+"\n\nTIMELINE:\n"+hops+"\n\nEVIDENCE PROFILE: "+(deep?"DEEP":"QUICK")+"\nUNKNOWN is not SAFE; SUSPICIOUS is not MALWARE.";}

    static final class CaseStore { final Path dir=Paths.get(System.getProperty("user.home"),".trace","cases"); CaseStore(){try{Files.createDirectories(dir);}catch(IOException ignored){}}
        String save(String target,URI start,URI end,String page,String risk,List<String> findings,List<Map<String,Object>> hops,String body,HttpResponse<String> r)throws Exception{int n=(int)Files.list(dir).filter(x->x.getFileName().toString().endsWith(".trace")).count()+1;String id=String.format("CASE-%05d",n);String data="id="+id+"\ntarget="+target+"\noriginal="+start+"\nfinal="+end+"\npage="+page+"\nrisk="+risk+"\ntime="+Instant.now()+"\nfindings="+String.join(" | ",findings)+"\nredirects="+hops.size()+"\nbodyBytes="+body.length()+"\n";Files.writeString(dir.resolve(id+".trace"),data);return id;}
        String history()throws IOException{StringBuilder s=new StringBuilder("TRACE CASE HISTORY\n");try(var x=Files.list(dir).sorted()){x.forEach(p->{try{s.append(Files.readString(p)).append("\n");}catch(IOException ignored){}});}return s.toString();}
        String read(String id)throws IOException{Path p=dir.resolve(id.endsWith(".trace")?id:id+".trace");return Files.exists(p)?Files.readString(p):"Case not found: "+id;}
        String findHash(String h)throws IOException{try(var x=Files.list(dir)){return x.filter(p->{try{return Files.readString(p).contains(h);}catch(IOException e){return false;}}).map(p->p.getFileName().toString()).findFirst().orElse("UNKNOWN");}}
        String compare(String a,String b)throws IOException{return "COMPARE\nNEW/REMOVED/CHANGED/UNCHANGED\nA:\n"+read(a)+"\nB:\n"+read(b)+"\nEvidence fields: DNS IP TLS CERTIFICATE REDIRECT HEADERS CONTENT FORMS TECHNOLOGY RISK";}
        String report(String id)throws IOException{String data=read(id);Path p=dir.resolve(id+".html");Files.writeString(p,"<!doctype html><meta charset='utf-8'><title>TRACE "+id+"</title><style>body{background:#080c0f;color:#d7e6dd;font:14px monospace;padding:32px}pre{white-space:pre-wrap}</style><h1>TRACE SECURITY REPORT</h1><pre>"+data.replace("&","&amp;").replace("<","&lt;")+"</pre><p>UNKNOWN is not SAFE. Static report; evidence timestamped locally.</p>");return "REPORT: "+p.toAbsolutePath();}
    }
}
