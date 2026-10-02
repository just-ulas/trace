package com.trace.core;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/** TRACE 3.1 presentation and integration primitives shared by Android and PC. */
public final class Trace31 {
    private Trace31() {}

    public enum Mode { BEGINNER, STANDARD, DEVELOPER }
    public enum SourceState { AVAILABLE, UNAVAILABLE, FAILED, STALE, NOT_QUERIED, LOCAL }
    public enum Verdict { RELIABLE, SUSPICIOUS, THREAT, UNVERIFIED }

    public record SourceDiagnostic(String name, SourceState state, String detail) {}
    public record Timing(String stage, long millis) {}
    public record VerdictCard(Verdict verdict, String label, String why, String action,
                              int confidence, int evidenceCount, int unknownCount,
                              List<String> reasons, List<String> findings) {}

    private static final List<String> LANGUAGES = List.of("tr", "en", "de", "es", "fr", "it", "pt", "ru", "ar", "zh");
    private static final Map<String, Map<String, String>> T = translations();

    public static List<String> languages() { return LANGUAGES; }
    public static String language(String requested) {
        if (requested == null || requested.isBlank()) return "en";
        String x = requested.toLowerCase(Locale.ROOT).replace('_','-');
        String base = x.substring(0, Math.min(2, x.length()));
        return LANGUAGES.contains(base) ? base : "en";
    }
    public static String text(String lang, String key) {
        Map<String,String> map = T.getOrDefault(language(lang), T.get("en"));
        return map.getOrDefault(key, T.get("en").getOrDefault(key, key));
    }

    public static VerdictCard verdict(String risk, int confidence, int evidenceCount, int unknownCount,
                                      int unavailableSources, List<String> reasons, List<String> findings) {
        String r = risk == null ? "UNKNOWN" : risk.toUpperCase(Locale.ROOT);
        Verdict v = switch (r) {
            case "THREAT" -> Verdict.THREAT;
            case "SUSPICIOUS" -> Verdict.SUSPICIOUS;
            case "INFORMATIONAL", "HARDENING" -> confidence >= 55 && evidenceCount > 0 ? Verdict.RELIABLE : Verdict.UNVERIFIED;
            default -> Verdict.UNVERIFIED;
        };
        if (unknownCount > evidenceCount && v != Verdict.THREAT) v = Verdict.UNVERIFIED;
        String label = switch (v) {
            case RELIABLE -> "RELIABLE / GÜVENİLİR GÖRÜNÜYOR";
            case SUSPICIOUS -> "SUSPICIOUS / ŞÜPHELİ";
            case THREAT -> "THREAT / TEHDİT BULGUSU";
            case UNVERIFIED -> "UNVERIFIED / GÜVENİLİRLİK DOĞRULANAMADI";
        };
        String why = switch (v) {
            case RELIABLE -> "Available evidence shows no clear malicious indicator. This is not a security guarantee.";
            case SUSPICIOUS -> "One or more heuristic or phishing indicators require review.";
            case THREAT -> "Evidence contains a threat-level indicator. Do not interact with the target.";
            case UNVERIFIED -> "The available evidence is insufficient to verify reliability; UNKNOWN is not SAFE.";
        };
        String action = switch (v) {
            case RELIABLE -> "Normal use shows no clear threat indicator, but remain cautious.";
            case SUSPICIOUS -> "Verify the domain before entering passwords or payment information.";
            case THREAT -> "Close the connection before interacting with this target.";
            case UNVERIFIED -> "The scan could not establish a security decision; do not infer safety.";
        };
        int capped = Math.max(0, Math.min(100, confidence));
        return new VerdictCard(v, label, why, action, capped, evidenceCount, unknownCount,
                reasons == null ? List.of() : List.copyOf(reasons), findings == null ? List.of() : List.copyOf(findings));
    }

    public static List<String> explainLink(String original, String normalized, String finalUrl,
                                           int redirects, String pageType, boolean login, boolean payment,
                                           boolean download, boolean nestedUrl, int externalDomains) {
        List<String> out = new ArrayList<>();
        if (redirects > 0) out.add("This link uses " + redirects + " redirect hop(s) before reaching its final destination.");
        if (finalUrl != null && original != null && !sameHost(original, finalUrl)) out.add("The final destination is on a different domain.");
        if (nestedUrl) out.add("The URL contains an embedded destination URL.");
        if (login) out.add("A password or login form was detected.");
        if (payment) out.add("Payment or billing language was detected.");
        if (download) out.add("A file download indicator was detected.");
        if (externalDomains > 0) out.add("The page references " + externalDomains + " external domain(s).");
        if (pageType != null && !pageType.equals("UNKNOWN")) out.add("This likely leads to a " + pageType.toLowerCase(Locale.ROOT) + " page.");
        if (out.isEmpty()) out.add("No high-signal link explanation was available from the collected evidence.");
        return out;
    }

    public static String safeCode(String language, String original, String finalUrl, int status, Map<String,String> headers) {
        String lang = language == null ? "curl" : language.toLowerCase(Locale.ROOT);
        String url = redact(original == null || original.isBlank() ? finalUrl : original);
        String safeFinal = redact(finalUrl == null ? url : finalUrl);
        String ua = headers == null ? "TRACE/3.1" : redact(headers.getOrDefault("user-agent", "TRACE/3.1"));
        return switch (lang) {
            case "python" -> "import requests\n\nresponse = requests.get(" + py(url) + ", headers={\"User-Agent\": " + py(ua) + "}, allow_redirects=False, timeout=12)\nprint(response.status_code)  # observed: " + status + "\nprint(response.headers.get('location'))\n";
            case "javascript", "js" -> "const response = await fetch(" + js(url) + ", { redirect: 'manual', headers: { 'User-Agent': " + js(ua) + " } });\nconsole.log(response.status); // observed: " + status + "\nconsole.log(response.headers.get('location'));\n";
            case "typescript", "ts" -> "const response: Response = await fetch(" + js(url) + ", { redirect: 'manual', headers: { 'User-Agent': " + js(ua) + " } });\nconsole.log(response.status); // observed: " + status + "\n";
            case "java" -> "var request = java.net.http.HttpRequest.newBuilder(java.net.URI.create(" + py(url) + ")).header(\"User-Agent\", " + py(ua) + ").GET().build();\nvar response = java.net.http.HttpClient.newHttpClient().send(request, java.net.http.HttpResponse.BodyHandlers.ofString());\nSystem.out.println(response.statusCode()); // observed: " + status + "\n";
            case "kotlin" -> "val request = java.net.http.HttpRequest.newBuilder(java.net.URI.create(" + py(url) + ")).header(\"User-Agent\", " + py(ua) + ").GET().build()\nval response = java.net.http.HttpClient.newHttpClient().send(request, java.net.http.HttpResponse.BodyHandlers.ofString())\nprintln(response.statusCode()) // observed: " + status + "\n";
            case "go" -> "req, _ := http.NewRequest(http.MethodGet, " + py(url) + ", nil)\nreq.Header.Set(\"User-Agent\", " + py(ua) + ")\nresp, err := http.DefaultClient.Do(req)\nif err != nil { panic(err) }\ndefer resp.Body.Close()\nfmt.Println(resp.Status) // observed: " + status + "\n";
            case "rust" -> "let response = reqwest::blocking::Client::new().get(" + py(url) + ").header(\"User-Agent\", " + py(ua) + ").send()?;\nprintln!(\"{}\", response.status()); // observed: " + status + "\n";
            case "powershell" -> "Invoke-WebRequest -Uri " + ps(url) + " -Headers @{ 'User-Agent' = " + ps(ua) + " } -MaximumRedirection 0 | Select-Object StatusCode, Headers\n# observed status: " + status + "\n";
            case "bash" -> "curl --silent --show-error --location --max-redirs 0 --connect-timeout 8 -A " + sh(ua) + " -D - -o /dev/null " + sh(url) + "\n# observed status: " + status + "\n";
            default -> "curl --silent --show-error --location --max-redirs 0 -A 'TRACE/3.1' -D - -o /dev/null " + sh(url) + "\n# observed status: " + status + "\n";
        };
    }

    public static String redact(String value) {
        if (value == null) return "";
        String x = value.replaceAll("(?i)(token|api[_-]?key|password|passwd|secret|authorization)=([^&\\s]+)", "$1=[REDACTED]");
        return x.replaceAll("(?i)Bearer\\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]").replaceAll("(?i)Cookie:\\s*[^\\r\\n]+", "Cookie: [REDACTED]");
    }

    private static boolean sameHost(String a, String b) { try { return Objects.equals(URI.create(a).getHost(), URI.create(b).getHost()); } catch (Exception e) { return false; } }
    private static String py(String x) { return "\"" + x.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }
    private static String js(String x) { return "'" + x.replace("\\", "\\\\").replace("'", "\\'") + "'"; }
    private static String sh(String x) { return "'" + x.replace("'", "'\\''") + "'"; }
    private static String ps(String x) { return "'" + x.replace("'", "''") + "'"; }

    private static Map<String, Map<String,String>> translations() {
        Map<String,Map<String,String>> all = new LinkedHashMap<>();
        all.put("en", map("general", "GENERAL RESULT", "why", "WHY?", "action", "WHAT SHOULD I DO?", "details", "VIEW TECHNICAL DETAILS", "settings", "SETTINGS", "mode", "MODE", "developer", "DEVELOPER MODE", "beginner", "BEGINNER MODE", "standard", "STANDARD MODE", "analyze", "ANALYZE", "target", "TARGET", "unknown", "RELIABILITY COULD NOT BE VERIFIED", "copy", "COPY", "code", "CODE / INTEGRATION", "sources", "SOURCE DIAGNOSTICS", "timing", "SCAN TIMING"));
        all.put("tr", map("general", "GENEL SONUÇ", "why", "NEDEN?", "action", "NE YAPMALIYIM?", "details", "TEKNİK DETAYLARI GÖR", "settings", "AYARLAR", "mode", "MOD", "developer", "GELİŞTİRİCİ MODU", "beginner", "BAŞLANGIÇ MODU", "standard", "STANDART MOD", "analyze", "ANALİZ ET", "target", "HEDEF", "unknown", "GÜVENİLİRLİK DOĞRULANAMADI", "copy", "KOPYALA", "code", "KOD / ENTEGRASYON", "sources", "KAYNAK DURUMLARI", "timing", "TARAMA SÜRESİ"));
        all.put("de", map("general", "ALLGEMEINES ERGEBNIS", "why", "WARUM?", "action", "WAS SOLL ICH TUN?", "details", "TECHNISCHE DETAILS", "settings", "EINSTELLUNGEN", "mode", "MODUS", "developer", "ENTWICKLERMODUS", "beginner", "ANFÄNGERMODUS", "standard", "STANDARDMODUS", "analyze", "ANALYSIEREN", "target", "ZIEL", "unknown", "ZUVERLÄSSIGKEIT NICHT BESTÄTIGT", "copy", "KOPIEREN", "code", "CODE / INTEGRATION", "sources", "QUELLSTATUS", "timing", "SCANZEIT"));
        all.put("es", map("general", "RESULTADO GENERAL", "why", "¿POR QUÉ?", "action", "¿QUÉ DEBO HACER?", "details", "VER DETALLES TÉCNICOS", "settings", "AJUSTES", "mode", "MODO", "developer", "MODO DESARROLLADOR", "beginner", "MODO PRINCIPIANTE", "standard", "MODO ESTÁNDAR", "analyze", "ANALIZAR", "target", "OBJETIVO", "unknown", "FIABILIDAD NO VERIFICADA", "copy", "COPIAR", "code", "CÓDIGO / INTEGRACIÓN", "sources", "FUENTES", "timing", "TIEMPO DE ESCANEO"));
        all.put("fr", map("general", "RÉSULTAT GÉNÉRAL", "why", "POURQUOI ?", "action", "QUE DOIS-JE FAIRE ?", "details", "DÉTAILS TECHNIQUES", "settings", "PARAMÈTRES", "mode", "MODE", "developer", "MODE DÉVELOPPEUR", "beginner", "MODE DÉBUTANT", "standard", "MODE STANDARD", "analyze", "ANALYSER", "target", "CIBLE", "unknown", "FIABILITÉ NON VÉRIFIÉE", "copy", "COPIER", "code", "CODE / INTÉGRATION", "sources", "SOURCES", "timing", "TEMPS D’ANALYSE"));
        all.put("it", map("general", "RISULTATO GENERALE", "why", "PERCHÉ?", "action", "COSA DEVO FARE?", "details", "DETTAGLI TECNICI", "settings", "IMPOSTAZIONI", "mode", "MODALITÀ", "developer", "MODALITÀ SVILUPPATORE", "beginner", "MODALITÀ PRINCIPIANTE", "standard", "MODALITÀ STANDARD", "analyze", "ANALIZZA", "target", "OBIETTIVO", "unknown", "AFFIDABILITÀ NON VERIFICATA", "copy", "COPIA", "code", "CODICE / INTEGRAZIONE", "sources", "FONTI", "timing", "TEMPO DI SCANSIONE"));
        all.put("pt", map("general", "RESULTADO GERAL", "why", "POR QUÊ?", "action", "O QUE DEVO FAZER?", "details", "VER DETALHES TÉCNICOS", "settings", "DEFINIÇÕES", "mode", "MODO", "developer", "MODO DE PROGRAMADOR", "beginner", "MODO INICIANTE", "standard", "MODO PADRÃO", "analyze", "ANALISAR", "target", "ALVO", "unknown", "CONFIABILIDADE NÃO VERIFICADA", "copy", "COPIAR", "code", "CÓDIGO / INTEGRAÇÃO", "sources", "FONTES", "timing", "TEMPO DE ANÁLISE"));
        all.put("ru", map("general", "ОБЩИЙ РЕЗУЛЬТАТ", "why", "ПОЧЕМУ?", "action", "ЧТО ДЕЛАТЬ?", "details", "ТЕХНИЧЕСКИЕ ДЕТАЛИ", "settings", "НАСТРОЙКИ", "mode", "РЕЖИМ", "developer", "РЕЖИМ РАЗРАБОТЧИКА", "beginner", "НАЧАЛЬНЫЙ РЕЖИМ", "standard", "СТАНДАРТНЫЙ РЕЖИМ", "analyze", "АНАЛИЗ", "target", "ЦЕЛЬ", "unknown", "НАДЁЖНОСТЬ НЕ ПОДТВЕРЖДЕНА", "copy", "КОПИРОВАТЬ", "code", "КОД / ИНТЕГРАЦИЯ", "sources", "ИСТОЧНИКИ", "timing", "ВРЕМЯ СКАНИРОВАНИЯ"));
        all.put("ar", map("general", "النتيجة العامة", "why", "لماذا؟", "action", "ماذا أفعل؟", "details", "عرض التفاصيل التقنية", "settings", "الإعدادات", "mode", "الوضع", "developer", "وضع المطور", "beginner", "وضع المبتدئ", "standard", "الوضع القياسي", "analyze", "تحليل", "target", "الهدف", "unknown", "تعذر التحقق من الموثوقية", "copy", "نسخ", "code", "الكود / التكامل", "sources", "حالة المصادر", "timing", "وقت الفحص"));
        all.put("zh", map("general", "总体结果", "why", "为什么？", "action", "我该怎么办？", "details", "查看技术详情", "settings", "设置", "mode", "模式", "developer", "开发者模式", "beginner", "入门模式", "standard", "标准模式", "analyze", "分析", "target", "目标", "unknown", "无法验证可靠性", "copy", "复制", "code", "代码 / 集成", "sources", "来源诊断", "timing", "扫描时间"));
        return Collections.unmodifiableMap(all);
    }
    private static Map<String,String> map(String... values) { Map<String,String> m=new LinkedHashMap<>(); for(int i=0;i+1<values.length;i+=2)m.put(values[i],values[i+1]); return m; }
}
