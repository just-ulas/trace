package com.trace.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Environment;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** Local-only persistence. No server or account is needed for case history. */
public final class CaseStore {
    private static final String PREFS = "trace_cases";
    private static final String CASES = "cases";
    private static final String NEXT_ID = "next_id";
    private final SharedPreferences preferences;

    public CaseStore(Context context) {
        preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public synchronized TraceCase save(String target, JSONObject results) {
        int next = preferences.getInt(NEXT_ID, 1);
        String id = String.format(Locale.US, "CASE-%05d", next);
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(new Date());
        TraceCase traceCase = new TraceCase(id, target, timestamp, results.toString());
        JSONArray existing = readArray();
        JSONArray updated = new JSONArray();
        try {
            updated.put(traceCase.toJson());
            for (int i = 0; i < Math.min(existing.length(), 49); i++) {
                updated.put(existing.getJSONObject(i));
            }
        } catch (JSONException ignored) {
            // A malformed old entry is skipped; the new case remains usable.
        }
        preferences.edit().putString(CASES, updated.toString()).putInt(NEXT_ID, next + 1).apply();
        return traceCase;
    }

    public synchronized List<TraceCase> all() {
        JSONArray array = readArray();
        List<TraceCase> cases = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            try {
                cases.add(TraceCase.fromJson(array.getJSONObject(i)));
            } catch (JSONException ignored) {
                // Keep history resilient if a single entry is corrupt.
            }
        }
        return cases;
    }

    public synchronized TraceCase find(String id) {
        for (TraceCase traceCase : all()) {
            if (traceCase.id.equalsIgnoreCase(id)) {
                return traceCase;
            }
        }
        return null;
    }

    public synchronized File export(Context context, TraceCase traceCase) throws Exception {
        File root = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS);
        if (root == null) root = new File(context.getFilesDir(), "documents");
        File dir = new File(root, traceCase.id);
        if (!dir.exists() && !dir.mkdirs()) throw new IllegalStateException("Cannot create report directory");

        JSONObject caseJson = traceCase.toJson();
        write(new File(dir, "case.json"), caseJson.toString(2));
        write(new File(dir, "evidence.json"), new JSONObject(traceCase.resultsJson).toString(2));
        write(new File(dir, "report.html"), htmlReport(traceCase, caseJson));
        return dir;
    }

    private JSONArray readArray() {
        try {
            return new JSONArray(preferences.getString(CASES, "[]"));
        } catch (JSONException e) {
            return new JSONArray();
        }
    }

    private static void write(File file, String content) throws Exception {
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(content.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String htmlReport(TraceCase traceCase, JSONObject object) {
        String json;
        try {
            json = escape(object.toString(2));
        } catch (JSONException e) {
            json = escape(object.toString());
        }
        JSONObject risk = object.optJSONObject("risk");
        String severity = risk == null ? "UNKNOWN" : risk.optString("severity", "UNKNOWN");
        String confidence = risk == null ? "UNKNOWN" : risk.optString("confidence", "UNKNOWN");
        String findings = risk == null ? "[]" : risk.optJSONArray("findings") == null ? "[]" : risk.optJSONArray("findings").toString();
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>TRACE "
                + escape(traceCase.id) + "</title><style>body{background:#080c0f;color:#d7e6dd;font:14px monospace;padding:32px}h1{color:#66e3a6}pre{background:#10191d;padding:20px;border:1px solid #273a40;overflow:auto;white-space:pre-wrap}.meta{color:#91a89b}</style></head><body>"
                + "<h1>TRACE SECURITY REPORT / " + escape(traceCase.id) + "</h1><p class=\"meta\">Target: "
                + escape(traceCase.target) + "<br>Captured: " + escape(traceCase.timestamp)
                + "</p><h2>RISK OVERVIEW</h2><p>Severity: <b>" + escape(severity) + "</b><br>Confidence: " + escape(confidence) + "</p>"
                + "<h2>KEY FINDINGS</h2><pre>" + escape(findings) + "</pre><h2>EVIDENCE / DNS / IP / TLS / HTTP / CONTENT / TECHNOLOGY / SOURCES</h2><pre>"
                + json + "</pre><h2>REALITY RULE</h2><p class=\"meta\">UNKNOWN is not SAFE. SUSPICIOUS is not MALWARE. Evidence is collected at the timestamp above.</p></body></html>";
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
