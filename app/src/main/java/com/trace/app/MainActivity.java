package com.trace.app;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import java.util.concurrent.TimeUnit;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@SuppressLint("SetTextI18n")
public final class MainActivity extends android.app.Activity {
    private static final int BG = Color.rgb(8, 12, 15);
    private static final int PANEL = Color.rgb(13, 20, 24);
    private static final int PANEL_2 = Color.rgb(16, 25, 29);
    private static final int BORDER = Color.rgb(39, 58, 64);
    private static final int TEXT = Color.rgb(215, 230, 221);
    private static final int MUTED = Color.rgb(145, 168, 155);
    private static final int GREEN = Color.rgb(102, 227, 166);
    private static final int AMBER = Color.rgb(239, 190, 95);
    private static final int RED = Color.rgb(246, 119, 119);

    private LinearLayout root;
    private FrameLayout content;
    private TextView terminalOutput;
    private EditText terminalInput;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private CaseStore store;
    private TraceScanner scanner;
    private WatchlistStore watchlist;
    private ThreatFeedCache feedCache;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        store = new CaseStore(this);
        scanner = new TraceScanner(this);
        watchlist = new WatchlistStore(this);
        feedCache = new ThreatFeedCache(this);
        PeriodicWorkRequest watchWork = new PeriodicWorkRequest.Builder(WatchWorker.class, 24, TimeUnit.HOURS).build();
        WorkManager.getInstance(this).enqueueUniquePeriodicWork("trace-watchlist", ExistingPeriodicWorkPolicy.KEEP, watchWork);
        buildShell();
        showTerminal();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void buildShell() {
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setPadding(dp(16), dp(12), dp(16), dp(10));

        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView brand = label("TRACE", 24, GREEN);
        brand.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        header.addView(brand, new LinearLayout.LayoutParams(0, dp(40), 1));
        TextView status = label("●  ONLINE", 11, GREEN);
        status.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        header.addView(status, new LinearLayout.LayoutParams(-2, dp(40)));
        root.addView(header);

        TextView subtitle = label("LOCAL-FIRST  /  SECURITY INTELLIGENCE  /  v3.0.0", 10, MUTED);
        subtitle.setPadding(0, 0, 0, dp(10));
        root.addView(subtitle);

        HorizontalScrollView navScroll = new HorizontalScrollView(this);
        navScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout nav = new LinearLayout(this);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        String[] sections = {"DASHBOARD", "TERMINAL", "SCAN", "HISTORY", "CASES", "REPORTS", "SETTINGS"};
        for (String section : sections) {
            Button button = button(section, 10, section.equals("TERMINAL") ? GREEN : MUTED);
            button.setOnClickListener(v -> {
                switch (section) {
                    case "DASHBOARD": showDashboard(); break;
                    case "TERMINAL": showTerminal(); break;
                    case "SCAN": showScan(); break;
                    case "HISTORY": showHistory(); break;
                    case "CASES": showCases(); break;
                    case "REPORTS": showReports(); break;
                    case "SETTINGS": showSettings(); break;
                }
            });
            nav.addView(button, new LinearLayout.LayoutParams(-2, dp(38)));
        }
        navScroll.addView(nav);
        root.addView(navScroll);

        View rule = new View(this);
        rule.setBackgroundColor(BORDER);
        root.addView(rule, new LinearLayout.LayoutParams(-1, 1));

        content = new FrameLayout(this);
        content.setPadding(0, dp(12), 0, 0);
        root.addView(content, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);
    }

    private void showTerminal() {
        content.removeAllViews();
        LinearLayout page = page();
        LinearLayout heading = sectionHeading("TERMINAL", "Read-only collection commands; results stay on this device.");
        page.addView(heading);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        terminalOutput = label(welcomeText(), 13, TEXT);
        terminalOutput.setTypeface(Typeface.MONOSPACE);
        terminalOutput.setTextIsSelectable(true);
        terminalOutput.setGravity(Gravity.TOP | Gravity.START);
        terminalOutput.setPadding(dp(14), dp(14), dp(14), dp(14));
        terminalOutput.setBackground(panelBackground(PANEL, BORDER));
        scroll.addView(terminalOutput);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        LinearLayout promptRow = new LinearLayout(this);
        promptRow.setGravity(Gravity.CENTER_VERTICAL);
        promptRow.setPadding(0, dp(10), 0, 0);
        terminalInput = edit("trace scan example.com", false);
        terminalInput.setSingleLine(true);
        terminalInput.setImeOptions(EditorInfo.IME_ACTION_GO);
        terminalInput.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_GO) { runTerminalCommand(); return true; }
            return false;
        });
        promptRow.addView(terminalInput, new LinearLayout.LayoutParams(0, dp(48), 1));
        Button run = button("RUN", 11, BG);
        run.setTextColor(BG);
        run.setBackground(panelBackground(GREEN, GREEN));
        run.setOnClickListener(v -> runTerminalCommand());
        LinearLayout.LayoutParams runParams = new LinearLayout.LayoutParams(dp(72), dp(48));
        runParams.setMargins(dp(8), 0, 0, 0);
        promptRow.addView(run, runParams);
        page.addView(promptRow);
        content.addView(page);
    }

    private void runTerminalCommand() {
        if (terminalInput == null) return;
        String command = terminalInput.getText().toString().trim();
        if (command.isEmpty()) return;
        terminalInput.setText("");
        if (command.equalsIgnoreCase("trace clear") || command.equalsIgnoreCase("clear")) {
            terminalOutput.setText(welcomeText());
            return;
        }
        appendTerminal("\n$ " + command + "\n[·] running...\n");
        executor.submit(() -> {
            String response = executeCommand(command);
            runOnUiThread(() -> appendTerminal(response + "\n"));
        });
    }

    private String executeCommand(String command) {
        try {
            String normalized = command.trim();
            if (normalized.startsWith("$")) normalized = normalized.substring(1).trim();
            String[] parts = normalized.split("\\s+");
            int offset = parts.length > 0 && parts[0].equalsIgnoreCase("trace") ? 1 : 0;
            if (parts.length <= offset) return helpText();
            String action = parts[offset].toLowerCase(Locale.US);
            String argument = join(parts, offset + 1);
            switch (action) {
                case "help": return helpText();
                case "scan": return scanCommand(argument);
                case "quick": return profileCommand(argument, false);
                case "deep": return profileCommand(argument, true);
                case "dns": return compactJson(scanner.dns(argument));
                case "tls": return compactJson(scanner.tls(argument));
                case "headers": return compactJson(scanner.headers(argument));
                case "redirects": return compactJson(scanner.redirects(argument));
                case "tech": return compactJson(scanner.tech(argument));
                case "domain": return compactJson(scanner.domain(argument));
                case "ip": return compactJson(scanner.ip(argument));
                case "reputation": return compactJson(scanner.reputation(argument));
                case "risk": return compactJson(scanner.scan(argument).optJSONObject("risk"));
                case "file": return compactJson(MalwareGuard.analyze(this, argument));
                case "hash": return hashCommand(argument);
                case "compare": return compareCommand(argument);
                case "history": return historyText();
                case "case": return caseText(argument);
                case "watch": watchlist.add(argument); return "[+] WATCHLIST  " + argument;
                case "unwatch": watchlist.remove(argument); return "[+] UNWATCHED  " + argument;
                case "watches": return watchText();
                case "export": return exportText(argument);
                case "report": return exportText(argument);
                case "clear": return "";
                default: return "[-] Unknown command. Type `trace help`.";
            }
        } catch (Exception e) {
            return "[-] ERROR  " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    private String scanCommand(String target) throws Exception {
        if (target.isEmpty()) throw new IllegalArgumentException("Usage: trace scan <target>");
        JSONObject result = scanner.scan(target);
        feedCache.mark("AVAILABLE");
        TraceCase traceCase = store.save(target, result);
        return formatScan(result, traceCase.id);
    }

    private String profileCommand(String target, boolean deep) throws Exception {
        if (target.isEmpty()) throw new IllegalArgumentException("Usage: trace " + (deep ? "deep" : "quick") + " <target>");
        JSONObject result = deep ? scanner.deep(target) : scanner.quick(target);
        TraceCase traceCase = store.save(target, result);
        return "[+] PROFILE       " + (deep ? "DEEP" : "QUICK") + "\n" + formatScan(result, traceCase.id);
    }

    private String hashCommand(String value) {
        if (value.isEmpty()) return "Usage: trace hash <file-path>";
        java.io.File file = new java.io.File(value);
        if (file.exists()) return compactJson(MalwareGuard.analyze(this, value));
        for (TraceCase c : store.all()) if (c.resultsJson.toLowerCase(Locale.US).contains(value.toLowerCase(Locale.US))) return "[+] HASH MATCH  " + c.id;
        return "[i] HASH UNKNOWN  No local evidence matched this value; no keyless public source available.";
    }

    private String compareCommand(String args) {
        String[] ids = args.trim().split("\\s+");
        if (ids.length < 2) return "Usage: trace compare <caseA> <caseB>";
        TraceCase a = store.find(ids[0]), b = store.find(ids[1]);
        if (a == null || b == null) return "[-] Both case IDs must exist locally.";
        return compactJson(IntelligenceUtils.compare(parse(a.resultsJson), parse(b.resultsJson)));
    }

    private String watchText() { StringBuilder out=new StringBuilder("[+] WATCHLIST\n"); for(String target:watchlist.all()) out.append("• ").append(target).append('\n'); return out.toString(); }

    private void showDashboard() {
        content.removeAllViews(); LinearLayout page=page();
        page.addView(sectionHeading("DASHBOARD", "Local posture overview; no provider account or API key required."));
        List<TraceCase> cases=store.all();
        StringBuilder text=new StringBuilder(); text.append("TOTAL SCANS   ").append(cases.size()).append("\n\nRECENT CASES\n");
        for(int i=0;i<Math.min(5,cases.size());i++) text.append(cases.get(i).id).append("  ").append(cases.get(i).target).append('\n');
        text.append("\nWATCHLIST\n").append(watchText()).append("\nFEED CACHE\n").append(compactJson(feedCache.status()));
        TextView output=label(text.toString(),13,TEXT); output.setTypeface(Typeface.MONOSPACE); output.setPadding(dp(14),dp(14),dp(14),dp(14)); output.setBackground(panelBackground(PANEL,BORDER));
        page.addView(output,new LinearLayout.LayoutParams(-1,0,1)); content.addView(page);
    }

    private void showScan() {
        content.removeAllViews();
        LinearLayout page = page();
        page.addView(sectionHeading("SCAN", "One target, one evidence bundle, no server required."));
        EditText target = edit("example.com or https://example.com", false);
        page.addView(target, new LinearLayout.LayoutParams(-1, dp(50)));
        Button run = button("RUN SCAN", 11, BG);
        run.setTextColor(BG);
        run.setBackground(panelBackground(GREEN, GREEN));
        LinearLayout.LayoutParams runParams = new LinearLayout.LayoutParams(-1, dp(46));
        runParams.setMargins(0, dp(10), 0, dp(10));
        page.addView(run, runParams);
        TextView output = label("Awaiting target...", 12, TEXT);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextIsSelectable(true);
        output.setPadding(dp(14), dp(14), dp(14), dp(14));
        output.setBackground(panelBackground(PANEL, BORDER));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        run.setOnClickListener(v -> {
            String value = target.getText().toString().trim();
            if (value.isEmpty()) { output.setText("[-] Enter a target."); return; }
            run.setEnabled(false);
            output.setText("[·] Resolving, validating, and collecting evidence...\n");
            executor.submit(() -> {
                try {
                    JSONObject result = scanner.scan(value);
                    TraceCase traceCase = store.save(value, result);
                    String text = formatScan(result, traceCase.id) + "\n\n" + compactJson(result);
                    runOnUiThread(() -> { output.setText(text); run.setEnabled(true); });
                } catch (Exception e) {
                    runOnUiThread(() -> { output.setText("[-] ERROR  " + errorText(e)); run.setEnabled(true); });
                }
            });
        });
        content.addView(page);
    }

    private void showHistory() {
        content.removeAllViews();
        LinearLayout page = page();
        page.addView(sectionHeading("HISTORY", "Offline case history from local app-private storage."));
        List<TraceCase> cases = store.all();
        if (cases.isEmpty()) {
            page.addView(label("No cases yet. Run `trace scan example.com` to create one.", 13, MUTED));
        } else {
            ScrollView scroll = new ScrollView(this);
            LinearLayout list = new LinearLayout(this);
            list.setOrientation(LinearLayout.VERTICAL);
            for (TraceCase traceCase : cases) addCaseRow(list, traceCase);
            scroll.addView(list);
            page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        }
        content.addView(page);
    }

    private void showCases() {
        content.removeAllViews();
        LinearLayout page = page();
        List<TraceCase> cases = store.all();
        page.addView(sectionHeading("CASES", String.format(Locale.US, "%02d local evidence bundles", cases.size())));
        page.addView(label("Cases contain DNS, TLS, HTTP, redirect, technology, security-header, and reputation evidence.\n", 12, MUTED));
        ScrollView scroll = new ScrollView(this);
        LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        if (cases.isEmpty()) list.addView(label("No stored cases.", 13, MUTED));
        for (TraceCase traceCase : cases) addCaseRow(list, traceCase);
        scroll.addView(list);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        content.addView(page);
    }

    private void addCaseRow(LinearLayout list, TraceCase traceCase) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(12), dp(10), dp(12), dp(10));
        card.setBackground(panelBackground(PANEL, BORDER));
        TextView title = label(traceCase.id + "   " + traceCase.target, 13, GREEN);
        title.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        card.addView(title);
        card.addView(label(traceCase.timestamp, 11, MUTED));
        Button open = button("OPEN CASE", 10, MUTED);
        open.setOnClickListener(v -> showCaseDetail(traceCase));
        card.addView(open, new LinearLayout.LayoutParams(-1, dp(36)));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, dp(112));
        params.setMargins(0, 0, 0, dp(10));
        list.addView(card, params);
    }

    private void showCaseDetail(TraceCase traceCase) {
        content.removeAllViews();
        LinearLayout page = page();
        page.addView(sectionHeading(traceCase.id, traceCase.target + "  /  " + traceCase.timestamp));
        TextView output = label(compactJson(parse(traceCase.resultsJson)), 12, TEXT);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextIsSelectable(true);
        output.setPadding(dp(14), dp(14), dp(14), dp(14));
        output.setBackground(panelBackground(PANEL, BORDER));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        Button export = button("EXPORT JSON + HTML", 11, BG);
        export.setTextColor(BG);
        export.setBackground(panelBackground(GREEN, GREEN));
        export.setOnClickListener(v -> {
            try { output.setText(output.getText() + "\n\n[+] Exported to " + store.export(this, traceCase).getAbsolutePath()); }
            catch (Exception e) { output.setText(output.getText() + "\n\n[-] Export failed: " + errorText(e)); }
        });
        page.addView(export, new LinearLayout.LayoutParams(-1, dp(46)));
        content.addView(page);
    }

    private void showReports() {
        content.removeAllViews();
        LinearLayout page = page();
        page.addView(sectionHeading("REPORTS", "Export any local case as case.json, evidence.json, and report.html."));
        List<TraceCase> cases = store.all();
        ScrollView scroll = new ScrollView(this);
        LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        if (cases.isEmpty()) list.addView(label("No reports available until a scan is saved.", 13, MUTED));
        for (TraceCase traceCase : cases) {
            LinearLayout row = new LinearLayout(this);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.addView(label(traceCase.id + "  " + traceCase.target, 12, TEXT), new LinearLayout.LayoutParams(0, dp(48), 1));
            Button export = button("EXPORT", 10, GREEN);
            export.setOnClickListener(v -> {
                try { export.setText("EXPORTED"); export.setTextColor(GREEN); store.export(this, traceCase); }
                catch (Exception e) { export.setText("FAILED"); export.setTextColor(RED); }
            });
            row.addView(export, new LinearLayout.LayoutParams(dp(100), dp(42)));
            list.addView(row);
        }
        scroll.addView(list);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        content.addView(page);
    }

    private void showSettings() {
        content.removeAllViews();
        LinearLayout page = page();
        page.addView(sectionHeading("SETTINGS", "No provider account or API key is required."));
        SharedPreferences prefs = getSharedPreferences("trace_settings", MODE_PRIVATE);
        EditText timeout = edit("Scan timeout (seconds)", false); timeout.setText(prefs.getString("timeout", "9"));
        EditText bodyLimit = edit("Body size limit (KiB)", false); bodyLimit.setText(prefs.getString("bodyLimit", "256"));
        EditText watchInterval = edit("Background watch interval (hours)", false); watchInterval.setText(prefs.getString("watchInterval", "24"));
        page.addView(timeout, new LinearLayout.LayoutParams(-1, dp(50)));
        page.addView(bodyLimit, new LinearLayout.LayoutParams(-1, dp(50)));
        page.addView(watchInterval, new LinearLayout.LayoutParams(-1, dp(50)));
        Button save = button("SAVE LOCAL SETTINGS", 11, BG);
        save.setTextColor(BG);
        save.setBackground(panelBackground(GREEN, GREEN));
        LinearLayout.LayoutParams saveParams = new LinearLayout.LayoutParams(-1, dp(46));
        saveParams.setMargins(0, dp(10), 0, dp(18));
        page.addView(save, saveParams);
        TextView note = label("Privacy\n• Cases and file analysis stay in Android app-private storage.\n• Files are hashed and inspected locally; they are never uploaded.\n• Public sources are optional and keyless; unavailable sources remain UNKNOWN.\n\nSafety policy\n• HTTP/HTTPS only\n• Loopback, private, link-local, internal and special-use targets blocked\n• Redirect targets revalidated\n• No exploit, brute force, credential, DDoS, stealth or evasion features", 12, MUTED);
        note.setTypeface(Typeface.MONOSPACE);
        page.addView(note);
        save.setOnClickListener(v -> {
            prefs.edit().putString("timeout", timeout.getText().toString().trim()).putString("bodyLimit", bodyLimit.getText().toString().trim()).putString("watchInterval", watchInterval.getText().toString().trim()).apply();
            save.setText("SAVED LOCALLY");
        });
        content.addView(page);
    }

    private String historyText() {
        List<TraceCase> cases = store.all();
        if (cases.isEmpty()) return "[i] No local cases.";
        StringBuilder out = new StringBuilder("[+] LOCAL HISTORY\n");
        for (TraceCase traceCase : cases) out.append(traceCase.id).append("  ").append(traceCase.target).append("  ").append(traceCase.timestamp).append('\n');
        return out.toString();
    }

    private String caseText(String id) throws Exception {
        if (id.isEmpty()) throw new IllegalArgumentException("Usage: trace case <id>");
        TraceCase traceCase = store.find(id);
        if (traceCase == null) return "[-] Case not found: " + id;
        return "[+] " + traceCase.id + "  " + traceCase.target + "\n" + compactJson(parse(traceCase.resultsJson));
    }

    private String exportText(String id) throws Exception {
        if (id.isEmpty()) throw new IllegalArgumentException("Usage: trace export <id>");
        TraceCase traceCase = store.find(id);
        if (traceCase == null) return "[-] Case not found: " + id;
        return "[+] EXPORTED  " + store.export(this, traceCase).getAbsolutePath();
    }

    private String formatScan(JSONObject result, String caseId) {
        JSONObject http = result.optJSONObject("http");
        JSONObject dns = result.optJSONObject("dns");
        JSONObject tech = result.optJSONObject("technology");
        JSONObject tls = result.optJSONObject("tls");
        JSONObject reputation = result.optJSONObject("reputation");
        String status = http == null ? "?" : String.valueOf(http.optInt("statusCode", 0));
        String redirectCount = String.valueOf(result.optJSONArray("redirects") == null ? 0 : result.optJSONArray("redirects").length());
        String tlsStatus = tls == null ? "?" : tls.optString("status", "?").toUpperCase(Locale.US);
        JSONArray technologies = tech == null ? null : tech.optJSONArray("technologies");
        String technology = technologies == null || technologies.length() == 0 ? "unknown" : technologies.optString(0, "unknown");
        int providerCount = reputation == null || reputation.optJSONArray("providers") == null ? 0 : reputation.optJSONArray("providers").length();
        JSONObject risk = result.optJSONObject("risk");
        return "[+] TARGET        " + result.optString("target") + "\n"
                + "[+] DNS           " + (dns == null ? "ERROR" : "OK") + "\n"
                + "[+] TLS           " + tlsStatus + "\n"
                + "[+] HTTP          " + status + "\n"
                + "[+] REDIRECTS     " + redirectCount + "\n"
                + "[+] TECHNOLOGY    " + technology + "\n"
                + "[+] REPUTATION    " + providerCount + " provider modules\n"
                + "[+] RISK          " + (risk == null ? "UNKNOWN" : risk.optString("severity", "UNKNOWN")) + "\n"
                + "[+] CONFIDENCE    " + (risk == null ? "UNKNOWN" : risk.optString("confidence", "UNKNOWN")) + "\n"
                + "[+] CASE          " + caseId;
    }

    private String compactJson(JSONObject object) {
        try { return object.toString(2); } catch (Exception e) { return object.toString(); }
    }

    private JSONObject parse(String json) {
        try { return new JSONObject(json); } catch (Exception e) { return new JSONObject(); }
    }

    private void appendTerminal(String text) {
        if (terminalOutput == null) return;
        terminalOutput.append(text);
        terminalOutput.post(() -> {
            View parent = (View) terminalOutput.getParent();
            if (parent instanceof ScrollView) ((ScrollView) parent).fullScroll(View.FOCUS_DOWN);
        });
    }

    private LinearLayout page() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        return page;
    }

    private LinearLayout sectionHeading(String title, String subtitle) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        TextView heading = label(title, 18, GREEN);
        heading.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        box.addView(heading);
        TextView sub = label(subtitle, 11, MUTED);
        sub.setPadding(0, dp(2), 0, dp(12));
        box.addView(sub);
        return box;
    }

    private TextView label(String text, int size, int color) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setFontFeatureSettings("tnum");
        return view;
    }

    private EditText edit(String hint, boolean password) {
        EditText field = new EditText(this);
        field.setHint(hint);
        field.setHintTextColor(MUTED);
        field.setTextColor(TEXT);
        field.setTextSize(13);
        field.setSingleLine(true);
        field.setPadding(dp(12), 0, dp(12), 0);
        field.setTypeface(Typeface.MONOSPACE);
        field.setBackground(panelBackground(PANEL_2, BORDER));
        if (password) field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        return field;
    }

    private Button button(String text, int size, int color) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(size);
        button.setTextColor(color);
        button.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        button.setGravity(Gravity.CENTER);
        button.setAllCaps(false);
        button.setPadding(dp(8), 0, dp(8), 0);
        button.setBackground(panelBackground(Color.TRANSPARENT, BORDER));
        return button;
    }

    private GradientDrawable panelBackground(int fill, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(3));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private String welcomeText() {
        return "TRACE / LOCAL-FIRST WEB INTELLIGENCE\n"
                + "────────────────────────────────────\n"
                + "Read-only collection. Targets are validated before every request.\n\n"
                + "Type `trace help` for commands.\n\n$ ";
    }

    private String helpText() {
        return "TRACE COMMANDS\n"
                + "────────────────────────────────────\n"
                + "trace scan <target>        full evidence bundle + save case\n"
                + "trace quick <target>       fast safe analysis\n"
                + "trace deep <target>        full intelligence pipeline\n"
                + "trace dns <domain>          A / AAAA / MX / NS / TXT / CNAME\n"
                + "trace tls <domain>          certificate and cipher details\n"
                + "trace headers <url>         response and security headers\n"
                + "trace redirects <url>       safe redirect chain\n"
                + "trace tech <url>            server and framework hints\n"
                + "trace domain <domain>       public RDAP data\n"
                + "trace ip <host>             IP and reverse DNS\n"
                + "trace file <path>           local static file/APK analysis\n"
                + "trace hash <path-or-hash>   local hash history\n"
                + "trace reputation <domain>  provider modules\n"
                + "trace risk <target>         explainable risk assessment\n"
                + "trace compare <a> <b>       compare local cases\n"
                + "trace history               local case list\n"
                + "trace case <id>             reopen a case\n"
                + "trace watch <target>        add to local watchlist\n"
                + "trace unwatch <target>      remove from watchlist\n"
                + "trace watches               list watchlist\n"
                + "trace export <id>           JSON + HTML report\n"
                + "trace clear                 clear terminal output\n"
                + "trace help                  show this help\n\n"
                + "Safety: no exploit, brute force, credential attack, DDoS, or evasion features.";
    }

    private static String join(String[] parts, int start) {
        if (start >= parts.length) return "";
        StringBuilder value = new StringBuilder();
        for (int i = start; i < parts.length; i++) { if (value.length() > 0) value.append(' '); value.append(parts[i]); }
        return value.toString();
    }

    private static String errorText(Exception e) { return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(); }
    private int dp(int value) { return (int) (value * getResources().getDisplayMetrics().density + 0.5f); }
}
