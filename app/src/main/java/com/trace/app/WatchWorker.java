package com.trace.app;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import org.json.JSONObject;

/** Periodic, local watchlist refresh. Network failure is reported as retry, never as a fake alert. */
public final class WatchWorker extends Worker {
    public WatchWorker(@NonNull Context context, @NonNull WorkerParameters params) { super(context, params); }
    @NonNull @Override public Result doWork() {
        WatchlistStore watches = new WatchlistStore(getApplicationContext());
        CaseStore cases = new CaseStore(getApplicationContext());
        TraceScanner scanner = new TraceScanner(getApplicationContext());
        boolean retry = false;
        for (String target : watches.all()) {
            try {
                JSONObject previous = watches.snapshot(target);
                JSONObject current = scanner.scan(target);
                JSONObject changes = IntelligenceUtils.compare(previous, current);
                if (changes.optJSONArray("changed") != null && changes.optJSONArray("changed").length() > 0) {
                    cases.save(target, current);
                }
                watches.saveSnapshot(target, current);
            } catch (Exception e) { retry = true; }
        }
        return retry ? Result.retry() : Result.success();
    }
}
